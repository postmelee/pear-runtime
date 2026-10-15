# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Observable admission, bounded process and receipt behavior for build drivers."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from pear_runtime.build import Context, fact, load, parse_depfile
from pear_runtime.errors import Error


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='pear-build-test-')
        self.addCleanup(self.scratch.cleanup)
        self.base = Path(self.scratch.name).resolve()
        self.input = self.base / 'immutable'
        self.input.mkdir()
        self.file = self.input / 'header with spaces.h'
        self.file.write_text('original\n')
        self.python = Path(sys.executable).resolve()
        self.recipe = {
            'schema_version': 1, 'name': 'synthetic',
            'roots': {'inputs': {'kind': 'input'}, 'python': {'kind': 'toolchain'}},
            'inputs': [self.row('inputs', self.file, self.input),
                       self.row('python', self.python, self.python.parent)],
            'budget': {'additional_bytes': 4096, 'floor_bytes': 0},
        }
        self.bindings = {'inputs': str(self.input), 'python': str(self.python.parent)}
        self.output = self.base / 'output'
        self.lock = self.base / 'operation.lock'

    @staticmethod
    def row(root, path, base):
        ref = fact(path)
        return dict(root=root, path=str(path.relative_to(base)),
                    sha256=ref['sha256'], size_bytes=ref['size_bytes'])

    def context(self, **kwargs):
        return Context(kwargs.get('recipe', self.recipe), kwargs.get('bindings', self.bindings),
                       kwargs.get('output', self.output), lock_path=self.lock)

    def command(self, ctx, code, **kwargs):
        return ctx.run('python', [str(self.python), '-c', code], **kwargs)

    def test_exact_input_and_success_receipt(self):
        with self.context() as ctx:
            ctx.copy_input('inputs', self.file.name, 'copied.h')
            row = self.command(ctx, "print('bounded result')")
            self.assertEqual(row['exit_code'], 0)
            self.assertGreaterEqual(row['ended']['monotonic_seconds'], row['started']['monotonic_seconds'])
            self.assertIn('wall_utc', row['started'])
            self.assertEqual(Path(row['logs']['stdout']['path']).read_text(), 'bounded result\n')
            receipt = ctx.finish('passed', extra={'artifacts': {'header': ctx.outputs['copied.h']}})
            self.assertFalse(receipt['runtime_eligible'])
            self.assertFalse(receipt['game_qualified'])
        self.assertTrue(load(self.output / 'operation.json')['released'])
        self.assertEqual(load(self.output / 'build.json')['status'], 'passed')

    def test_relative_executable_cannot_substitute_via_path_or_cwd(self):
        # The caller cwd contains admitted bytes, while the command cwd/PATH
        # contains a different executable with the same lexical name.
        accepted = self.input / 'tool'
        accepted.write_text('#!/bin/sh\nexit 0\n')
        accepted.chmod(0o700)
        self.recipe['inputs'].append(self.row('inputs', accepted, self.input))
        previous = Path.cwd()
        with self.context() as ctx:
            substitute = ctx.output / 'tool'
            substitute.write_text('#!/bin/sh\nprintf substituted > marker\n')
            substitute.chmod(0o700)
            try:
                os.chdir(self.input)
                for index, executable in enumerate(('tool', './tool')):
                    with self.subTest(executable=executable):
                        with self.assertRaisesRegex(Error, 'build_executable_absolute'):
                            ctx.run('relative-' + str(index), [executable],
                                    env={'PATH': str(ctx.output)})
                        self.assertFalse((ctx.output / 'marker').exists())
                # An absolute admitted executable still uses its exact spelling.
                ctx.run('absolute', [str(accepted)])
            finally:
                os.chdir(previous)
            ctx.finish('passed')

    def test_tampered_input_refuses_before_output(self):
        self.file.write_text('changed')
        with self.assertRaisesRegex(Error, 'build_input_mismatch'):
            with self.context():
                self.fail('must not enter')
        self.assertFalse(self.output.exists())

    def test_missing_binding_refuses(self):
        with self.assertRaisesRegex(Error, 'build_root_bindings'):
            self.context(bindings={'inputs': str(self.input)})

    def test_reserved_root_metadata_refuses_before_execution(self):
        self.recipe['roots']['inputs']['path'] = 'ambiguous'
        with self.assertRaisesRegex(Error, 'build_root_reserved_field'):
            self.context()
        self.assertFalse(self.output.exists())

    def test_release_record_survives_receipt_serialization_failure(self):
        ctx = self.context()
        ctx.__enter__()
        with patch.object(ctx, 'finish', side_effect=RuntimeError('receipt unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'receipt unavailable'):
                ctx.__exit__(None, None, None)
        self.assertTrue(load(self.output / 'operation.json')['released'])
        self.assertIsNone(ctx._lock)

    def test_output_existing_or_overlapping_refuses(self):
        with self.assertRaisesRegex(Error, 'build_output_exists'):
            self.context(output=self.input)
        with self.assertRaisesRegex(Error, 'build_output_overlaps_input'):
            self.context(output=self.input / 'new')

    def test_symlink_root_refuses(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.input)
        with self.assertRaisesRegex(Error, 'build_root_alias'):
            self.context(bindings={**self.bindings, 'inputs': str(alias)})

    def test_declared_link_requires_exact_target_and_admitted_bytes(self):
        alias = self.input / 'alias.h'
        alias.symlink_to(self.file.name)
        self.recipe['inputs'].append(dict(root='inputs', path='alias.h', kind='symlink', target=self.file.name))
        with self.context() as ctx:
            self.assertEqual(ctx.input('inputs', 'alias.h'), alias)
            copied = ctx.copy_input('inputs', 'alias.h', 'materialized.h')
            self.assertFalse(copied.is_symlink())
            self.assertEqual(copied.read_bytes(), self.file.read_bytes())
            with self.assertRaisesRegex(Error, 'build_expected_input'):
                ctx.input('inputs', 'alias.h', '0' * 64)
            ctx.finish('passed')
        alias.unlink()
        alias.symlink_to('../outside')
        (self.base / 'outside').write_text('outside')
        with self.assertRaisesRegex(Error, 'build_input_escape'):
            self.context(output=self.base / 'second').validate_inputs()

    def test_live_lock_refuses_other_operation(self):
        with self.context() as first:
            with self.assertRaisesRegex(Error, 'build_operation_busy'):
                with self.context(output=self.base / 'second'):
                    self.fail('must not enter')
            first.finish('passed')
        with self.context(output=self.base / 'third') as third:
            third.finish('passed')

    def test_storage_refusal_creates_no_output(self):
        self.recipe['budget']['additional_bytes'] = 10**30
        with self.assertRaisesRegex(Error, 'build_storage_unavailable'):
            with self.context():
                self.fail('must not enter')
        self.assertFalse(self.output.exists())

    def test_nonzero_records_original_failure_and_releases_lock(self):
        with self.assertRaisesRegex(Error, 'build_command_failed'):
            with self.context() as ctx:
                self.command(ctx, "import sys; print('reason',file=sys.stderr); sys.exit(7)")
        receipt = load(self.output / 'build.json')
        self.assertEqual(receipt['status'], 'failed')
        row = receipt['commands'][0]
        self.assertEqual(row['exit_code'], 7)
        self.assertEqual(row['error'], 'build_command_failed')
        self.assertEqual(Path(row['logs']['stderr']['path']).read_text(), 'reason\n')
        self.assertTrue(load(self.output / 'operation.json')['released'])

    def test_output_limit_is_aggregate_and_retained(self):
        with self.assertRaisesRegex(Error, 'build_command_output_limit'):
            with self.context() as ctx:
                self.command(ctx, "import os; os.write(1,b'x'*5000); os.write(2,b'y'*5000)", max_output_bytes=1500)
        row = load(self.output / 'build.json')['commands'][0]
        self.assertLessEqual(sum(ref['size_bytes'] for ref in row['logs'].values()), 1500)
        self.assertEqual(row['error'], 'build_command_output_limit')

    def test_timeout_cleans_owned_group_even_when_leader_exited(self):
        real_killpg = os.killpg
        with patch('pear_runtime.build.os.killpg', wraps=real_killpg) as killpg:
            with self.assertRaisesRegex(Error, 'build_command_timeout'):
                with self.context() as ctx:
                    self.command(ctx, "import os,time; child=os.fork(); time.sleep(20) if child==0 else None", timeout=0.5)
            killpg.assert_called_once()
            self.assertEqual(killpg.call_args.args[1], signal.SIGKILL)
        row = load(self.output / 'build.json')['commands'][0]
        self.assertEqual(row['error'], 'build_command_timeout')
        self.assertLess(row['elapsed_seconds'], 5)

    def test_undeclared_command_path_never_starts(self):
        outsider = self.base / 'secret'
        outsider.write_text('private')
        with self.context() as ctx:
            with self.assertRaisesRegex(Error, 'build_undeclared_argument_path'):
                ctx.run('reject', [str(self.python), str(outsider)])
            self.assertEqual(ctx.commands, [])
            ctx.finish('passed')

    def test_unrecorded_generated_command_operand_refuses(self):
        with self.context() as ctx:
            generated = ctx.path('unrecorded.py')
            generated.write_text("raise AssertionError('must not run')")
            with self.assertRaisesRegex(Error, 'build_unrecorded_generated_input'):
                ctx.run('reject', [str(self.python), str(generated)])
            self.assertEqual(ctx.commands, [])
            ctx.finish('passed')

    def test_environment_does_not_inherit_cache_settings(self):
        with patch.dict(os.environ, {'CCACHE_PREFIX': 'unexpected', 'UNDECLARED_SECRET': 'hidden'}):
            with self.context() as ctx:
                row = self.command(ctx, "import os; assert 'CCACHE_PREFIX' not in os.environ; assert 'UNDECLARED_SECRET' not in os.environ")
                self.assertNotIn('CCACHE_PREFIX', row['env'])
                ctx.finish('passed')

    def test_changed_generated_input_and_finish_refuse(self):
        with self.assertRaisesRegex(Error, 'build_output_changed'):
            with self.context() as ctx:
                copied = ctx.copy_input('inputs', self.file.name, 'generated.h')
                copied.write_text('changed')
                with self.assertRaisesRegex(Error, 'build_generated_input_changed'):
                    ctx._admit_path(copied)
                ctx.finish('passed')
        self.assertEqual(load(self.output / 'build.json')['status'], 'failed')

    def test_changed_command_log_refuses_success(self):
        with self.assertRaisesRegex(Error, 'build_log_changed'):
            with self.context() as ctx:
                row = self.command(ctx, "print('original evidence')")
                Path(row['logs']['stdout']['path']).write_text('different evidence')
                ctx.finish('passed')
        self.assertEqual(load(self.output / 'build.json')['status'], 'failed')

    def test_input_changed_during_operation_refuses_pass(self):
        with self.assertRaisesRegex(Error, 'build_input_mismatch'):
            with self.context() as ctx:
                self.file.write_text('changed after admission')
                ctx.finish('passed')

    def test_depfile_escaped_paths_and_unknown_dependency(self):
        with self.context() as ctx:
            dep = ctx.path('object.d')
            escaped = str(self.file).replace(' ', '\\ ')
            dep.write_text('object.o: \\\n ' + escaped + '\n' + escaped + ':\n')
            self.assertEqual(parse_depfile(dep), [str(self.file)])
            self.assertEqual(ctx.audit_depfile(dep)[0]['sha256'], fact(self.file)['sha256'])
            unknown = self.input / 'undeclared.h'
            unknown.write_text('unknown')
            rejected_dep = ctx.path('rejected.d')
            rejected_dep.write_text('object.o: ' + str(unknown) + '\n')
            with self.assertRaisesRegex(Error, 'build_undeclared_input'):
                ctx.audit_depfile(rejected_dep)
            ctx.finish('passed')

    def test_changed_dependency_evidence_refuses_success(self):
        with self.assertRaisesRegex(Error, 'build_depfile_changed'):
            with self.context() as ctx:
                dep = ctx.path('object.d')
                dep.write_text('object.o: ' + str(self.file).replace(' ', '\\ ') + '\n')
                ctx.audit_depfile(dep)
                dep.write_text('object.o: omitted.h\n')
                ctx.finish('passed')

    def test_git_source_identity_and_dirty_source_refusal(self):
        source = self.base / 'source'
        source.mkdir()
        (source / 'input.c').write_text('int value;\n')
        for args in (['init', '-q'], ['add', 'input.c'], ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture']):
            subprocess.run(['git', '-C', str(source), *args], check=True, capture_output=True)
        commit = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
        self.recipe['roots']['source'] = {'kind': 'git', 'commit': commit}
        self.bindings['source'] = str(source)
        with self.context() as ctx:
            self.assertEqual(ctx.input('source', 'input.c'), source / 'input.c')
            (source / 'unknown.h').write_text('untracked')
            with self.assertRaisesRegex(Error, 'build_untracked_source_input'):
                ctx.input('source', 'unknown.h')
            ctx.finish('passed')
        (source / 'input.c').write_text('changed')
        with self.assertRaisesRegex(Error, 'build_source_dirty'):
            self.context(output=self.base / 'second').validate_inputs()

    def test_fifo_inputs_refuse_without_open_blocking(self):
        fifo = self.base / 'pipe'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(Error, 'build_input_not_regular'):
            fact(fifo)
        with self.assertRaisesRegex(Error, 'build_json_not_regular'):
            load(fifo)

    def test_oversize_json_refuses_before_reading(self):
        oversized = self.base / 'oversize.json'
        with oversized.open('wb') as stream:
            stream.truncate(64 * 1024**2 + 1)
        with self.assertRaisesRegex(Error, 'build_json_size'):
            load(oversized)

    def test_duplicate_json_key_refuses(self):
        path = self.base / 'duplicate.json'
        path.write_text('{"key":1,"key":2}')
        with self.assertRaisesRegex(Error, 'build_duplicate_json_key'):
            load(path)

    def test_finish_cannot_be_rewritten(self):
        with self.context() as ctx:
            ctx.finish('passed')
            with self.assertRaisesRegex(Error, 'build_finish_state'):
                ctx.finish('failed')


if __name__ == '__main__':
    unittest.main()
