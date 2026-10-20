# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic WGI recipe, dependency, binary and retained-budget controls."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from pear_runtime.build import Context, fact, write_json
from pear_runtime.errors import Error
from pear_runtime.recipes import wgi
from tests.build.test_wine_recipe import pe_fixture

SYNTHETIC_C_NOTICE = (b'/* SPDX-FileCopyrightText: 2026 Pear contributors\n'
                      b' * SPDX-License-Identifier: GPL-3.0-or-later */\n')


class WGIRecipeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recipe_path = Path(wgi.__file__).resolve().parents[2] / 'recipes/wine/wgi-v1.json'
        cls.raw = cls.recipe_path.read_bytes()
        cls.recipe = json.loads(cls.raw)

    def test_public_recipe_matches_independent_seal_and_exact_action_contract(self):
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(), wgi.RECIPE_SHA256)
        actions = wgi.validate_plan(self.recipe)
        self.assertEqual(len(actions), 65)
        self.assertEqual(self.recipe['private_plan']['sha256'], wgi.HISTORICAL_PLAN_SHA256)
        self.assertNotIn(b'/Users/', self.raw)
        self.assertNotIn(b'/private/', self.raw)

    def test_changed_flags_even_with_self_declared_digest_refuse_before_input(self):
        value = deepcopy(self.recipe)
        value['actions'][36]['argv'].append('-O2')
        value['expected_sha256'] = hashlib.sha256(json.dumps(value).encode()).hexdigest()
        context = SimpleNamespace(recipe=value, recipe_sha256=value['expected_sha256'], input=Mock())
        with self.assertRaisesRegex(Error, 'wgi_recipe_not_reviewed'):
            wgi.seal(context)
        context.input.assert_not_called()

    def test_changed_private_plan_digest_refuses_before_read(self):
        value = deepcopy(self.recipe)
        value['private_plan']['sha256'] = '0' * 64
        digest = hashlib.sha256((json.dumps(value, indent=2, sort_keys=True) + '\n').encode()).hexdigest()
        context = SimpleNamespace(recipe=value, recipe_sha256=digest, input=Mock())
        with patch.object(wgi, 'RECIPE_SHA256', digest):
            with self.assertRaisesRegex(Error, 'wgi_private_plan_identity'):
                wgi.seal(context)
        context.input.assert_not_called()

    def test_missing_action_is_refused(self):
        value = deepcopy(self.recipe)
        value['actions'].pop()
        with self.assertRaisesRegex(Error, 'wgi_action_count'):
            wgi.validate_plan(value)

    def test_shell_command_in_place_of_argv_is_refused(self):
        value = deepcopy(self.recipe)
        value['actions'][0]['historical_argv'] = 'widl && other'
        with self.assertRaisesRegex(Error, 'wgi_command_argv'):
            wgi.validate_plan(value)

    def test_unreviewed_optimization_and_source_spelling_are_refused(self):
        for change in ('optimization', 'source'):
            with self.subTest(change=change):
                value = deepcopy(self.recipe)
                row = next(r for r in value['actions'] if r['kind'] == 'compile')
                if change == 'optimization':
                    row['historical_argv'].append('-O2')
                else:
                    row['historical_argv'] = [x.replace('../source/', '/foreign/') for x in row['historical_argv']]
                with self.assertRaises(Error):
                    wgi.validate_plan(value)

    def test_missing_link_operand_and_diagnostic_flags_are_refused(self):
        for field in ('operands', 'argv'):
            value = deepcopy(self.recipe)
            value['actions'][-1][field].pop()
            with self.subTest(field=field), self.assertRaises(Error):
                wgi.validate_plan(value)

    def test_missing_input_mismatched_bytes_and_mode_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / 'inputs'
            source.mkdir()
            p = source / 'unit.c'
            p.write_bytes(SYNTHETIC_C_NOTICE + b'/* synthetic input */\n')
            p.chmod(0o644)
            row = dict(root='inputs', path=p.name, **{k: v for k, v in fact(p).items() if k != 'path'}, mode=0o644)
            recipe = dict(schema_version=1, name='synthetic', roots={'inputs': {'kind': 'input'}}, inputs=[row])
            context = Context(recipe, {'inputs': str(source)}, root / 'output')
            context.input('inputs', p.name)
            p.write_bytes(b'changed')
            with self.assertRaisesRegex(Error, 'build_input_mismatch'):
                context.input('inputs', p.name)
            p.write_bytes(SYNTHETIC_C_NOTICE + b'/* synthetic input */\n')
            p.chmod(0o755)
            with self.assertRaisesRegex(Error, 'build_input_mode'):
                context.input('inputs', p.name)
            p.unlink()
            with self.assertRaises(FileNotFoundError):
                context.input('inputs', p.name)

    def test_declared_reference_cannot_use_an_ancestor_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            real = root / 'real'
            real.mkdir()
            (real / 'file').write_bytes(b'input')
            (root / 'alias').symlink_to(real, target_is_directory=True)
            context = SimpleNamespace(input=Mock(return_value=root / 'alias/file'))
            with self.assertRaisesRegex(Error, 'wgi_reference_identity'):
                wgi.reference(context, dict(root='inputs', path='file', sha256='0' * 64, size_bytes=5))

    def dependency_context(self, root):
        inputs = root / 'inputs'
        inputs.mkdir()
        context = Context(dict(schema_version=1, name='synthetic', roots={'inputs': {'kind': 'input'}}, inputs=[]),
                          {'inputs': str(inputs)}, root / 'output')
        context.output.mkdir()
        (context.output / 'objects').mkdir()
        source = context.path('source/dlls/windows.gaming.input/provider.c')
        source.write_bytes(SYNTHETIC_C_NOTICE + b'/* synthetic source */\n')
        context.record_output('source/dlls/windows.gaming.input/provider.c')
        action = dict(target='provider.o', source='dlls/windows.gaming.input/provider.c', depfile='provider.d')
        return context, action

    def test_depfile_requires_canonical_expected_source_and_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, action = self.dependency_context(Path(tmp).resolve())
            path = context.output / 'provider.d'
            path.write_text('provider.o: ../source/dlls/windows.gaming.input/provider.c\n')
            rows = wgi.audit_compile(context, action)
            self.assertEqual(len(rows), 1)
            path.write_text('different.o: ../source/dlls/windows.gaming.input/provider.c\n')
            with self.assertRaisesRegex(Error, 'wgi_depfile_target'):
                wgi.audit_compile(context, action)

    def test_depfile_missing_or_admitted_same_name_shadow_source_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            context, action = self.dependency_context(Path(tmp).resolve())
            shadow = context.path('source/shadow/provider.c')
            shadow.write_bytes(SYNTHETIC_C_NOTICE + b'/* synthetic shadow */\n')
            context.record_output('source/shadow/provider.c')
            (context.output / 'provider.d').write_text('provider.o: ../source/shadow/provider.c\n')
            with self.assertRaisesRegex(Error, 'wgi_depfile_missing_source'):
                wgi.audit_compile(context, action)

    def test_depfile_unknown_input_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            context, action = self.dependency_context(root)
            (root / 'foreign.h').write_bytes(SYNTHETIC_C_NOTICE + b'/* foreign */\n')
            (context.output / 'provider.d').write_text('provider.o: ../source/dlls/windows.gaming.input/provider.c ../../foreign.h\n')
            with self.assertRaisesRegex(Error, 'build_undeclared_dependency'):
                wgi.audit_compile(context, action)

    def test_relative_link_operands_are_bound_to_command_cwd_not_process_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'objects').mkdir()
            operands = [f'lib{i}.a' for i in range(39)]
            for name in operands:
                (root / 'objects' / name).write_bytes(b'synthetic archive')
            context = SimpleNamespace(output=root, _admit_path=Mock(side_effect=fact))
            paths = wgi.explicit_link_operands(context, {'operands': operands})
            self.assertEqual(paths, [str(root / 'objects' / p) for p in operands])
            self.assertEqual(context._admit_path.call_count, 39)
            (root / 'objects' / operands[-1]).unlink()
            with self.assertRaisesRegex(Error, 'wgi_link_operand'):
                wgi.explicit_link_operands(context, {'operands': operands})

    def trace_fixture(self, root):
        class TraceContext:
            output = root
            def path(self, rel):
                path = self.output / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                return path
            def record_output(self, rel):
                return fact(self.output / rel)
            def _admit_path(self, path):
                return fact(path)
        context = TraceContext()
        for rel in ('objects/tools/winebuild/winebuild', 'tools/clang', 'tools/lld-link', 'objects/one.o'):
            context.path(rel).write_bytes(b'synthetic non-executable input')
        stdout = context.path('logs/stdout')
        stdout.write_text('./tools/winebuild/winebuild -v --dll\n'
                          + '"' + str(root / 'tools/clang') + '" -v\n')
        stderr = context.path('logs/stderr')
        stderr.write_text('"' + str(root / 'tools/lld-link') + '" -v\n'
                          + 'lld-link: Reading one.o\n')
        record = dict(id='synthetic-link', cwd=str(root / 'objects'),
                      logs={'stdout': fact(stdout), 'stderr': fact(stderr)})
        return context, record, [str(root / 'objects/one.o')]

    def test_exact_relative_winebuild_field_is_admitted_without_changing_original_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            context, record, operands = self.trace_fixture(root)
            before = {k: Path(v['path']).read_bytes() for k, v in record['logs'].items()}
            result = wgi.audit_link_trace(context, record, operands)
            self.assertEqual(result['required_operand_count'], 1)
            self.assertEqual(len(result['tools']), 3)
            self.assertEqual(len(result['executable_field_adaptations']), 1)
            self.assertEqual(result['original_logs'], record['logs'])
            self.assertEqual({k: Path(v['path']).read_bytes() for k, v in record['logs'].items()}, before)

    def test_unknown_relative_child_tool_and_changed_original_log_are_refused(self):
        for change in ('unknown', 'replaced'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                context, record, operands = self.trace_fixture(Path(tmp).resolve())
                log = Path(record['logs']['stdout']['path'])
                log.write_text(log.read_text().replace('./tools/winebuild/winebuild', './tools/other/winebuild'))
                if change == 'unknown':
                    record['logs']['stdout'] = fact(log)
                with self.assertRaisesRegex(Error, 'wgi_trace_relative_tool|wgi_trace_log_changed'):
                    wgi.audit_link_trace(context, record, operands)

    def test_relative_helper_alias_and_missing_required_child_are_refused(self):
        for change in ('alias', 'missing'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                context, record, operands = self.trace_fixture(root)
                if change == 'alias':
                    helper = root / 'objects/tools/winebuild/winebuild'
                    helper.unlink()
                    helper.symlink_to(root / 'tools/clang')
                else:
                    log = Path(record['logs']['stdout']['path'])
                    log.write_text(log.read_text().split('\n', 1)[1])
                    record['logs']['stdout'] = fact(log)
                with self.assertRaisesRegex(Error, 'wgi_trace_helper_alias|wine_pe_trace_missing_tool'):
                    wgi.audit_link_trace(context, record, operands)

    def test_raw_pe_is_preserved_and_only_timestamps_may_differ(self):
        old = pe_fixture()
        new = bytearray(old)
        struct.pack_into('<I', new, 0x88, 900)
        struct.pack_into('<I', new, 0x704, 901)
        raw = bytes(new)
        result = wgi.compare_pe(old, raw)
        self.assertFalse(result['raw_equal'])
        self.assertTrue(result['timestamp_only_equal'])
        self.assertEqual(bytes(new), raw)
        self.assertEqual(result['raw_sha256'], hashlib.sha256(raw).hexdigest())

    def test_rsds_code_import_or_other_rdata_difference_is_not_normalized(self):
        original = bytearray(pe_fixture())
        original[0x740:0x744] = b'RSDS'
        original = bytes(original)
        for offset in (0x210, 0x600, 0x744):
            with self.subTest(offset=offset):
                new = bytearray(original)
                new[offset] ^= 1
                result = wgi.compare_pe(original, bytes(new))
                self.assertFalse(result['timestamp_only_equal'])
                self.assertEqual(result['differing_bytes_after_timestamps'], 1)

    def test_arm64x_metadata_and_section_changes_are_refused(self):
        for offset, value in ((0x59e, 0xaa64), (0x188 + 36, 0)):
            new = bytearray(pe_fixture())
            struct.pack_into('<H' if offset == 0x59e else '<I', new, offset, value)
            with self.subTest(offset=offset), self.assertRaises(Error):
                wgi.compare_pe(pe_fixture(), bytes(new))

    def test_malformed_pe_refuses(self):
        with self.assertRaises(Error):
            wgi.compare_pe(pe_fixture(), b'MZ')

    def test_campaign_budget_includes_preserved_prior_attempt_and_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            paths = {name: root / name for name in ('pack', 'attempts', 'evidence')}
            for path in paths.values():
                path.mkdir()
            current = paths['attempts'] / 'current'
            current.mkdir()
            old = paths['attempts'] / 'failed'
            old.mkdir()
            (old / 'retained.raw').write_bytes(b'x' * 100)
            binding = paths['evidence'] / 'bindings.json'
            write_json(binding, {'storage_roots': {n: str(p) for n, p in paths.items()}})
            context = SimpleNamespace(output=current, root=lambda _: paths['pack'], recipe={'budget': {
                'additional_bytes': 50, 'floor_bytes': 0, 'pack_bytes': 100,
                'log_bytes': 100, 'output_bytes': 100, 'small_evidence_bytes': 100}})
            wgi.storage_bindings(context, binding)
            with self.assertRaisesRegex(Error, 'wgi_campaign_budget'):
                wgi.check_budget(context)
            context.recipe['budget']['additional_bytes'] = 10000
            value = wgi.check_budget(context)
            self.assertEqual(value['campaign']['attempts']['logical_bytes'], 100)
            self.assertGreater(value['campaign_logical_bytes'], 100)

    def test_storage_binding_cannot_omit_prior_output_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for name in ('pack', 'attempts', 'evidence', 'other'):
                (root / name).mkdir()
            binding = root / 'evidence/bindings.json'
            write_json(binding, {'storage_roots': {'pack': str(root / 'pack'), 'attempts': str(root / 'other'),
                                                 'evidence': str(root / 'evidence')}})
            context = SimpleNamespace(output=root / 'attempts/new', root=lambda _: root / 'pack')
            with self.assertRaisesRegex(Error, 'wgi_storage_coverage'):
                wgi.storage_bindings(context, binding)

    def test_snapshot_builder_change_refuses_before_materialization_or_child(self):
        before = [{'path': '/synthetic/driver.py', 'sha256': 'a' * 64, 'size_bytes': 10}]
        after = [dict(before[0], sha256='b' * 64)]
        context = SimpleNamespace(input=Mock(), run=Mock())
        with patch.object(wgi, 'sources', return_value=after):
            with self.assertRaisesRegex(Error, 'wgi_builder_snapshot_changed'):
                wgi.reconstruct(context, before)
        context.input.assert_not_called()
        context.run.assert_not_called()

    def test_final_receipt_bytes_are_counted_and_oversized_pass_becomes_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            roots = {name: root / name for name in ('pack', 'attempts', 'evidence')}
            for path in roots.values():
                path.mkdir()
            output = roots['attempts'] / 'current'
            output.mkdir()
            context = SimpleNamespace(output=output, wgi_storage_roots=roots, recipe={'budget': {
                'additional_bytes': 1024, 'floor_bytes': 0, 'pack_bytes': 100,
                'log_bytes': 100, 'output_bytes': 10000, 'small_evidence_bytes': 10000}})
            def save(status, comparisons=None, extra=None):
                receipt = {'status': status, 'retained_metadata': 'x' * 4096}
                write_json(output / 'build.json', receipt)
                return receipt
            context.finish = save
            with self.assertRaisesRegex(Error, 'wgi_campaign_budget'):
                wgi.finish(context, 'passed')
            receipt = json.loads((output / 'build.json').read_text())
            self.assertEqual(receipt['status'], 'failed')
            self.assertEqual(receipt['final_accounting_error'], 'wgi_campaign_budget')
            self.assertEqual(receipt['output_storage'], wgi.usage(context))

    def test_interrupt_during_final_accounting_cannot_leave_a_completed_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp).resolve()
            def save(status, comparisons=None, extra=None):
                receipt = dict(status=status, **extra)
                write_json(output / 'build.json', receipt)
                self.assertFalse(receipt['wgi_finalization_complete'])
                return receipt
            context = SimpleNamespace(output=output, finish=save)
            with patch.object(wgi, 'settle_storage', side_effect=[KeyboardInterrupt(), {}]):
                with self.assertRaises(KeyboardInterrupt):
                    wgi.finish(context, 'passed')
            receipt = json.loads((output / 'build.json').read_text())
            self.assertEqual(receipt['status'], 'failed')
            self.assertFalse(receipt['wgi_finalization_complete'])
            self.assertEqual(receipt['final_accounting_error'], 'KeyboardInterrupt')

    def test_undeclared_symlink_output_is_not_omitted_from_accounting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / 'alias').symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(Error, 'wgi_output_alias'):
                wgi.tree_usage(root)


if __name__ == '__main__':
    unittest.main()
