# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Original supervisor import, namespace, source-binding and cleanup controls."""
import ast
from contextlib import ExitStack
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import CodeType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from pear_runtime.errors import Error
from pear_runtime.fixtures import supervision as subject
from pear_runtime.assembly.helpers import SourcePack, signing_helpers

REPO = Path(__file__).resolve().parents[2]
PROVIDER = REPO / 'pear_runtime/providers/pear_legacy'
MANIFEST = REPO / 'provenance/fixture-provider-import.json'
ALIASES = (*subject.WINE_HELPERS, subject.AUDIT_ALIAS)


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.temp = Path(temp.name).resolve()

    def copy_provider(self):
        target = self.temp / 'provider'
        shutil.copytree(PROVIDER, target)
        return target

    def test_exact_provider_set_and_refs_without_import(self):
        with patch('importlib.util.module_from_spec', side_effect=AssertionError('must not import')):
            refs = subject.source_refs(PROVIDER)
        data = json.loads(MANIFEST.read_text())
        self.assertEqual(set(refs), subject.SOURCE_PATHS)
        self.assertEqual(len(refs), 17)
        self.assertEqual(sum(r['size_bytes'] for r in refs.values()), 546159)
        for row in data['files']:
            self.assertEqual(refs[row['path']]['sha256'], row['sha256'])
        self.assertEqual(subject.provenance_ref()['sha256'], hashlib.sha256(MANIFEST.read_bytes()).hexdigest())

    def test_missing_file_has_no_old_worktree_fallback(self):
        root = self.copy_provider(); (root / 'tools/wine/common.py').unlink()
        with self.assertRaises(FileNotFoundError), patch('importlib.util.module_from_spec') as load:
            with subject.supervision(root): pass
        load.assert_not_called()

    def test_changed_file_is_rejected_before_any_exec(self):
        root = self.copy_provider(); path = root / 'tools/wine/api_runner.py'
        path.write_bytes(path.read_bytes() + b'\nraise RuntimeError("unreviewed")\n')
        with self.assertRaisesRegex(Error, 'fixture_provider_changed'), patch('importlib.util.module_from_spec') as load:
            with subject.supervision(root): pass
        load.assert_not_called()

    def test_file_and_root_aliases_rejected(self):
        root = self.copy_provider(); leaf = root / 'tools/wine/common.py'
        leaf.unlink(); leaf.symlink_to(PROVIDER / 'tools/wine/common.py')
        with self.assertRaisesRegex(Error, 'fixture_provider_alias'): subject.source_refs(root)
        alias = self.temp / 'alias'; alias.symlink_to(PROVIDER, target_is_directory=True)
        with self.assertRaisesRegex(Error, 'assembly_root_alias'): subject.source_refs(alias)
        with self.assertRaisesRegex(Error, 'assembly_root_alias'): subject.source_refs(Path('pear_runtime/providers/pear_legacy'))

    def test_every_source_captured_before_module_creation(self):
        captured = set(); read = subject.read_relative; create = importlib.util.module_from_spec
        def observe_read(root, name, *args):
            raw = read(root, name, *args)
            if name in subject.SOURCE_PATHS: captured.add(name)
            return raw
        def observe_create(spec):
            self.assertEqual(captured, subject.SOURCE_PATHS)
            return create(spec)
        with patch.object(subject, 'read_relative', side_effect=observe_read), \
             patch('importlib.util.module_from_spec', side_effect=observe_create):
            with subject.supervision(PROVIDER) as (life, helpers):
                self.assertEqual(len(life.source_refs), 17)
                self.assertEqual(helpers.api.APISession.__module__, 'api_runner')

    def test_original_classes_and_loaded_method_code_are_unchanged(self):
        manifest = json.loads(MANIFEST.read_text())
        with subject.supervision(PROVIDER) as (_, helpers):
            for row in manifest['original_supervisor_body_pins']:
                path = PROVIDER / row['source_path']; raw = path.read_bytes(); tree = ast.parse(raw)
                node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == row['symbol'])
                self.assertEqual(hashlib.sha256(ast.get_source_segment(raw.decode(), node).encode()).hexdigest(),
                                 row['source_segment_sha256'])
                code = compile(raw, str(path), 'exec', dont_inherit=True)
                original_class = next(c for c in code.co_consts if isinstance(c, CodeType) and c.co_name == row['symbol'])
                module = helpers.api if row['source_path'].endswith('api_runner.py') else helpers.base
                loaded = getattr(module, row['symbol'])
                for c in original_class.co_consts:
                    if isinstance(c, CodeType):
                        actual = getattr(loaded, c.co_name)
                        # Code equality compares nested constants without marshal's
                        # incidental string-reference/interning encoding.
                        self.assertEqual(actual.__code__, c, (row['symbol'], c.co_name))
                        self.assertEqual(actual.__code__.co_filename, c.co_filename)

    def test_prepare_changes_only_reviewed_top_level_seam(self):
        raw = (PROVIDER / 'tools/wine/prepare.py').read_bytes()
        old = ast.parse(raw); new = subject._prepare_tree(raw, 'prepare.py')
        selected = lambda t: [ast.dump(n, include_attributes=False) for n in t.body
                              if isinstance(n, (ast.FunctionDef, ast.ClassDef))]
        self.assertEqual(selected(old), selected(new))
        malformed = raw.replace(b'_spec.loader.exec_module(_audit)', b'_spec.loader.exec_module(other)')
        with self.assertRaisesRegex(Error, 'fixture_provider_audit_seam'):
            subject._prepare_tree(malformed, 'prepare.py')

    def test_audit_uses_captured_bytes_and_post_use_detects_mutation(self):
        root = self.copy_provider(); audit = root / subject.AUDIT_PATH
        create = importlib.util.module_from_spec; once = False
        def mutate_after_capture(spec):
            nonlocal once
            if not once:
                once = True
                audit.write_bytes(b'raise AssertionError("reopened audit bytes")\n')
            return create(spec)
        with patch('importlib.util.module_from_spec', side_effect=mutate_after_capture):
            with self.assertRaisesRegex(Error, 'fixture_provider_changed'):
                with subject.supervision(root) as (_, helpers):
                    self.assertTrue(callable(helpers.api.APISession))
                    self.assertTrue(callable(sys.modules['prepare']._audit.bounded_git))

    def test_aliases_and_path_restored_on_success_and_body_failure(self):
        previous = {name: (name in sys.modules, sys.modules.get(name)) for name in ALIASES}
        marker = SimpleNamespace(marker='prior module')
        for name in ALIASES: sys.modules[name] = marker
        sys.modules['common'] = None
        prior_path = list(sys.path)
        try:
            for fails in (False, True):
                try:
                    with subject.supervision(PROVIDER) as (_, helpers):
                        self.assertIsNot(sys.modules['api_runner'], marker)
                        sys.path.append('synthetic temporary import path')
                        self.assertEqual(helpers.base.STREAM_LIMIT, 2 * 1024**2)
                        self.assertNotIn('metal_pairing_images', helpers.api.EVENTS)
                        self.assertIn('metal_pairing_images', helpers.assess_native.__globals__['EVENTS'])
                        if fails: raise RuntimeError('primary execution failure')
                except RuntimeError as exc:
                    self.assertTrue(fails); self.assertEqual(str(exc), 'primary execution failure')
                self.assertEqual(sys.path, prior_path)
                for name in ALIASES:
                    self.assertIn(name, sys.modules)
                    self.assertIs(sys.modules[name], None if name == 'common' else marker)
        finally:
            for name, (present, module) in previous.items():
                if present: sys.modules[name] = module
                else: sys.modules.pop(name, None)
            sys.path[:] = prior_path

    def test_loading_failure_restores_aliases(self):
        previous = {n: (n in sys.modules, sys.modules.get(n)) for n in ALIASES}
        prior_path = list(sys.path)
        with patch.object(subject, '_prepare_tree', side_effect=RuntimeError('loader failure')):
            with self.assertRaisesRegex(RuntimeError, 'loader failure'):
                with subject.supervision(PROVIDER): pass
        self.assertEqual(sys.path, prior_path)
        self.assertEqual({n: (n in sys.modules, sys.modules.get(n)) for n in ALIASES}, previous)
        with subject.supervision(PROVIDER): pass

    def test_primary_failure_survives_provider_recheck_failure(self):
        root = self.copy_provider()
        with self.assertRaisesRegex(RuntimeError, 'primary failure') as raised:
            with subject.supervision(root):
                (root / 'tools/wine/common.py').write_bytes(b'changed')
                raise RuntimeError('primary failure')
        self.assertIn('fixture_provider_changed', raised.exception.__notes__[0])

    def test_overlapping_context_refused_without_corrupting_active_aliases(self):
        with subject.supervision(PROVIDER) as (_, helpers):
            with self.assertRaisesRegex(Error, 'fixture_supervision_busy'):
                with subject.supervision(PROVIDER): pass
            self.assertIs(sys.modules['api_runner'], helpers.api)

    def test_import_constructs_no_host_session_and_runs_no_command(self):
        forbidden = AssertionError('native operation during import')
        with ExitStack() as stack:
            for target in ('subprocess.Popen', 'subprocess.run', 'ctypes.CDLL', 'os.killpg',
                           'os.fork', 'socket.socket'):
                stack.enter_context(patch(target, side_effect=forbidden))
            with subject.supervision(PROVIDER) as (_, helpers):
                self.assertTrue(issubclass(helpers.api.APISession, helpers.base.Session))
                self.assertEqual(Path(helpers.api.__file__), PROVIDER / 'tools/wine/api_runner.py')
                self.assertEqual(sys.modules['common'].REPO, PROVIDER)

    def test_existing_signing_selector_accepts_canonical_provider(self):
        helpers, reader = signing_helpers(SourcePack(PROVIDER))
        self.assertTrue(callable(helpers.capture_authorization))
        self.assertTrue(callable(reader.inventory))

    def test_original_environment_refusals_and_packet_fields(self):
        work = self.temp / 'work'; prefix = self.temp / 'prefix'
        env = subject.environment(work, prefix, 'a' * 32, None)
        self.assertEqual(env['TMPDIR'], str(work / 'tmp')); self.assertNotIn('HOME', env)
        for nonce, home in [('A' * 32, None), ('a' * 32, 'relative'), ('a' * 32, '/bad\0home')]:
            with self.assertRaises(Error): subject.environment(work, prefix, nonce, home)
        with self.assertRaises(Error): subject.loader_environment(env, str(self.temp/'control'), 20, 'a'*32)
        packet = subject.assessment_packet({'entrypoints': {'loader': 'l', 'server': 's', 'ntdll_native': 'n'},
                                            'native_images': ['evidence'], 'baseline_loader_capacity': {'x': 1}})
        self.assertEqual(packet['entrypoints'], {'loader': 'l', 'server': 's', 'ntdll': 'n'})
        self.assertEqual(packet['code_publication_policy'], 'page-wx')

    def test_original_loader_environment_binds_integer_and_retains_scope(self):
        value = subject.loader_environment({'BASE': 'kept'}, '/private/tmp/pear-stage3-synthetic/control', 42, 'a'*32)
        self.assertEqual(value['BASE'], 'kept')
        self.assertEqual(value['PEAR_BOOTSTRAP_SERVER_PID'], '42')
        self.assertEqual(value['PEAR_FEX_BITMAP_DIAGNOSTICS'], '1')
        for pid in (True, 1, 2**31):
            with self.assertRaisesRegex(Error, 'memory_wine_control_scope'):
                subject.loader_environment({}, '/private/tmp/pear-stage3-synthetic/control', pid, 'a'*32)

    def test_original_cleanup_attempts_server_sentinel_and_logs_after_error(self):
        calls = []
        complete = {'signals': [], 'errors': [], 'observation_gap': False, 'reaped': {'server': True}, 'complete': True}
        def cleanup(roles, bounds):
            calls.append(roles)
            if roles == ('loader', 'server'): raise RuntimeError('synthetic cleanup failure')
            return complete
        session = SimpleNamespace(observer=SimpleNamespace(refresh=lambda: None, registrations={}),
                                  children={}, cleanup=cleanup, finish_logs=lambda bound: [])
        with subject.supervision(PROVIDER) as (life, _):
            result = life.cleanup_session(session, None, None, self.temp)
        self.assertEqual(calls, [('loader', 'server'), ('server',), ('sentinel',)])
        self.assertFalse(result[1]['complete']); self.assertEqual(result[3], [])
        self.assertEqual(result[5][0]['operation'], 'owned_group_cleanup')


if __name__ == '__main__': unittest.main()
