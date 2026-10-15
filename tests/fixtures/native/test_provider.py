# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
import ast
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

from pear_runtime.errors import Error
from pear_runtime.fixtures.inputs import fact
from pear_runtime.fixtures.native import provider

ROOT=Path(__file__).resolve().parents[3]
PROVIDER=ROOT/'pear_runtime/providers/pear_legacy'


class ProviderTests(unittest.TestCase):
    def test_original_classes_and_transitive_geometry(self):
        with patch('subprocess.Popen',side_effect=AssertionError('host execution forbidden')):
            with provider.native_helpers(PROVIDER) as (life,h):
                raw=life.read_relative(PROVIDER,'tools/wine/api_runner.py')
                tree=ast.parse(raw)
                for name in ('APISession','APIObserver'):
                    self.assertEqual(getattr(h.api,name).__module__,'api_runner')
                self.assertEqual(h.base.Session.__module__,'run_fixtures')
                self.assertIs(h.api.APISession,sys.modules['api_runner'].APISession)
                self.assertIs(h.api.APIObserver,sys.modules['api_runner'].APIObserver)
                self.assertIs(h.base.Session,sys.modules['run_fixtures'].Session)
                self.assertEqual(h.api.run_case.__code__.co_filename,str(PROVIDER/'tools/wine/api_runner.py'))
                self.assertIs(h.api.assess_case.__globals__['assess_arena_events'],h.api.assess_arena_events)
                self.assertIs(h.api.assess_dynamic_events.__globals__['_process'],h.dynamic._process)
                self.assertIs(h.dynamic._process.__globals__['validate_budget'],h.dynamic.validate_budget)
                self.assertEqual(h.base.STREAM_LIMIT,262144)
                self.assertTrue(callable(provider.bootstrap_assessment(life,h,PROVIDER)))
                self.assertEqual(h.window.expected_results()[0]['cycles'],20)

    def test_alias_restoration_even_exception(self):
        old=object();previous=sys.modules.get('window_evidence',None);had='window_evidence' in sys.modules
        sys.modules['window_evidence']=old
        try:
            with self.assertRaisesRegex(RuntimeError,'stop'):
                with provider.native_helpers(PROVIDER):raise RuntimeError('stop')
            self.assertIs(sys.modules['window_evidence'],old)
        finally:
            if had:sys.modules['window_evidence']=previous
            else:sys.modules.pop('window_evidence',None)

    def test_source_mutation_after_capture_refused(self):
        raw,ref=provider.window_capture(); changed={**ref,'sha256':'0'*64}
        with patch.object(provider,'window_capture',side_effect=[(raw,ref),(raw,changed)]):
            with self.assertRaisesRegex(Error,'native_window_provider_changed'):
                with provider.native_helpers(PROVIDER):pass
        self.assertNotIn('window_evidence',sys.modules)

    def test_old_saved_grant_refused(self):
        with self.assertRaisesRegex(Error,'native_current_authority_required'):
            provider.validate_suite_authorization('mac-driver',{'authorization_scope':'development_windows_mac_driver_fixtures',
                'code_publication_policy':'page-wx','entrypoints':{'stage4_pe':'x','window_pe':'y','window_driver_pe':'z'}})

    def test_target_reader_assertions_are_original(self):
        raw=(PROVIDER/'tools/wine/api_runner.py').read_bytes()
        original=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='target_controls')
        with provider.native_helpers(PROVIDER) as (_,h):
            namespace=h.api.target_controls.__globals__
            seen=[]
            namespace['validate_suite_authorization']=lambda suite,packet:seen.append(suite)
            with self.assertRaisesRegex(Exception,'control_execution_forbidden'):
                h.api.target_controls(Path('.'),{'native_fixture_policy':{'requirements':{
                    'fixture_suite':'mac-driver','guest_fixtures':{'x64_control':{'execution_permitted':True}}}}})
            self.assertEqual(seen,['mac-driver'])


    def test_current_variant_changes_only_query_row_and_path_seam(self):
        with TemporaryDirectory() as tmp:
            fixture=Path(tmp).resolve()/'fixture.exe';fixture.write_bytes(b'fixed-fixture')
            variant={'variant':'arm64ec-class181-arm64-i386-v1','fixture_ref':fact(fixture),
                     'expected_architecture':{'version':1,'record_kind':'pear_architecture_result','status':0,
                         'returned_bytes':12,'machines':[43620,332],'flags':[7,18],'terminator':0}}
            with patch('subprocess.Popen',side_effect=AssertionError('host execution forbidden')):
                with provider.native_helpers(PROVIDER) as (_,original):
                    expected=original.api.expected_api_rows()
                with provider.native_helpers(PROVIDER,variant=variant) as (_,h):
                    self.assertEqual(h.api.expected_api_rows(),[variant['expected_architecture'],*expected[1:]])
                    self.assertIs(h.api.APISession,sys.modules['api_runner'].APISession)
                    self.assertIs(h.api.APIObserver,sys.modules['api_runner'].APIObserver)
                    self.assertIs(h.api.assess_case.__globals__['expected_api_rows'],h.api.expected_api_rows)
                    self.assertEqual(h.api.run_case.__code__.co_filename,str(PROVIDER/'tools/wine/api_runner.py'))
                    packet={'native_api_variant':variant,'entrypoints':{'api_pe':str(fixture),'loader':'payload/wine'}}
                    paths=h.api.native_api_paths(Path('/runtime'),packet)
                    self.assertEqual(paths,{'api_pe':fixture,'loader':Path('/runtime/payload/wine')})
                    with self.assertRaisesRegex(Error,'native_api_variant_entrypoint'):
                        h.api.native_api_paths(Path('/runtime'),{**packet,'entrypoints':{'api_pe':'other.exe'}})
                    fixture.write_bytes(b'changed')
                    with self.assertRaisesRegex(Error,'assembly_reference_changed'):
                        h.api.native_api_paths(Path('/runtime'),packet)
                with provider.native_helpers(PROVIDER) as (_,original):
                    self.assertEqual(original.api.expected_api_rows(),expected)

    def test_variant_rejects_any_extra_or_relaxed_enumeration(self):
        variant={'variant':'arm64ec-class181-arm64-i386-v1','expected_architecture':{
            'version':1,'record_kind':'pear_architecture_result','status':0,'returned_bytes':12,
            'machines':[43620,332],'flags':[7,7],'terminator':0}}
        with self.assertRaisesRegex(Error,'native_api_variant_expected'):
            with provider.native_helpers(PROVIDER,variant=variant):pass
        self.assertNotIn('window_evidence',sys.modules)

    def test_seed_clones_once_and_keeps_original_environment(self):
        calls=[];base=SimpleNamespace(environment=lambda *args:calls.append(args) or {'ORIGINAL':'kept'})
        observation={};seed=object();origin={'cold_prefix_initialization':False,'seed_ref':{'exact':True}}
        with patch('pear_runtime.fixtures.controls.execution.clone_prefix',return_value=origin) as clone, \
             patch.object(provider,'configure_menu',return_value={'one_entry':True}) as menu:
            provider._seed_environment(base,seed,observation)
            for _ in range(3):self.assertEqual(base.environment('home','prefix','nonce'),{'ORIGINAL':'kept'})
            clone.assert_called_once_with(seed,'prefix');self.assertEqual(len(calls),3)
            self.assertEqual(observation,{**origin,'policy':provider.NATIVE_SEED_POLICY,'configuration':{'one_entry':True}})
            menu.assert_called_once_with(seed,'prefix')
            with self.assertRaisesRegex(Error,'native_seed_multiple_prefixes'):base.environment('home','other','nonce')

    def test_seed_failure_precedes_any_original_environment_or_launch(self):
        base=SimpleNamespace(environment=lambda *args:self.fail('original environment called'))
        with patch('pear_runtime.fixtures.controls.execution.clone_prefix',side_effect=Error('changed-seed')):
            provider._seed_environment(base,object(),{})
            with self.assertRaisesRegex(Error,'changed-seed'):base.environment('home','prefix','nonce')

if __name__=='__main__':unittest.main()
