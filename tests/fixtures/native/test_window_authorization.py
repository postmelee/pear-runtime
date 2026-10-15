# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Current authority for the exact original window reader; no host execution."""
import ast
import builtins
import copy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pear_runtime.errors import Error, need
from pear_runtime.fixtures.inputs import fact, save
from pear_runtime.fixtures.native import provider

ROOT=Path(__file__).resolve().parents[3]
PROVIDER=ROOT/'pear_runtime/providers/pear_legacy'


class WindowAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        for name in ('runtime','operation'):
            save(self.root/(name+'.json'),{'bound':name})
        self.runtime=fact(self.root/'runtime.json')
        self.operation=fact(self.root/'operation.json')
        self.authority={'passed':True,'runtime_sha256':self.runtime['sha256'],
                        'operation_ref':self.operation}
        self.packet={'code_publication_policy':'page-wx',
            'entrypoints':{'stage4_pe':'stage4.exe','window_pe':'window.exe','window_driver_pe':'window.dll'},
            'native_fixture_policy':{'scope':'development_native_wine_controls',
                'runtime_ref':self.runtime,'operation_ref':self.operation,
                'authority_ref':None,'requirements':{}}}
        self.bind_authority()

    def bind_authority(self):
        save(self.root/'authority.json',self.authority)
        self.packet['native_fixture_policy']['authority_ref']=fact(self.root/'authority.json')

    def rejected(self, code, packet=None, case_id='window'):
        # Only guest-row decoding is substituted. The next original native-part
        # assertion must still fail after a successful current authorization.
        with patch('subprocess.Popen',side_effect=AssertionError('host execution forbidden')):
            with provider.native_helpers(PROVIDER) as (_,helpers):
                result={'case':{'id':case_id},'events':{'loader':[]}}
                with patch.object(helpers.window,'group_rows',return_value=({},[])):
                    with self.assertRaises(Exception) as caught:
                        helpers.window.assess([],result,self.root,self.packet if packet is None else packet,{})
        self.assertEqual(getattr(caught.exception,'code',None),code)

    def test_valid_current_policy_reaches_original_native_parts(self):
        self.assertNotIn('authorization_scope',self.packet)
        self.rejected('window_native_part_count')

    def test_historical_scope_alone_is_not_authority(self):
        self.rejected('native_current_authority_required',
                      {'authorization_scope':'development_windows_mac_driver_fixtures'})

    def test_missing_or_wrong_current_policy_refused(self):
        missing=copy.deepcopy(self.packet);missing.pop('native_fixture_policy')
        self.rejected('native_current_authority_required',missing)
        wrong=copy.deepcopy(self.packet)
        wrong['native_fixture_policy']['scope']='development_windows_mac_driver_fixtures'
        self.rejected('native_current_authority_required',wrong)

    def test_wrong_case_refused_before_authority(self):
        with patch.object(provider,'validate_suite_authorization',side_effect=AssertionError('wrong case reached authority')):
            self.rejected('window_authorization_scope',case_id='api')

    def test_stale_authority_bytes_refused(self):
        save(self.root/'authority.json',{'changed':True})
        self.rejected('assembly_reference_changed')

    def test_mismatched_runtime_authority_refused(self):
        self.authority['runtime_sha256']='0'*64;self.bind_authority()
        self.rejected('native_current_authority_required')

    def test_mismatched_operation_authority_refused(self):
        self.authority['operation_ref']=self.runtime;self.bind_authority()
        self.rejected('native_current_authority_required')

    def test_failed_or_nonboolean_authority_refused(self):
        for value in (False,1,None):
            with self.subTest(value=value):
                self.authority['passed']=value;self.bind_authority()
                self.rejected('native_current_authority_required')

    def test_changed_runtime_or_operation_bytes_refused(self):
        for name in ('runtime','operation'):
            with self.subTest(name=name):
                original=(self.root/(name+'.json')).read_bytes()
                save(self.root/(name+'.json'),{'changed':True})
                self.rejected('assembly_reference_changed')
                (self.root/(name+'.json')).write_bytes(original)

    def test_exact_seam_mutations_refused(self):
        raw,_=provider.window_capture();text=raw.decode()
        variants={
            'condition':text.replace("signed.get('authorization_scope')", "signed.get('another_scope')"),
            'position':text.replace('    identity, cycles = group_rows(rows)','    pass\n    identity, cycles = group_rows(rows)'),
            'arguments':text.replace('def assess(rows, result, runtime, signed, dynamic):','def assess(rows, result, runtime, signed, extra):'),
            'duplicate':text+'\ndef assess(rows, result, runtime, signed, dynamic):\n    pass\n',
            'missing':text.replace('def assess(rows, result, runtime, signed, dynamic):','def other(rows, result, runtime, signed, dynamic):'),
        }
        for name,changed in variants.items():
            with self.subTest(name=name):
                namespace={'need':need}
                with self.assertRaisesRegex(Error,'native_window_authorization_seam'):
                    provider._window_authorization(changed.encode(),namespace,'window-provider')
                self.assertNotIn('assess',namespace)
                self.assertNotIn('_pear_current_suite_authorization',namespace)

    def test_only_one_original_statement_is_replaced(self):
        raw,ref=provider.window_capture()
        original=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='assess')
        compiled=[]
        def capture(tree,*args,**kwargs):
            compiled.append(copy.deepcopy(tree))
            return builtins.compile(tree,*args,**kwargs)
        namespace={'need':need}
        with patch.object(provider,'compile',side_effect=capture,create=True):
            provider._window_authorization(raw,namespace,ref['path'])
        self.assertEqual(len(compiled),1)
        self.assertEqual(len(compiled[0].body),1)
        adapted=compiled[0].body[0]
        dump=lambda node:ast.dump(node,include_attributes=False)
        self.assertEqual(dump(original.args),dump(adapted.args))
        self.assertEqual([dump(n) for n in original.body[:2]+original.body[3:]],
                         [dump(n) for n in adapted.body[:2]+adapted.body[4:]])
        self.assertEqual(len(original.body),28)
        self.assertEqual(len(adapted.body),29)
        self.assertEqual([ast.unparse(n) for n in adapted.body[2:4]],[
            "need(result['case']['id'] == 'window', 'window_authorization_scope')",
            "_pear_current_suite_authorization('mac-driver', signed)"])
        self.assertIs(namespace['_pear_current_suite_authorization'],provider.validate_suite_authorization)
        self.assertEqual(namespace['assess'].__code__.co_filename,ref['path'])
        self.assertEqual(provider.window_capture(),(raw,ref))

    def test_original_classes_and_alias_restored_after_refusal(self):
        previous=sys.modules.get('window_evidence');present='window_evidence' in sys.modules
        with patch('subprocess.Popen',side_effect=AssertionError('host execution forbidden')):
            with self.assertRaisesRegex(RuntimeError,'stop'):
                with provider.native_helpers(PROVIDER) as (_,helpers):
                    self.assertIs(helpers.api.APISession,sys.modules['api_runner'].APISession)
                    self.assertIs(helpers.api.APIObserver,sys.modules['api_runner'].APIObserver)
                    self.assertIs(helpers.base.Session,sys.modules['run_fixtures'].Session)
                    self.assertIs(helpers.window.assess.__globals__,vars(helpers.window))
                    self.assertIs(helpers.window.__dict__['_pear_current_suite_authorization'],provider.validate_suite_authorization)
                    raise RuntimeError('stop')
        self.assertEqual('window_evidence' in sys.modules,present)
        self.assertIs(sys.modules.get('window_evidence'),previous)


if __name__=='__main__':unittest.main()
