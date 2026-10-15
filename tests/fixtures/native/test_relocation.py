# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
import ast
import builtins
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest
from unittest.mock import patch

from pear_runtime.errors import Error
from pear_runtime.fixtures.inputs import fact,save,digest
from pear_runtime.fixtures.native import provider

ROOT=Path(__file__).resolve().parents[3]
PROVIDER=ROOT/'pear_runtime/providers/pear_legacy'


class RelocationInputTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        for name in ('runtime','operation'):save(self.root/(name+'.json'),{'input':name})
        runtime,operation=fact(self.root/'runtime.json'),fact(self.root/'operation.json')
        save(self.root/'authority.json',{'passed':True,'runtime_sha256':runtime['sha256'],'operation_ref':operation,'seconds':0.1})
        self.fixture=b'exact lifetime DLL'
        self.requirements={'fixture_suite':'mac-driver','guest_fixtures':{'lifetime_dll':{
            'machine':0xaa64,'execution_permitted':True,'sha256':digest(self.fixture)}}}
        self.packet={'entrypoints':{'lifetime_dll':'payload/lifetime.dll'},'code_publication_policy':'page-wx',
            'native_fixture_policy':{'scope':'development_native_wine_controls','runtime_ref':runtime,
                'operation_ref':operation,'authority_ref':fact(self.root/'authority.json'),'requirements':self.requirements}}
    def call(self):
        with provider.native_helpers(PROVIDER) as (_,helpers):
            fn=helpers.api.assess_relocation_events;ns=fn.__globals__
            self.assertIs(helpers.api.assess_case.__globals__['assess_relocation_events'],fn)
            self.assertEqual(fn.__code__.co_filename,str(PROVIDER/'tools/wine/api_runner.py'))
            ns['relocation_events']=lambda rows:None
            ns['relocation_file']=lambda *args:(self.fixture,(1,1))
            ns['read_relative']=lambda *args:self.fail('historical requirements reopened')
            def geometry(raw):
                self.assertEqual(raw,self.fixture);raise Error('original_geometry_oracle_reached')
            ns['relocation_image']=geometry
            return fn({'case':{'id':'abi'}},[],self.root,self.packet,self.root)
    def test_current_lifetime_identity_reaches_unchanged_geometry_oracle(self):
        with self.assertRaisesRegex(Error,'original_geometry_oracle_reached'):self.call()
    def test_missing_wrong_machine_or_permission_refused(self):
        original=dict(self.requirements['guest_fixtures']['lifetime_dll'])
        for entry in ({},{**original,'machine':0x8664},{**original,'machine':True},
                      {**original,'execution_permitted':False},{**original,'execution_permitted':1}):
            with self.subTest(entry=entry):
                self.requirements['guest_fixtures']['lifetime_dll']=entry
                with self.assertRaisesRegex(Exception,'relocation_signed_fixture'):self.call()
    def test_mismatched_current_fixture_hash_refused(self):
        self.requirements['guest_fixtures']['lifetime_dll']['sha256']='0'*64
        with self.assertRaisesRegex(Exception,'relocation_fixture_changed'):self.call()
    def test_unbound_authority_refused_before_fixture_read(self):
        self.packet['native_fixture_policy']['operation_ref']=self.packet['native_fixture_policy']['runtime_ref']
        with self.assertRaisesRegex(Error,'native_current_authority_required'):self.call()
    def test_ast_only_three_historical_input_statements_replaced(self):
        raw=(PROVIDER/'tools/wine/api_runner.py').read_bytes()
        original=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='assess_relocation_events')
        captured=[];real_compile=builtins.compile
        def compile_capture(source,*args,**kwargs):
            if isinstance(source,ast.Module):captured.append(source)
            return real_compile(source,*args,**kwargs)
        with patch('builtins.compile',side_effect=compile_capture):
            provider._relocation_requirements(raw,{},'original-api-runner')
        adapted=captured[-1].body[0]
        self.assertEqual(ast.dump(original.args),ast.dump(adapted.args))
        self.assertEqual([ast.dump(n) for n in original.body[:3]+original.body[6:]],
                         [ast.dump(n) for n in adapted.body[:3]+adapted.body[5:]])
    def test_original_case_input_validated_before_policy_projection(self):
        with provider.native_helpers(PROVIDER) as (_,helpers):
            original=sys.modules['api_runner'];base=sys.modules['run_fixtures']
            value={'schema_version':1,'record_kind':'wine_fixture_cases','suite':'api-abi',
                'qualification':'instrumented-arm64-pe-api-abi-only',
                'environment_policy':dict(original.ENVIRONMENT_POLICY),
                'cases':[{'id':'api','entrypoint':'api_pe','args':original.API_ARGS,'timeout_ms':180000,'expected_exit':0},
                         {'id':'abi','entrypoint':'abi_pe','args':[],'timeout_ms':180000,'expected_exit':0}],
                'controls':['x64_control','i386_control'],'provenance':{},
                'bounds':{'stdout_bytes':base.STREAM_LIMIT,'stderr_bytes':base.STREAM_LIMIT,
                    'event_bytes_per_process':base.EVENT_LIMIT,'total_event_bytes':original.TOTAL_EVENTS,
                    'max_processes':original.MAX_PROCESSES,'registration_ms':30000,
                    'grace_ms':3000,'terminate_ms':2000,'kill_ms':5000,'drain_ms':1000}}
            projected=helpers.api.validate_cases(value)
            self.assertEqual(projected,{**value,'environment_policy':helpers.api.ENVIRONMENT_POLICY})
            self.assertEqual(value['environment_policy']['prefix_initialization'],'fresh-wineboot')
            with self.assertRaisesRegex(Exception,'api_environment_policy'):
                helpers.api.validate_cases(projected)
            value['cases'][0]['expected_exit']=1
            with self.assertRaisesRegex(Exception,'unsupported_api_cases'):helpers.api.validate_cases(value)

    def test_actual_prefix_label_isolated_from_original_constant(self):
        with provider.native_helpers(PROVIDER) as (_,helpers):
            original=sys.modules['api_runner'].ENVIRONMENT_POLICY
            self.assertEqual(original['prefix_initialization'],'fresh-wineboot')
            self.assertEqual(helpers.api.ENVIRONMENT_POLICY,{**original,'prefix_initialization':provider.NATIVE_SEED_POLICY})
            helpers.api.validate_environment_policy(helpers.api.ENVIRONMENT_POLICY)
            with self.assertRaisesRegex(Exception,'api_environment_policy'):
                helpers.api.validate_environment_policy(original)

if __name__=='__main__':unittest.main()
