# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic recovery boundaries; no native runtime, signing or compilation."""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import uuid

from pear_runtime import build, recovery
from pear_runtime.errors import Error


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pear-recovery-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.sources = self.root/'source'; self.sources.mkdir()
        self.headers = self.root/'headers'; self.headers.mkdir()
        self.metadata = self.root/'metadata'; self.metadata.mkdir()
        self.products = self.root/'build'; self.products.mkdir()
        self.candidate = self.root/'candidate'; self.candidate.mkdir()
        self.operation = self.root/'candidate-operation'; self.operation.mkdir()
        self.outputs = self.root/'outputs'; self.outputs.mkdir()
        self.output = self.outputs/'restore'
        self.header = self.headers/'wire.h'; self.header.write_bytes(b'original shared header\n'); self.header.chmod(0o644)
        self.recipe = {'schema_version':1,'name':'synthetic-recovery',
            'roots':{'wine':{'kind':'git','commit':'1'*40},'common_headers':{'kind':'input'}},
            'inputs':[dict(root='common_headers',path='wire.h',mode=0o644,
                **{k:v for k,v in build.fact(self.header).items() if k!='path'})],
            'budget':{'additional_bytes':0,'floor_bytes':recovery.RESERVE_BYTES}}
        self.recipe_path=self.metadata/'recipe.json';build.write_json(self.recipe_path,self.recipe)
        self.bindings={'roots':{'wine':str(self.sources),'common_headers':str(self.headers)}}
        self.binding_path=self.metadata/'bindings.json';build.write_json(self.binding_path,self.bindings)
        artifact=self.products/'native.so';artifact.write_bytes(b'not an executable; identity fixture')
        stdout=self.products/'stdout';stdout.write_bytes(b'original output\n')
        stderr=self.products/'stderr';stderr.write_bytes(b'')
        opid=str(uuid.uuid4())
        self.receipt={'schema_version':1,'scope':'development_component_build','status':'passed',
            'runtime_eligible':False,'game_qualified':False,'operation_id':opid,
            'recipe_sha256':build.fact(self.recipe_path)['sha256'],
            'roots':{name:{**row,'path':self.bindings['roots'][name]} for name,row in self.recipe['roots'].items()},
            'commands':[{'id':'synthetic','exit_code':0,'error':None,
                         'logs':{'stdout':build.fact(stdout),'stderr':build.fact(stderr)}}],
            'outputs':{'native.so':build.fact(artifact)},'artifacts':{'wine_native':build.fact(artifact)}}
        build.write_json(self.products/'build.json',self.receipt)
        build.write_json(self.products/'operation.json',{'scope':'task56_component_build','operation_id':opid,'released':True})
        assembly_id=str(uuid.uuid4())
        runtime={'passed':True,'diagnostic_only':True,'runtime_qualified':False,'game_qualified':False,
                 'execution_authorized_by_this_record':False,
                 'assembly_operation':{'path':str(self.operation/'operation.json'),'operation_id':assembly_id},
                 'development_assembly':{'artifacts':self.receipt['artifacts'],
                    'builds':[build.fact(self.products/'build.json')],
                    'component_operations':[build.fact(self.products/'operation.json')]}}
        build.write_json(self.candidate/'runtime.json',runtime)
        operation={'schema_version':1,'scope':'development_candidate_assembly_operation',
            'operation_id':assembly_id,'status':'passed','runtime_ref':build.fact(self.candidate/'runtime.json'),
            'lock':{'released':True},'plan':{'output':str(self.candidate),'operation_output':str(self.operation)}}
        build.write_json(self.operation/'operation.json',operation)
        self.lock={'schema_version':1,'scope':'task56_development_reconstruction',
            'recipes':{'wine':{**self.ident(build.fact(self.recipe_path)),
                              'source_roots':{'wine':{'kind':'git','commit':'1'*40}}}},
            'artifact_identities_before_signing':{'wine_native':self.ident(build.fact(artifact))},
            'assembly_receipt_identity':self.ident(build.fact(self.candidate/'runtime.json')),
            'operation_receipt_identity':self.ident(build.fact(self.operation/'operation.json'))}
        self.lock_path=self.metadata/'lock.json';build.write_json(self.lock_path,self.lock)
        self.request={'schema_version':1,'scope':'development_input_recovery','component':'wine',
            'lock_ref':build.fact(self.lock_path),'recipe_ref':build.fact(self.recipe_path),
            'bindings_ref':build.fact(self.binding_path),'build_ref':build.fact(self.products/'build.json'),
            'runtime_ref':build.fact(self.candidate/'runtime.json'),
            'operation_ref':build.fact(self.operation/'operation.json'),
            'input_root':'common_headers','output':str(self.output),'max_output_bytes':recovery.MAX_BYTES}
        self.request_path=self.metadata/'request.json';self.write_request()
        self.space=patch.object(recovery.shutil,'disk_usage',return_value=SimpleNamespace(free=100*1024**3))
        self.space.start();self.addCleanup(self.space.stop)

    @staticmethod
    def ident(ref):
        return {key:ref[key] for key in ('sha256','size_bytes')}

    def write_request(self):
        build.write_json(self.request_path,self.request)

    def changed_recipe(self):
        build.write_json(self.recipe_path,self.recipe)
        ref=build.fact(self.recipe_path);self.request['recipe_ref']=ref
        self.lock['recipes']['wine'].update(self.ident(ref))
        build.write_json(self.lock_path,self.lock);self.request['lock_ref']=build.fact(self.lock_path)
        self.receipt['recipe_sha256']=ref['sha256']
        build.write_json(self.products/'build.json',self.receipt)
        self.request['build_ref']=build.fact(self.products/'build.json')
        runtime=build.load(self.candidate/'runtime.json')
        runtime['development_assembly']['builds']=[self.request['build_ref']]
        build.write_json(self.candidate/'runtime.json',runtime)
        self.request['runtime_ref']=build.fact(self.candidate/'runtime.json')
        operation=build.load(self.operation/'operation.json');operation['runtime_ref']=self.request['runtime_ref']
        build.write_json(self.operation/'operation.json',operation)
        self.request['operation_ref']=build.fact(self.operation/'operation.json')
        self.lock['assembly_receipt_identity']=self.ident(self.request['runtime_ref'])
        self.lock['operation_receipt_identity']=self.ident(self.request['operation_ref'])
        build.write_json(self.lock_path,self.lock);self.request['lock_ref']=build.fact(self.lock_path)
        self.write_request()

    def test_inspection_is_read_only_and_does_not_enter_or_run(self):
        with (patch.object(build.Context,'__enter__',side_effect=AssertionError('no lease')),
              patch.object(build.Context,'run',side_effect=AssertionError('no child'))):
            plan=recovery.inspect(self.request_path)[1]
        self.assertFalse(self.output.exists())
        self.assertEqual(plan['file_count'],1)
        self.assertFalse(plan['full_recipe_admission_performed'])
        self.assertFalse(plan['current_authority_assessed'])
        self.assertFalse(plan['build_or_runtime_execution_performed'])
        self.assertEqual(plan['historical_source_pins'],{'wine':'1'*40})

    def test_exact_root_and_binding_restore_preserve_originals(self):
        original={path:build.fact(path) for path in (self.header,self.binding_path,self.products/'build.json',self.candidate/'runtime.json')}
        result=recovery.restore(self.request_path)
        restored=self.output/'inputs/common_headers/wire.h'
        self.assertEqual(restored.read_bytes(),self.header.read_bytes())
        self.assertEqual(restored.stat().st_mode&0o777,0o644)
        self.assertNotEqual(restored.stat().st_ino,self.header.stat().st_ino)
        self.assertEqual((self.output/'original-bindings.json').read_bytes(),self.binding_path.read_bytes())
        rebound=build.load(self.output/'rebound-bindings.json')
        self.assertEqual(rebound['roots']['wine'],str(self.sources))
        self.assertEqual(rebound['roots']['common_headers'],str(restored.parent))
        self.assertEqual(result['status'],'passed')
        self.assertTrue(result['historical_build_binding_unchanged'])
        self.assertFalse(result['full_input_pack_restored'])
        self.assertTrue(all(build.fact(path)==ref for path,ref in original.items()))
        self.assertFalse((self.output/'unperformed-build').exists())

    def test_missing_declared_input_refuses_before_output(self):
        self.header.unlink()
        with self.assertRaises(FileNotFoundError): recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_mismatched_declared_input_refuses_before_output(self):
        self.header.write_bytes(b'changed')
        with self.assertRaisesRegex(Error,'build_input_mismatch'):recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_wrong_mode_refuses_before_output(self):
        self.header.chmod(0o600)
        with self.assertRaisesRegex(Error,'build_input_mode'):recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_root_is_complete_not_a_chosen_file_subset(self):
        row=deepcopy(self.recipe['inputs'][0]);row['path']='missing-second.h'
        self.recipe['inputs'].append(row);self.changed_recipe()
        with self.assertRaises(FileNotFoundError):recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_git_toolchain_and_unselected_root_are_not_relabelled_as_inputs(self):
        for name in ('wine','not-declared'):
            self.request['input_root']=name;self.write_request()
            with self.assertRaisesRegex(Error,'recovery_immutable_root'):recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_symlink_and_root_alias_refused(self):
        moved=self.headers/'original';self.header.rename(moved);self.header.symlink_to(moved.name)
        with self.assertRaisesRegex(Error,'build_input_alias'):recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_changed_recipe_cannot_supply_its_own_expected_hash(self):
        self.recipe['name']='unreviewed';build.write_json(self.recipe_path,self.recipe)
        self.request['recipe_ref']=build.fact(self.recipe_path);self.write_request()
        with self.assertRaisesRegex(Error,'recovery_recipe_lock'):recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_historical_build_source_pin_cannot_follow_new_head(self):
        self.receipt['roots']['wine']['commit']='2'*40
        build.write_json(self.products/'build.json',self.receipt)
        self.request['build_ref']=build.fact(self.products/'build.json');self.write_request()
        with self.assertRaisesRegex(Error,'assembly_build_sources'):recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_rebinding_does_not_rewrite_historical_receipt_roots(self):
        other=self.root/'other';other.mkdir()
        changed=deepcopy(self.bindings);changed['roots']['wine']=str(other)
        build.write_json(self.binding_path,changed)
        self.request['bindings_ref']=build.fact(self.binding_path);self.write_request()
        with self.assertRaisesRegex(Error,'assembly_build_binding'):recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_candidate_and_operation_need_locked_exact_identities(self):
        operation=build.load(self.operation/'operation.json');operation['lock']['released']=False
        build.write_json(self.operation/'operation.json',operation)
        self.request['operation_ref']=build.fact(self.operation/'operation.json');self.write_request()
        with self.assertRaisesRegex(Error,'recovery_candidate_lock'):recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_candidate_artifact_role_must_match_selected_build(self):
        self.lock['artifact_identities_before_signing']['wine_native']['sha256']='0'*64
        build.write_json(self.lock_path,self.lock);self.request['lock_ref']=build.fact(self.lock_path);self.write_request()
        with self.assertRaisesRegex(Error,'recovery_candidate_artifact'):recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_equivalent_build_rewrite_is_not_the_recorded_candidate_producer(self):
        self.receipt['unreviewed_metadata']='new receipt identity'
        build.write_json(self.products/'build.json',self.receipt)
        self.request['build_ref']=build.fact(self.products/'build.json');self.write_request()
        with self.assertRaisesRegex(Error,'recovery_candidate_build'):recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_fresh_output_and_overlap_are_required(self):
        for target,code in ((self.headers,'recovery_fresh_output'),(self.headers/'nested','recovery_output_overlap')):
            self.request['output']=str(target);self.write_request()
            with self.assertRaisesRegex(Error,code):recovery.restore(self.request_path)

    def test_budget_and_six_gib_reserve_refuse_before_copy(self):
        self.request['max_output_bytes']=32;self.write_request()
        with self.assertRaisesRegex(Error,'recovery_budget_exceeded'):recovery.restore(self.request_path)
        self.request['max_output_bytes']=recovery.MAX_BYTES;self.write_request()
        with patch.object(recovery.shutil,'disk_usage',return_value=SimpleNamespace(free=recovery.RESERVE_BYTES)),\
             self.assertRaisesRegex(Error,'recovery_storage_unavailable'):recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_boolean_schema_budget_and_extra_fields_refuse(self):
        original=deepcopy(self.request)
        for key,value,code in [('schema_version',True,'recovery_request_scope'),
                              ('max_output_bytes',True,'recovery_budget_limit'),
                              ('unreviewed',True,'recovery_request_shape')]:
            self.request={**original,key:value};self.write_request()
            with self.assertRaisesRegex(Error,code):recovery.restore(self.request_path)

    def test_boolean_lock_schema_refuses_before_output(self):
        self.lock['schema_version'] = True
        build.write_json(self.lock_path, self.lock)
        self.request['lock_ref'] = build.fact(self.lock_path)
        self.write_request()
        with self.assertRaisesRegex(Error, 'recovery_lock_scope'):
            recovery.restore(self.request_path)
        self.assertFalse(self.output.exists())

    def test_source_change_during_copy_retains_failure(self):
        real_write=recovery._write
        def mutate(path,raw):
            real_write(path,raw)
            if path.name=='wire.h':self.header.write_bytes(b'changed during copy')
        with patch.object(recovery,'_write',side_effect=mutate),\
             self.assertRaisesRegex(Error,'build_input_mismatch'):recovery.restore(self.request_path)
        self.assertFalse((self.output/'recovery.json').exists())
        self.assertEqual(build.load(self.output/'recovery-failed.json')['status'],'failed')

    def test_rebound_check_missing_then_wrong_then_restored_bytes(self):
        result=recovery.restore(self.request_path)
        rebound=result['rebound_bindings_ref'];path=self.output/'inputs/common_headers/wire.h';raw=path.read_bytes()
        path.unlink()
        with self.assertRaises(FileNotFoundError):recovery.validate_rebound(self.request['recipe_ref'],rebound,'common_headers',self.outputs/'unused')
        path.write_bytes(b'wrong');path.chmod(0o644)
        with self.assertRaisesRegex(Error,'build_input_mismatch'):recovery.validate_rebound(self.request['recipe_ref'],rebound,'common_headers',self.outputs/'unused')
        path.write_bytes(raw)
        checked=recovery.validate_rebound(self.request['recipe_ref'],rebound,'common_headers',self.outputs/'unused')
        self.assertEqual(checked,[build.fact(path)])
        self.assertFalse((self.outputs/'unused').exists())

    def test_command_line_check_requires_original_recipe_identity(self):
        result=recovery.restore(self.request_path)
        argv=['check-binding','--recipe',str(self.recipe_path),'--recipe-sha256','0'*64,
              '--recipe-size',str(self.request['recipe_ref']['size_bytes']),
              '--bindings',result['rebound_bindings_ref']['path'],'--root','common_headers',
              '--unused-output',str(self.outputs/'unused')]
        with patch('sys.stdout',new_callable=io.StringIO) as output:
            self.assertEqual(recovery.main(argv),1)
        self.assertIn('assembly_reference_changed',output.getvalue())


if __name__ == '__main__':
    unittest.main()
