# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable input, projection and owned-process refusal tests; no Apple signing."""
from contextlib import nullcontext
from dataclasses import replace
import copy
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch, Mock

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.assembly import core, _byte_readers
from pear_runtime.assembly.helpers import SourcePack, signing_helpers, BUNDLE, MAIN
from test_original_checks import signed_macho

PACK_ROOT = Path(os.environ['PEAR_ASSEMBLY_SOURCE_PACK'])


def pe(machine):
    raw = bytearray(192); raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 60, 64); raw[64:68] = b'PE\0\0'
    struct.pack_into('<H', raw, 68, machine)
    return bytes(raw)


class InputTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.parent, self.products, self.outputs, self.private = (self.root/p for p in ('parent','products','outputs','private'))
        for root in (self.parent,self.products,self.outputs,self.private): root.mkdir()
        self.helpers,self.reader = signing_helpers(SourcePack(PACK_ROOT))
        for relative,raw in [(MAIN,signed_macho()),(core.ROLE_PATHS['wine_native'],signed_macho()),
            (core.ROLE_PATHS['fex_pe'],pe(0x8664)),(core.ROLE_PATHS['wine_pe'],pe(0xaa64)),
            (BUNDLE+'/Contents/embedded.provisionprofile',b'synthetic profile bytes; never Apple authority'),
            (BUNDLE+'/Contents/data.txt',b'untouched'),(BUNDLE+'/Contents/_CodeSignature/CodeResources',b'old')]:
            path=self.parent/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
        self.old={'passed':True,'diagnostic_only':True,'game_qualified':False,
            'bundle_inventory':self.reader.inventory(self.parent/BUNDLE),
            'native_images':[{'path':MAIN},{'path':core.ROLE_PATHS['wine_native']}],
            'dependency_closure':[{'path':path,'images':_byte_readers.inspect_closure(self.parent/path,self.parent/BUNDLE)}
                                  for path in (MAIN,core.ROLE_PATHS['wine_native'])]}
        build.write_json(self.parent/'runtime.json',self.old)
        (self.private/'profile').write_bytes(b'synthetic profile bytes; never Apple authority')
        for path,raw in [('native.so',signed_macho()),('fex.dll',pe(0x8664)),('stdout',b'fixture'),('stderr',b'')]:
            (self.products/path).write_bytes(raw)
        outputs={name:build.fact(self.products/name) for name in ('native.so','fex.dll')}
        self.receipt={'schema_version':1,'scope':'development_component_build','status':'passed',
            'runtime_eligible':False,'game_qualified':False,'recipe_sha256':'a'*64,
            'operation_id':str(uuid.uuid4()),
            'roots':{'source':{'kind':'git','commit':'b'*40}},
            'commands':[{'id':'test','exit_code':0,'error':None,'logs':{s:build.fact(self.products/s) for s in ('stdout','stderr')}}],
            'outputs':outputs,'artifacts':{'wine_native':outputs['native.so'],'fex_pe':outputs['fex.dll']}}
        build.write_json(self.products/'operation.json',{'scope':'task56_component_build',
            'operation_id':self.receipt['operation_id'],'released':True})
        self.write_receipt()
        self.inputs=core.AssemblyInputs(build.fact(self.parent/'runtime.json'),(self.request,),
            ('wine_native','fex_pe'),build.fact(self.private/'profile'),PACK_ROOT,self.outputs,'candidate')

    def write_receipt(self):
        build.write_json(self.products/'build.json',self.receipt)
        self.request={'ref':build.fact(self.products/'build.json'),'recipe_sha256':'a'*64,'source_commits':{'source':'b'*40}}

    def changed_request(self):
        self.write_receipt()
        return replace(self.inputs,builds=(self.request,))

    def test_readonly_plan_checks_bundle_and_roles_without_output(self):
        plan=core.signing_plan(self.inputs)
        self.assertFalse((self.outputs/'candidate').exists())
        self.assertFalse(plan['execution_performed']);self.assertFalse(plan['permission_admitted'])
        self.assertGreater(plan['storage']['additional_peak_bytes'],plan['storage']['parent_bundle_logical_bytes'])
        self.assertEqual(set(plan['replacements']),{'wine_native','fex_pe'})

    def test_failed_receipt_cannot_be_admitted(self):
        self.receipt['status']='failed'
        with self.assertRaisesRegex(Error,'assembly_build_scope'):core.inspect_inputs(self.changed_request())

    def test_failed_command_cannot_be_masked_by_passed_status(self):
        self.receipt['commands'][0]['exit_code']=1
        with self.assertRaisesRegex(Error,'assembly_build_commands'):core.inspect_inputs(self.changed_request())

    def test_stale_recipe_or_source_pin_fails(self):
        for field,value,code in [('recipe_sha256','c'*64,'assembly_build_recipe'),
                                 ('source_commits',{'source':'c'*40},'assembly_build_sources')]:
            request={**self.request,field:value}
            with self.subTest(field=field),self.assertRaisesRegex(Error,code):
                core.inspect_inputs(replace(self.inputs,builds=(request,)))

    def test_artifact_must_be_recorded_output(self):
        self.receipt['outputs'].pop('native.so')
        with self.assertRaisesRegex(Error,'assembly_artifact_output'):core.inspect_inputs(self.changed_request())

    def test_artifact_changed_after_build_is_rejected(self):
        (self.products/'native.so').write_bytes(b'changed')
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):core.inspect_inputs(self.inputs)

    def test_log_changed_after_build_is_rejected(self):
        (self.products/'stdout').write_bytes(b'changed')
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):core.inspect_inputs(self.inputs)

    def test_role_has_single_build_owner(self):
        with self.assertRaisesRegex(Error,'assembly_artifact_owner'):
            core.inspect_inputs(replace(self.inputs,builds=(self.request,self.request)))

    def test_unknown_or_duplicate_role_is_rejected(self):
        for roles in [('wine_native','other'),('wine_native','wine_native')]:
            with self.subTest(roles=roles),self.assertRaisesRegex(Error,'assembly_replacement_roles'):
                core.inspect_inputs(replace(self.inputs,roles=roles))

    def test_profile_alias_and_changed_profile_fail(self):
        alias=self.private/'alias';alias.symlink_to('profile')
        with self.assertRaisesRegex(Error,'assembly_reference_alias'):
            core.inspect_inputs(replace(self.inputs,profile_ref={**self.inputs.profile_ref,'path':str(alias)}))
        (self.private/'profile').write_bytes(b'changed')
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):core.inspect_inputs(self.inputs)

    def test_output_overlap_and_existing_output_fail(self):
        with self.assertRaisesRegex(Error,'assembly_output_overlaps_input'):
            core.inspect_inputs(replace(self.inputs,output_root=self.parent))
        (self.outputs/'candidate').mkdir()
        with self.assertRaisesRegex(Error,'assembly_output_exists'):core.inspect_inputs(self.inputs)

    def test_changed_parent_inventory_is_rejected(self):
        (self.parent/BUNDLE/'Contents/data.txt').write_bytes(b'changed')
        with self.assertRaisesRegex(Error,'assembly_parent_inventory'):core.inspect_inputs(self.inputs)

    def test_native_closure_cannot_omit_image_or_escape_bundle(self):
        for change in ('omit','escape'):
            value=copy.deepcopy(self.old)
            if change=='omit':value['dependency_closure'].pop()
            else:value['native_images'][0]['path']='../outside'
            with self.subTest(change=change),self.assertRaises(Error):core.verify_closure(self.parent,value,self.reader)

    def test_wrong_outer_pe_machine_is_rejected(self):
        (self.products/'fex.dll').write_bytes(pe(0xaa64))
        ref=build.fact(self.products/'fex.dll');self.receipt['outputs']['fex.dll']=ref;self.receipt['artifacts']['fex_pe']=ref
        with self.assertRaisesRegex(Error,'assembly_replacement_pe_machine'):core.inspect_inputs(self.changed_request())

    def test_no_copy_or_signing_without_owned_worker(self):
        with patch('os.getpgrp',return_value=0),self.assertRaisesRegex(Error,'signing_worker_group_required'):
            core.assemble(self.inputs,interval=lambda *args:None,expected_signing_recipe=[{'id':'fixture','argv':[]}])
        self.assertFalse((self.outputs/'candidate').exists())

    def projection_root(self):
        root=self.outputs/'projection';shutil.copytree(self.parent,root)
        return root

    def test_identical_declared_replacements_still_verify_origin(self):
        root=self.projection_root()
        result=core.projection(self.parent,root,self.old,self.old,self.reader,self.receipt['artifacts'])
        self.assertTrue(result['replacement_identity_verified']);self.assertEqual(result['changed_files'],[])
        self.assertEqual(len(result['declared_replacements']),2)

    def test_projection_refuses_undeclared_data_change(self):
        root=self.projection_root();(root/BUNDLE/'Contents/data.txt').write_bytes(b'unapproved')
        with self.assertRaisesRegex(Error,'early_wait_other_change'):
            core.projection(self.parent,root,self.old,self.old,self.reader,self.receipt['artifacts'])

    def test_projection_allows_signature_only_but_refuses_native_code_change(self):
        root=self.projection_root();(root/MAIN).write_bytes(signed_macho(b'a different signature'))
        core.projection(self.parent,root,self.old,self.old,self.reader,self.receipt['artifacts'])
        raw=bytearray((root/MAIN).read_bytes());raw[520]^=1;(root/MAIN).write_bytes(raw)
        with self.assertRaisesRegex(Error,'signed_code_origin_mismatch'):
            core.projection(self.parent,root,self.old,self.old,self.reader,self.receipt['artifacts'])

    def test_regular_file_and_actual_size_checked_before_hash(self):
        path=self.private/'fifo';os.mkfifo(path)
        with self.assertRaisesRegex(Error,'assembly_reference_regular_size'):
            core.checked_ref({'path':str(path),'sha256':'a'*64,'size_bytes':0})
        with self.assertRaisesRegex(Error,'assembly_reference_regular_size'):
            core.checked_ref({**self.inputs.profile_ref,'size_bytes':1},limit=1)

    def test_code_change_during_input_admission_is_rejected(self):
        before=core.builder_sources();after=copy.deepcopy(before)
        after['pear_runtime/build.py']['sha256']='0'*64
        with patch.object(core,'builder_sources',side_effect=[before,after]),self.assertRaisesRegex(Error,'assembly_builder_changed'):
            core.inspect_inputs(self.inputs)
        self.assertFalse((self.outputs/'candidate').exists())

    def test_static_sign_recipe_mismatch_records_failure_before_codesign(self):
        h=self.helpers
        h.capture_authorization=Mock(return_value=({'claims':{}},{'identity':'synthetic'},(self.private/'profile').read_bytes()))
        h.native=Mock(side_effect=AssertionError('codesign must not run'))
        def fake_copy(argv,**kwargs):
            shutil.copytree(argv[-2],argv[-1])
            return {'exit_code':0,'timed_out':False,'output_limit':False,'elapsed_ms':0}
        h.run_bounded=fake_copy
        with patch.object(core,'signing_helpers',return_value=(h,self.reader)), patch('os.getpgrp',return_value=os.getpid()), \
             patch.object(core.shutil,'disk_usage',return_value=type('Disk',(),{'free':100*1024**3})()), \
             self.assertRaisesRegex(Error,'attach_sign_exact_recipe'):
            core.assemble(self.inputs,interval=lambda *args:nullcontext(),operation_binding=self.live_operation(),expected_signing_recipe=[{'id':'wrong','argv':['/usr/bin/arch','-arm64','wrong']}])
        h.native.assert_not_called()
        value=build.load(self.outputs/'candidate/runtime.json')
        self.assertFalse(value['passed']);self.assertFalse(value['runtime_qualified'])
        self.assertFalse(value['execution_authorized_by_this_record'])
        self.assertEqual(value['assembly_error']['code'],'attach_sign_exact_recipe')
        self.assertIn('sign_and_verify',[p['name'] for p in value['assembly_phases']])
        self.assertTrue(all(p['seconds']>=0 and 'wall_utc' in p['started'] for p in value['assembly_phases']))
        self.assertEqual(self.reader.inventory(self.parent/BUNDLE),self.old['bundle_inventory'])

    def live_operation(self):
        folder=self.outputs/'candidate.assembly-operation';folder.mkdir()
        binding={'path':str(folder/'operation.json'),'operation_id':str(uuid.uuid4())}
        build.write_json(folder/'operation.json',dict(schema_version=1,scope='development_candidate_assembly_operation',
            operation_id=binding['operation_id'],status='running',runtime_ref=None,
            worker={'pid':os.getpid(),'process_group':os.getpgrp()},lock={'released':False},
            plan={'output':str(self.outputs/'candidate'),'operation_output':str(folder)}))
        return binding

    def current_record(self):
        value=copy.deepcopy(self.old)
        opdir=self.outputs/'previous.assembly-operation';opdir.mkdir()
        binding={'path':str(opdir/'operation.json'),'operation_id':str(uuid.uuid4())}
        value.update(runtime_qualified=False,execution_authorized_by_this_record=False,builder_sources=core.builder_sources(),
            assembly_operation=binding,
            development_assembly={'profile_ref':self.inputs.profile_ref,'helper_sources':SourcePack(PACK_ROOT).pins})
        build.write_json(self.parent/'authorization.json',{'capture':{'sha256':self.inputs.profile_ref['sha256']},'claims':{}})
        value['authorization_sha256']=build.fact(self.parent/'authorization.json')['sha256']
        build.write_json(self.parent/'runtime.json',value)
        ref=build.fact(self.parent/'runtime.json')
        build.write_json(opdir/'operation.json',dict(schema_version=1,scope='development_candidate_assembly_operation',
            operation_id=binding['operation_id'],status='passed',runtime_ref=ref,lock={'released':True},
            plan={'output':str(self.parent),'operation_output':str(opdir)}))
        return ref

    def test_current_authority_rejects_historical_record(self):
        with self.assertRaisesRegex(Error,'assembly_current_scope'):
            core.verify_current_authority(self.inputs.parent_ref,self.inputs.profile_ref,PACK_ROOT,self.outputs/'authority')
        self.assertFalse((self.outputs/'authority').exists())

    def test_current_authority_failure_retains_original_error_and_false_control(self):
        ref=self.current_record();h=self.helpers
        h.capture_authorization=Mock(side_effect=OSError(13,'synthetic current authorization refusal'))
        with patch.object(core,'signing_helpers',return_value=(h,self.reader)),patch('os.getpgrp',return_value=os.getpid()),self.assertRaises(OSError) as error:
            core.verify_current_authority(ref,self.inputs.profile_ref,PACK_ROOT,self.outputs/'authority',
                                              operation_ref=build.fact(build.load(ref['path'])['assembly_operation']['path']))
        value=build.load(self.outputs/'authority/control.json')
        self.assertFalse(value['passed']);self.assertEqual(value['error']['errno'],13)
        self.assertEqual(value['error']['code'],str(error.exception))
        self.assertEqual(value['phases'][-1]['name'],'current_authorization')
        self.assertEqual(build.fact(self.parent/'runtime.json'),ref)

    def test_component_operation_requires_matching_completed_owner(self):
        path=self.products/'operation.json';original=path.read_bytes()
        for change in ('missing','unreleased','scope','id'):
            path.write_bytes(original)
            if change=='missing':path.unlink()
            else:
                value=build.load(path)
                if change=='unreleased':value['released']=False
                if change=='scope':value['scope']='unrelated_operation'
                if change=='id':value['operation_id']=str(uuid.uuid4())
                build.write_json(path,value)
            with self.subTest(change=change),self.assertRaises((Error,FileNotFoundError)):
                core.inspect_inputs(self.inputs)
            self.assertEqual(list(self.outputs.iterdir()),[])
        path.write_bytes(original)

    def test_component_operation_ref_is_in_pre_post_inputs(self):
        plan=core.inspect_inputs(self.inputs)
        ref=build.fact(self.products/'operation.json')
        self.assertIn(ref,plan['component_operations']);self.assertIn(ref,plan['input_refs'])
        value=build.load(ref['path']);value['released']=False;build.write_json(ref['path'],value)
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):core.checked_ref(ref)

    def test_final_operation_status_identity_runtime_and_output_join(self):
        ref=self.current_record();value=build.load(ref['path'])
        path=Path(value['assembly_operation']['path']);original=path.read_bytes()
        self.assertEqual(core.completed_operation(ref,value,build.fact(path)),build.fact(path))
        for change in ('failed','running','unreleased','id','runtime','output','scope','missing'):
            path.write_bytes(original);record=build.load(path)
            if change in ('failed','running'):record['status']=change
            if change=='unreleased':record['lock']['released']=False
            if change=='id':record['operation_id']=str(uuid.uuid4())
            if change=='runtime':record['runtime_ref']['sha256']='c'*64
            if change=='output':record['plan']['output']=str(self.outputs/'other')
            if change=='scope':record['scope']='unrelated_operation'
            build.write_json(path,record)
            if change=='missing':path.unlink()
            with self.subTest(change=change),self.assertRaises((Error,FileNotFoundError)):
                core.verify_current_authority(ref,self.inputs.profile_ref,PACK_ROOT,self.outputs/'authority',
                                              operation_ref=build.fact(build.load(ref['path'])['assembly_operation']['path']))
            self.assertFalse((self.outputs/'authority').exists())
        path.write_bytes(original)

    def test_final_operation_cannot_supply_its_own_expected_identity(self):
        ref=self.current_record();value=build.load(ref['path'])
        operation_ref=build.fact(value['assembly_operation']['path'])
        record=build.load(operation_ref['path']);record['extra']='changed after review'
        build.write_json(operation_ref['path'],record)
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):
            core.verify_current_authority(ref,self.inputs.profile_ref,PACK_ROOT,self.outputs/'authority',operation_ref=operation_ref)
        with self.assertRaisesRegex(Error,'assembly_operation_reference_required'):
            core.verify_current_authority(ref,self.inputs.profile_ref,PACK_ROOT,self.outputs/'authority')
        self.assertFalse((self.outputs/'authority').exists())

    def test_operation_drift_during_authority_check_is_rejected(self):
        from types import SimpleNamespace
        ref=self.current_record();value=build.load(ref['path'])
        for row in value['native_images']:row['signature']={'synthetic':True}
        build.write_json(ref['path'],value);ref=build.fact(ref['path'])
        op=Path(value['assembly_operation']['path']);record=build.load(op);record['runtime_ref']=ref;build.write_json(op,record)
        def current(*args):
            mutated=build.load(op);mutated['unexpected_change']=True;build.write_json(op,mutated)
            return {'capture':{'sha256':self.inputs.profile_ref['sha256']},'claims':{}},{},b'fixture'
        h=SimpleNamespace(capture_authorization=current,profile_recipe=lambda *args:[],
            signature_recipe=lambda *args:[],native=Mock(side_effect=AssertionError('no native execution')),
            verify_commands=lambda *args:{},signature_from_logs=lambda *args:{'synthetic':True},
            signer_leaf=lambda *args:None,BUNDLE_ID=self.helpers.BUNDLE_ID)
        with patch.object(core,'signing_helpers',return_value=(h,self.reader)),patch('os.getpgrp',return_value=os.getpid()),             self.assertRaisesRegex(Error,'assembly_reference_changed'):
            core.verify_current_authority(ref,self.inputs.profile_ref,PACK_ROOT,self.outputs/'authority',
                                              operation_ref=build.fact(build.load(ref['path'])['assembly_operation']['path']))
        self.assertFalse(build.load(self.outputs/'authority/control.json')['passed'])



class SourceTests(unittest.TestCase):
    def test_source_pack_pins_complete_captured_bytes(self):
        pack=SourcePack(PACK_ROOT);h,r=signing_helpers(pack)
        self.assertEqual(len(pack.capture()),6)
        self.assertEqual(h.legacy.__defaults__,(pack.root,))
        self.assertNotIn('prepare',vars(h));self.assertNotIn('main',vars(h))

    def test_mutation_symlink_or_missing_source_is_rejected(self):
        for kind in ('mutation','symlink','missing'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary).resolve();pack=SourcePack(PACK_ROOT)
                for path,raw in pack.capture().items():
                    p=root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
                target=root/'tools/wine/signing.py'
                if kind=='mutation':target.write_bytes(target.read_bytes()+b'\n# drift\n')
                else:
                    target.unlink()
                    if kind=='symlink':target.symlink_to(PACK_ROOT/'tools/wine/signing.py')
                with self.assertRaises((Error,FileNotFoundError)):signing_helpers(SourcePack(root))

    def test_source_pack_alias_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();alias=root/'alias';alias.symlink_to(PACK_ROOT)
            with self.assertRaisesRegex(Error,'assembly_root_alias'):SourcePack(alias)


class TransportTests(unittest.TestCase):
    def setUp(self):self.h,self.r=signing_helpers(SourcePack(PACK_ROOT))

    def test_original_guard_refuses_nonowned_group(self):
        with patch('os.getpgrp',return_value=0),self.assertRaisesRegex(Error,'signing_worker_group_required'):
            self.h.run_bounded([sys.executable,'-c','pass'])

    def test_nonzero_result_and_streams_are_retained(self):
        with patch('os.getpgrp',return_value=os.getpid()):
            value=self.h.run_bounded([sys.executable,'-c','import sys; print("evidence"); sys.exit(7)'])
        self.assertEqual(value['exit_code'],7);self.assertEqual(value['stdout'],b'evidence\n')

    def test_output_overflow_retains_partial_logs(self):
        with tempfile.TemporaryDirectory() as temporary,patch('os.getpgrp',return_value=os.getpid()):
            root=Path(temporary)
            with self.assertRaisesRegex(Error,'command_bound') as raised:
                self.h.run_bounded([sys.executable,'-c','print("x"*100000)'],limit=32,log_directory=root)
            self.assertTrue(raised.exception.bound_outcome['output_limit'])
            self.assertGreater((root/'stdout').stat().st_size,32)

    def test_timeout_kills_descendant_after_leader_exits(self):
        with tempfile.TemporaryDirectory() as temporary,patch('os.getpgrp',return_value=os.getpid()):
            root=Path(temporary)
            code='import subprocess,sys; p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]); print(p.pid,flush=True)'
            with self.assertRaisesRegex(Error,'command_bound') as raised:
                self.h.run_bounded([sys.executable,'-c',code],timeout=.25,log_directory=root)
            self.assertTrue(raised.exception.bound_outcome['timed_out'])
            pid=int((root/'stdout').read_text().strip())
            state=subprocess.run(['ps','-o','stat=','-p',str(pid)],capture_output=True,text=True).stdout.strip()
            self.assertTrue(not state or state.startswith('Z'),state)

    def test_log_evidence_failure_does_not_mask_command_timeout(self):
        with tempfile.TemporaryDirectory() as temporary,patch('os.getpgrp',return_value=os.getpid()):
            missing=Path(temporary)/'missing'
            with self.assertRaisesRegex(Error,'command_bound') as raised:
                self.h.run_bounded([sys.executable,'-c','import time;time.sleep(60)'],timeout=.05,log_directory=missing)
            self.assertTrue(raised.exception.bound_outcome['timed_out'])
            detail=core.failure_details(raised.exception)
            self.assertEqual(detail['evidence_errors'][0]['code'],'command_log_directory')
