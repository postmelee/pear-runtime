# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Companion identity coverage and independent resource release without host probes."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import game_release as subject,game_operation


class GameReleaseTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.output=self.root/'game';self.output.mkdir();self.oproot=self.root/'game.game-operation';self.oproot.mkdir()
        self.play=self.output/'play';self.play.mkdir();(self.play/'hud').mkdir()
        self.pid=90000;self.opid='synthetic-operation'
        def child(role,index):
            return SimpleNamespace(role=role,identity=dict(pid=self.pid+index,ppid=self.pid,start_sec=100+index,start_usec=0),
                exit_code=0,reaped=True,allowed_paths={'/synthetic/declared-tool'},fork_seen=False,setup_error=None,emergency_cleanup=None)
        self.adapter=SimpleNamespace(operation=self.opid,helpers=SimpleNamespace(output=self.play,
            children={'owner-witness':child('owner-witness',4),'capture-0':child('capture-0',5)}),
            hud_helpers=SimpleNamespace(output=self.play/'hud',children={'hud-log':child('hud-log',6)}))
        witness=self.adapter.helpers.children['owner-witness'].identity
        self.write(self.play/'witness-config.json',dict(run=str(self.output),operation_id=self.opid,owner_identity=dict(pid=self.pid)))
        self.write(self.play/'witness-ready.json',dict(config=build.fact(self.play/'witness-config.json'),watcher_identity=witness))
        self.write(self.play/'witness-final.json',dict(config=build.fact(self.play/'witness-config.json'),watcher_identity=witness))
        self.write(self.play/'hud-binding.json',dict(collector_identity=self.adapter.hud_helpers.children['hud-log'].identity))
        for name in ('companion-result.json','hud-result.json'):self.write(self.play/name,dict(cleanup={'complete':True},logs=[],errors=[]))
        companion=subject.capture_companions(self.adapter,self.output)
        self.runtime=self.write(self.root/'runtime.json',{'synthetic':'runtime'});self.assembly=self.write(self.root/'assembly.json',{})
        self.descriptor=self.write(self.root/'descriptor.json',dict(runtime_ref=self.runtime,operation_ref=self.assembly))
        self.request=self.write(self.root/'game-request.json',dict(schema_version=1,scope='development_game_observation',
            descriptor_ref=self.descriptor,output_name='game'))
        self.plan=dict(schema_version=1,scope='development_game_plan',output=str(self.output),operation_output=str(self.oproot),
            request_ref=self.request,descriptor_ref=self.descriptor,runtime_ref=self.runtime,assembly_operation_ref=self.assembly)
        processes={role:{name:getattr(child(role,i),name) if name!='allowed_paths' else ['/synthetic/tool'] for name in subject.CHILD_FIELDS}
                   for i,role in enumerate(('loader','server','sentinel'),1)}
        self.case=dict(schema_version=1,scope='development_direct_game_v1',game_context_ref=self.descriptor,
            runtime_ref=self.runtime,execution_operation=dict(path=str(self.oproot/'operation.json'),operation_id=self.opid),
            processes=processes,registrations=[{'identity':processes['loader']['identity']}],companion_processes_ref=companion,
            game_qualified=False,error=None,stream_error=None,cleanup={'complete':True},sentinel_cleanup={'complete':True},
            sentinel_survived=True,cleanup_errors=[],original_files_unchanged=True,producer_dependencies_unchanged=True)
        self.op=dict(schema_version=1,scope='development_game_operation',status='passed',operation_id=self.opid,
            worker={'pid':self.pid,'process_group':self.pid},lock={'path':str(subject.release.GLOBAL_LOCK),'released':True},
            plan=self.plan,request_ref=self.request,companion_processes_ref=companion,runtime_execution_attempted=True,
            runtime_execution_performed=True)
        self.freeze()

    def write(self,path,value):build.write_json(path,value);return build.fact(path)
    def freeze(self):
        self.op['case_ref']=self.write(self.output/'case.json',self.case)
        opref=self.write(self.oproot/'operation.json',self.op)
        self.ref=self.write(self.root/'release-request.json',dict(schema_version=1,scope='development_game_release',operations=[opref]))

    def test_capture_is_idempotent_and_contains_every_original_child_identity(self):
        ref=subject.capture_companions(self.adapter,self.output);value=build.load(Path(ref['path']))
        self.assertEqual(ref,self.case['companion_processes_ref'])
        self.assertEqual(set(value['sessions']['helpers']['processes']),{'owner-witness','capture-0'})
        self.assertFalse(value['observation_performed'])
        self.adapter.helpers.children['capture-0'].identity['start_sec']+=1
        with self.assertRaisesRegex(Error,'game_companion_evidence_changed'):subject.capture_companions(self.adapter,self.output)

    def test_independent_inputs_cover_main_witness_hud_capture_groups_and_handles(self):
        plan=subject.inputs(self.ref)
        self.assertEqual(len(plan['identities']),6);self.assertEqual(len(plan['groups']),7)
        self.assertEqual(plan['workers'],[self.pid]);self.assertEqual(plan['roots'],[self.output,self.oproot])

    def test_missing_or_resealed_unknown_companion_identity_refuses(self):
        path=Path(self.case['companion_processes_ref']['path']);original=build.load(path)
        for change in ('missing','unknown','foreign-parent','unsupported-role'):
            value=copy.deepcopy(original)
            if change=='missing':self.op.pop('companion_processes_ref',None)
            elif change=='unknown':value['sessions']['helpers']['processes']['capture-0']['identity']=None
            elif change=='foreign-parent':value['sessions']['hud']['processes']['hud-log']['identity']['ppid']=self.pid+100
            else:value['sessions']['helpers']['processes']['unlisted-helper']=value['sessions']['helpers']['processes'].pop('capture-0')
            if change!='missing':
                ref=self.write(path,value);self.case['companion_processes_ref']=ref;self.op['companion_processes_ref']=ref
            self.freeze()
            with self.subTest(change=change),self.assertRaises((Error,TypeError)):subject.inputs(self.ref)

    def test_failed_game_can_release_but_surviving_capture_cannot(self):
        self.op['status']='failed';self.freeze();plan=subject.inputs(self.ref)
        empty=dict(processes={},groups={p:[] for p in plan['groups']},provider_ref={})
        probe=Mock();probe.observe.return_value=empty
        with patch.object(subject.release,'DarwinProbe',return_value=probe),\
             patch.object(subject.release,'handles',return_value={'handles':[],'tool_ref':{}}),\
             patch.object(subject.release,'lock_probe',return_value={'available':True,'immediately_released':True}):
            result=subject.inspect(self.ref)
        self.assertEqual(result['status'],'passed');self.assertEqual(result['operations'][0]['original_status'],'failed')
        capture=self.adapter.helpers.children['capture-0'].identity
        seen=copy.deepcopy(empty);seen['processes'][capture['pid']]=capture;probe.observe.side_effect=[empty,seen]
        with patch.object(subject.release,'DarwinProbe',return_value=probe),\
             patch.object(subject.release,'handles',return_value={'handles':[],'tool_ref':{}}),\
             patch.object(subject.release,'lock_probe',return_value={'available':True,'immediately_released':True}):
            result=subject.inspect(self.ref)
        self.assertEqual(result['status'],'failed');self.assertFalse(result['resource_release_passed'])

    def test_unavailable_case_evidence_is_unknown_not_implicitly_released(self):
        self.op.pop('case_ref');self.write(self.oproot/'operation.json',self.op)
        self.ref=self.write(self.root/'release-request.json',dict(schema_version=1,scope='development_game_release',
            operations=[build.fact(self.oproot/'operation.json')]))
        with patch.object(subject.release,'DarwinProbe',side_effect=AssertionError('no evidence no probe')):
            result=subject.inspect(self.ref)
        self.assertEqual(result['status'],'unknown');self.assertFalse(result['resource_release_passed'])

    def test_no_execution_attempt_can_release_only_recorded_worker_and_output_handles(self):
        self.op.pop('case_ref');self.op['runtime_execution_attempted']=False;self.op['runtime_execution_performed']=False
        self.write(self.oproot/'operation.json',self.op)
        self.ref=self.write(self.root/'release-request.json',dict(schema_version=1,scope='development_game_release',
            operations=[build.fact(self.oproot/'operation.json')]))
        plan=subject.inputs(self.ref);self.assertEqual(plan['identities'],[]);self.assertEqual(plan['workers'],[self.pid])

    def result(self):
        return dict(game_qualified=False,game_context_ref=self.descriptor,runtime_ref=self.runtime,assembly_operation_ref=self.assembly,
            case_ref=self.op['case_ref'],execution_operation=self.case['execution_operation'],cleanup_passed=True,
            authority_passed=True,host_bootstrap_arm64_no_rosetta=True,runtime_unchanged=True)

    def owner(self):
        return SimpleNamespace(output=self.output,operation_output=self.oproot,operation_id=self.opid,owner=(self.pid,),
            context=SimpleNamespace(ref=self.descriptor,value={'runtime_ref':self.runtime,'operation_ref':self.assembly}),assert_current=Mock())

    def test_nonzero_guest_exit_can_be_observed_without_claiming_game_qualification(self):
        self.case['processes']['loader']['exit_code']=42;self.freeze()
        game_operation.result_admission(self.result(),self.owner())

    def test_false_original_oracle_or_cleanup_never_passes_outer_operation(self):
        for key in ('cleanup_passed','authority_passed','host_bootstrap_arm64_no_rosetta','runtime_unchanged'):
            result=self.result();result[key]=False
            with self.subTest(key=key),self.assertRaisesRegex(Error,'game_result_harness'):
                game_operation.result_admission(result,self.owner())
        for key,value in (('sentinel_survived',False),('stream_error','truncated'),('cleanup_errors',['failure']),
                          ('error',{'code':'owned-run'}),('original_files_unchanged',False)):
            original=copy.deepcopy(self.case);self.case[key]=value;self.freeze()
            with self.subTest(key=key),self.assertRaisesRegex(Error,'game_result_cleanup'):
                game_operation.result_admission(self.result(),self.owner())
            self.case=original;self.freeze()

    def test_companion_incomplete_cleanup_or_changed_receipt_is_not_success(self):
        path=self.play/'companion-result.json';value=build.load(path);value['cleanup']['complete']=False
        self.write(path,value)
        # A stale exact capture is rejected before considering its old cleanup flag.
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):
            game_operation.result_admission(self.result(),self.owner())


if __name__=='__main__':unittest.main()
