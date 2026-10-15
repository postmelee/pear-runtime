# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Current lease, request and final evidence controls with native boundaries mocked."""
from contextlib import contextmanager,ExitStack
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import direct,game_operation as subject


class OperationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.root=Path(temporary.name).resolve()
        runtime=self.root/'runtime.json';build.write_json(runtime,{'synthetic':'candidate'})
        self.descriptor=self.root/'descriptor.json';build.write_json(self.descriptor,{'manual_policy':'manual_feedback_v1',
            'runtime_ref':build.fact(runtime),'operation_ref':{},'profile_ref':{}})
        self.context=SimpleNamespace(ref=build.fact(self.descriptor),value=build.load(self.descriptor),provider_root=self.root/'provider')
        self.path=self.root/'request.json';self.value=dict(schema_version=1,scope='development_game_observation',
            descriptor_ref=self.context.ref,output_name='game',manual_policy='manual_feedback_v1',
            limits=dict(whole_timeout_seconds=5400,worker_log_bytes=1024*1024))
        build.write_json(self.path,self.value);self.ref=build.fact(self.path)
        self.output=self.root/'game';self.opout=self.root/'game.game-operation'
        self.plan=dict(output=str(self.output),operation_output=str(self.opout))
        self.record=dict(operation_id='synthetic-operation',status='running',lock={'released':False},plan=self.plan,
                         not_after_monotonic_ns=10**18,intervals=[])
        self.captured=Mock();self.guard=Mock()
        self.stack=self.enterContext(ExitStack())
        self.stack.enter_context(patch.object(subject.os,'getpid',return_value=90000))
        self.stack.enter_context(patch.object(subject.os,'getpgrp',return_value=90000))
        self.stack.enter_context(patch.object(subject,'_ACTIVE',None))
        self.owner=subject.GameOperation(subject._TOKEN,self.context,self.ref,self.value,self.plan,self.captured,self.record,self.guard)
        self.owner.active=True;subject._ACTIVE=self.owner

    def test_saved_receipt_or_public_constructor_is_not_live_authority(self):
        subject._ACTIVE=None
        with self.assertRaisesRegex(Error,'game_operation_not_current'):self.owner.assert_current(self.output,self.owner.operation_id)
        with self.assertRaisesRegex(Error,'game_operation_constructor'):
            subject.GameOperation(object(),self.context,self.ref,self.value,self.plan,self.captured,self.record,self.guard)

    def test_current_binding_rejects_other_output_operation_owner_and_expiry(self):
        self.owner.assert_current(self.output,self.owner.operation_id);self.guard.assert_called_once_with()
        for output,ident in ((self.root/'foreign',self.owner.operation_id),(self.output,'foreign')):
            with self.assertRaisesRegex(Error,'game_operation_not_current'):self.owner.assert_current(output,ident)
        with patch.object(subject.os,'getpid',return_value=90001):
            with self.assertRaisesRegex(Error,'game_operation_not_current'):self.owner.assert_current(self.output,self.owner.operation_id)
        with patch.object(subject.time,'monotonic_ns',return_value=self.owner.not_after):
            with self.assertRaisesRegex(Error,'game_operation_not_current'):self.owner.assert_current(self.output,self.owner.operation_id)

    def test_gate_requires_authority_and_one_owned_interval(self):
        self.owner.assert_current(self.output,self.owner.operation_id)
        with self.assertRaisesRegex(Error,'game_operation_authority_required'):self.owner.check('game',self.output)
        with self.owner.execution_interval(self.output):
            with self.assertRaisesRegex(Error,'game_operation_authority_required'):self.owner.grant(self.output,self.owner.operation_id)
            self.owner.authority_before=True;self.owner.phase='owned_execution'
            active,ready=self.owner.check('game',self.output)
            self.assertEqual(active['operation_id'],self.owner.operation_id)
            self.assertEqual(ready['play_observation']['hold_seconds'],1800)
            with self.assertRaisesRegex(Error,'game_execution_single_interval'):
                with self.owner.execution_interval(self.output):pass
        self.assertEqual(self.owner.phase,'finalization')
        self.owner.assert_current(self.output,self.owner.operation_id)
        with self.assertRaisesRegex(Error,'game_operation_authority_required'):self.owner.check('game',self.output)
        self.owner.active=False
        with self.assertRaisesRegex(Error,'game_operation_not_current'):self.owner.assert_current(self.output,self.owner.operation_id)

    def test_authority_failure_preserves_original_error_and_never_enters_owned_phase(self):
        self.owner.phase='authority_before'
        with patch.object(subject.admission,'current',side_effect=Error('original_authority_failure')),\
             patch.object(direct,'_execute_owned',side_effect=AssertionError('no guest owner')) as execute:
            with self.assertRaisesRegex(Error,'original_authority_failure'):
                self.owner.current_authority(self.root,{'synthetic':'candidate'},self.output/'before',self.context.provider_root)
        self.assertFalse(self.owner.authority_before);self.assertEqual(self.owner.phase,'authority_before')
        execute.assert_not_called()

    def test_original_outer_deadline_is_not_extended_by_slow_preparation(self):
        self.owner.phase='owned_execution';self.owner.authority_before=True
        with patch.object(subject.time,'monotonic_ns',return_value=self.record['not_after_monotonic_ns']-123):
            grant=self.owner.grant(self.output,self.owner.operation_id)
        self.assertEqual(grant['not_after_monotonic_ns'],self.record['not_after_monotonic_ns'])

    def test_request_descriptor_and_lease_revocation_each_refuse(self):
        self.guard.side_effect=Error('game_lease_not_current')
        with self.assertRaisesRegex(Error,'game_lease_not_current'):self.owner.assert_current(self.output,self.owner.operation_id)
        self.guard.side_effect=None;self.context.value['manual_policy']='changed'
        with self.assertRaisesRegex(Error,'game_operation_input_changed'):self.owner.assert_current(self.output,self.owner.operation_id)
        self.context.value['manual_policy']='manual_feedback_v1';self.path.write_bytes(self.path.read_bytes()+b'\n')
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):self.owner.assert_current(self.output,self.owner.operation_id)

    def test_private_guard_revoked_before_original_lease_releases(self):
        events=[];guard=None
        @contextmanager
        def lease():
            events.append('enter')
            try:yield {'held':True}
            finally:
                with self.assertRaisesRegex(Error,'game_lease_not_current'):guard()
                events.append('release')
        with patch.object(subject,'lease',lease):
            with subject._current_lease() as (held,live):
                guard=live;guard();self.assertEqual(held,{'held':True})
        self.assertEqual(events,['enter','release'])

    def test_malformed_request_rejected_before_any_runtime_boundary(self):
        for mutate in ('scope','bool','extra','output'):
            value=copy.deepcopy(self.value)
            if mutate=='scope':value['scope']='historical_game'
            elif mutate=='bool':value['limits']['whole_timeout_seconds']=True
            elif mutate=='extra':value['launcher']='/bin/anything'
            else:value['output_name']='../outside'
            build.write_json(self.path,value)
            with self.subTest(mutate=mutate),patch.object(subject,'lease',side_effect=AssertionError('no lease')):
                with self.assertRaises(Error):subject.request(self.path)


class FinalizationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.root=Path(temporary.name).resolve()
        self.output=self.root/'game';self.opout=self.root/'game.game-operation'
        self.desc=self.root/'descriptor.json';build.write_json(self.desc,{'manual_policy':'manual_feedback_v1'})
        self.context=Mock();self.context.value=build.load(self.desc);self.context.ref=build.fact(self.desc)
        self.path=self.root/'request.json';self.value=dict(schema_version=1,scope='development_game_observation',
            descriptor_ref=self.context.ref,output_name='game',manual_policy='manual_feedback_v1',
            limits=dict(whole_timeout_seconds=5400,worker_log_bytes=1024*1024))
        build.write_json(self.path,self.value);self.ref=build.fact(self.path)
        self.plan=dict(output=str(self.output),operation_output=str(self.opout),limits=self.value['limits'])
        self.captured=Mock();self.events=[];self.owner=None;self.factory=object()
        self.stack=self.enterContext(ExitStack())
        self.stack.enter_context(patch.object(subject.os,'getpid',return_value=90000))
        self.stack.enter_context(patch.object(subject.os,'getpgrp',return_value=90000))
        self.stack.enter_context(patch.object(subject,'_ACTIVE',None))
        @contextmanager
        def no_signals(*args):yield
        @contextmanager
        def lease():
            self.events.append('lease')
            try:yield {'path':'synthetic-lock'}
            finally:self.events.append('release')
        self.stack.enter_context(patch.object(subject,'deadline',no_signals))
        self.stack.enter_context(patch.object(subject,'interrupts',no_signals))
        self.stack.enter_context(patch.object(subject,'lease',lease))
        self.stack.enter_context(patch.object(subject,'review',return_value=(self.value,self.ref,self.captured,self.plan)))
        self.stack.enter_context(patch.object(subject,'_symbol',return_value=self.factory))
        self.stack.enter_context(patch.object(subject,'result_admission',return_value={}))
        self.stack.enter_context(patch.object(subject,'observe_game',return_value={'status':'assessed'}))
        self.stack.enter_context(patch.object(subject.game_prerequisites,'observe_predecessors',return_value={'mock':'read-only probe'}))
        def begin(output,*,operation):
            self.owner=operation;operation.assert_current(output,operation.operation_id)
            self.events.append('begin');return self.root,{}
        self.context.begin_game.side_effect=begin;self.context.storage_admission.return_value={}
        self.context.finalize_assessment.side_effect=lambda out:self.events.append('finalize')
        def run(context,output,*,play_factory):
            self.assertIs(context,self.context);self.assertIs(play_factory,self.factory)
            self.owner.assert_current(output,self.owner.operation_id);self.events.append('run')
            output.mkdir();build.write_json(output/'case.json',dict(launches=[{'mock':'native boundary'}],
                cleanup={'complete':True},sentinel_survived=True))
            build.write_json(output/'assessment.json',{'game_qualified':False})
            return {'game_qualified':False}
        self.stack.enter_context(patch.object(direct,'run_game',side_effect=run))

    def read(self):return build.load(self.opout/'operation.json')

    def test_one_lease_surrounds_preparation_run_finalization_then_revokes(self):
        result=subject.execute(self.path,context=self.context,play_factory=self.factory)
        self.assertEqual(self.events,['lease','begin','run','finalize','release'])
        row=self.read();self.assertEqual(row['status'],'passed');self.assertTrue(row['lock']['released'])
        self.assertFalse(result['game_qualified']);self.assertTrue(result['independent_release_required'])
        with self.assertRaisesRegex(Error,'game_operation_not_current'):
            self.owner.assert_current(self.output,self.owner.operation_id)

    def test_late_assessment_source_failure_keeps_operation_failed_and_released(self):
        self.context.finalize_assessment.side_effect=Error('game_producer_changed')
        with self.assertRaisesRegex(Error,'game_producer_changed'):subject.execute(self.path,context=self.context,play_factory=self.factory)
        row=self.read();self.assertEqual(row['status'],'failed');self.assertTrue(row['lock']['released'])
        self.assertNotIn('result_ref',row);self.assertTrue(row['runtime_execution_performed'])

    def test_receipt_write_error_does_not_replace_primary_and_lease_releases(self):
        self.context.finalize_assessment.side_effect=Error('primary_finalization')
        write=subject.build.write_json
        def fail_final(path,value):
            if Path(path)==self.opout/'operation.json' and value['status']=='failed':raise OSError('receipt full')
            return write(path,value)
        with patch.object(subject.build,'write_json',side_effect=fail_final):
            with self.assertRaisesRegex(Error,'primary_finalization') as raised:
                subject.execute(self.path,context=self.context,play_factory=self.factory)
        self.assertIn('release',self.events);self.assertIsNone(subject._ACTIVE)
        self.assertIn('Game final receipt write also failed',raised.exception.__notes__[0])

    def test_original_owner_observations_run_on_failure_without_masking_primary(self):
        with patch.object(direct,'run_game',side_effect=Error('primary_owned_failure')),\
             patch.object(subject,'observe_game',side_effect=Error('observation_evidence_failure')) as observer:
            with self.assertRaisesRegex(Error,'primary_owned_failure') as raised:
                subject.execute(self.path,context=self.context,play_factory=self.factory)
        observer.assert_called_once();row=self.read()
        self.assertEqual(row['status'],'failed');self.assertTrue(row['lock']['released'])
        self.assertEqual(row['error']['code'],'primary_owned_failure')
        self.assertEqual(row['fex_observation_error']['code'],'observation_evidence_failure')

    def test_case_evidence_failure_cannot_return_inner_success(self):
        load=subject.build.load
        def fail_case(path):
            if Path(path)==self.output/'case.json':raise Error('case_evidence_changed')
            return load(path)
        with patch.object(subject.build,'load',side_effect=fail_case):
            with self.assertRaisesRegex(Error,'case_evidence_changed'):
                subject.execute(self.path,context=self.context,play_factory=self.factory)
        row=self.read();self.assertEqual(row['status'],'failed');self.assertTrue(row['lock']['released'])
        self.assertEqual(row['runtime_execution_performed'],'unknown')


if __name__=='__main__':unittest.main()
