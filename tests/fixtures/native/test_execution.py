# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from pear_runtime.errors import Error
from pear_runtime.fixtures.inputs import save
from pear_runtime.fixtures.native import execution
from pear_runtime.fixtures.native.context import NativeContext


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.events=[];self.context=object.__new__(NativeContext);c=self.context
        c.ref={'context':'pinned'};c.value={'runtime_ref':{},'operation_ref':{},'profile_ref':{},
            'producer_manifest_ref':{},'binding_ref':{},'provider_root':str(self.root)}
        c.variant={};c.seed_adapter=object()
        c.execution_operation={'path':str(self.root/'operation.json'),'operation_id':'test'}
        @contextmanager
        def interval(output):self.events.append('lease-enter');yield;self.events.append('lease-exit')
        c.execution_interval=interval
        c.storage_admission=Mock(return_value={});c.begin=Mock(return_value=(self.root,{}))
        c.preserve_sources=Mock();c.finish=Mock(side_effect=lambda:self.events.append('finish'))
        c.finalize_assessment=Mock(return_value={})
        c.api_cases={'cases':[{'id':'api'}],'bounds':{}}
        c.bootstrap_cases={'cases':[{'id':'bootstrap-timeout'}],'bounds':{}}
        def authority(output):
            self.events.append(output.name);output.mkdir();save(output/'control.json',{'passed':True})
        c.current_authority=Mock(side_effect=authority)
        self.out=self.root/'run'
    def helper(self,result):
        def run_case(case,runtime,packet,out,bounds):
            self.events.append('original-run');out.mkdir();save(out/'case.json',result);return result
        h=SimpleNamespace(api=SimpleNamespace(target_controls=lambda *a:[],run_case=run_case),
                          base=SimpleNamespace(run_case=run_case),seed_observation=getattr(self,'seed_observation',{'cold_prefix_initialization':False}))
        @contextmanager
        def helpers(root,**kwargs):yield None,h
        return helpers
    def execute(self,result,case='api'):
        with patch.object(execution,'native_helpers',self.helper(result)),             patch.object(execution,'packet_for',return_value={'entrypoints':{}}),             patch.object(execution,'authority',return_value={}),             patch.object(execution,'assess',return_value={'passed':True}):
            return execution.run(self.context,case,self.out)
    def test_owned_interval_before_after_and_finalize(self):
        self.assertTrue(self.execute({'passed':True,'error':None})['passed'])
        self.assertEqual(self.events,['lease-enter','before','original-run','after','finish','lease-exit'])
        self.context.finalize_assessment.assert_called_once_with(self.out)
    def test_original_failure_cannot_become_pass(self):
        with self.assertRaisesRegex(Error,'bad'):self.execute({'passed':False,'error':{'code':'bad'}})
        self.context.finalize_assessment.assert_not_called()
        self.assertIn('after',self.events);self.assertIn('finish',self.events)
    def test_consumed_whole_deadline_does_not_start_after_authority(self):
        with self.assertRaisesRegex(Error,'assembly_worker_timeout'):
            self.execute({'passed':False,'error':{'code':'assembly_worker_timeout'}})
        self.assertNotIn('after',self.events);self.assertIn('finish',self.events)
        self.context.finalize_assessment.assert_not_called()
    def test_timeout_without_seed_evidence_preserves_original_failure(self):
        self.seed_observation={}
        with self.assertRaisesRegex(Error,'assembly_worker_timeout'):
            self.execute({'passed':False,'error':{'code':'assembly_worker_timeout'}})
        self.assertNotIn('after',self.events)
    def test_success_without_seed_evidence_refused(self):
        self.seed_observation={}
        with self.assertRaisesRegex(Error,'native_seed_unobserved'):
            self.execute({'passed':True,'error':None})
        self.context.finalize_assessment.assert_not_called()
    def test_expected_bootstrap_timeout_control_is_not_whole_deadline(self):
        self.assertTrue(self.execute({'passed':True,'error':None,'outcome':'timeout'},'bootstrap-timeout')['passed'])
        self.assertIn('after',self.events)
    def test_bad_input_before_original_launch(self):
        self.context.begin.side_effect=Error('changed-input')
        with self.assertRaisesRegex(Error,'changed-input'):self.execute({'passed':True,'error':None})
        self.assertNotIn('original-run',self.events)
        self.assertFalse(self.out.exists())
    def test_final_revalidation_failure_refuses_success(self):
        self.context.finish.side_effect=Error('mutated-input')
        with self.assertRaisesRegex(Error,'mutated-input'):self.execute({'passed':True,'error':None})
        self.context.finalize_assessment.assert_not_called()

if __name__=='__main__':unittest.main()
