# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""CPU operation admission, single lease and late-failure evidence controls."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures.controls import cpu_driver as driver


class CPURequests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.path=self.root/'request.json';self.desc=self.root/'descriptor.json';build.write_json(self.desc,{})
        self.value=dict(schema_version=1,scope='development_cpu_verification',descriptor_ref=build.fact(self.desc),
                        case_id='ordering',output_name='cpu-1',limits=dict(whole_timeout_seconds=900,worker_log_bytes=1024))
        self.manifest={'output_root':str(self.root)};self.base={'runtime_ref':{'path':str(self.root/'runtime/runtime.json')}}
        self.describe=self.enterContext(patch.object(driver,'descriptor',return_value=(self.manifest,self.base)))
        self.native=self.enterContext(patch.object(driver.cpu_execution,'run',side_effect=AssertionError('native run')))

    def load(self,value=None):
        build.write_json(self.path,self.value if value is None else value);return driver.request(self.path)

    def test_closed_request_does_not_accept_options_or_game_inputs(self):
        for extra in ({'options':{}},{'game':{}},{'schema_version':True},{'scope':'game_execution'}):
            with self.subTest(extra=extra),self.assertRaisesRegex(Error,'cpu_request_shape'):self.load({**self.value,**extra})
        self.describe.assert_not_called();self.native.assert_not_called()

    def test_exact_case_set_and_fresh_output_vocabulary(self):
        for case_id in ('game','device','phase-guest',None):
            with self.assertRaisesRegex(Error,'cpu_request_case'):self.load({**self.value,'case_id':case_id})
        for name in ('..','a/b','/absolute',''):
            with self.assertRaisesRegex(Error,'cpu_request_output'):self.load({**self.value,'output_name':name})
        self.native.assert_not_called()

    def test_limits_reject_boolean_and_unbounded_values(self):
        for limits in ({'whole_timeout_seconds':True,'worker_log_bytes':1024},
                       {'whole_timeout_seconds':1801,'worker_log_bytes':1024},
                       {'whole_timeout_seconds':900,'worker_log_bytes':16*1024**2+1}):
            with self.assertRaisesRegex(Error,'cpu_request_limits'):self.load({**self.value,'limits':limits})

    def test_inspection_has_no_live_lease_or_execution(self):
        self.load();callbacks=[]
        def context(ref,candidate,callback):
            callbacks.append(callback)
            return SimpleNamespace(base=self.base,fresh_output=lambda p:p,storage_admission=lambda p:{})
        with patch.object(driver,'CPUContext',side_effect=context),patch.object(driver,'lease') as lease:
            before=set(self.root.iterdir());plan=driver.review(self.path)[3]
            self.assertFalse(plan['runtime_execution_performed']);self.assertEqual(before,set(self.root.iterdir()))
            with self.assertRaisesRegex(Error,'cpu_inspection_cannot_execute'):
                with callbacks[0](self.root/'cpu-1'):pass
            lease.assert_not_called();self.native.assert_not_called()


class CPUOperation(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.output=self.root/'cpu';self.operation=self.root/'cpu.cpu-operation';self.path=self.root/'request.json';self.desc=self.root/'descriptor.json'
        build.write_json(self.desc,{})
        self.value=dict(case_id='ordering',descriptor_ref=build.fact(self.desc),limits=dict(whole_timeout_seconds=900,worker_log_bytes=1024))
        build.write_json(self.path,self.value);self.ref=build.fact(self.path);self.mode='pass';self.held=False;self.events=[]
        self.context=SimpleNamespace(timings=[],finalize_assessment=Mock(side_effect=self.finalize))
        self.plan=dict(output=str(self.output),operation_output=str(self.operation))
        self.enterContext(patch.object(driver,'request',return_value=(self.value,self.ref,{},None)))
        self.enterContext(patch.object(driver,'review',side_effect=self.review))
        self.enterContext(patch.object(driver.os,'getpid',return_value=123));self.enterContext(patch.object(driver.os,'getpgrp',return_value=123))
        self.enterContext(patch.object(driver,'lease',self.lease));self.enterContext(patch.object(driver,'deadline',self.deadline))
        self.enterContext(patch.object(driver,'interrupts',self.interrupts))
        self.enterContext(patch.object(driver.cpu_execution,'run',side_effect=self.run_case))

    @contextmanager
    def lease(self):
        self.assertFalse(self.held);self.held=True;self.events.append('acquire')
        try:yield {'path':str(self.root/'lock')}
        finally:self.events.append('release');self.held=False

    @contextmanager
    def deadline(self,seconds):yield

    @contextmanager
    def interrupts(self):yield

    def review(self,path):
        self.assertTrue(self.held);return self.value,self.ref,self.context,self.plan

    def run_case(self,context,case_id,output):
        self.assertTrue(self.held);self.assertEqual(case_id,'ordering')
        target=self.root/'wrong' if self.mode=='wrong' else output
        with context.execution_interval(target):
            output.mkdir();build.write_json(output/'case.json',dict(launches=[{}],cleanup={'complete':True},sentinel_survived=True))
            if self.mode=='error':raise Error('original_owned_error')
        if self.mode=='twice':
            with context.execution_interval(output):self.fail('reentered')
        result={'passed':True};build.write_json(output/'cpu-assessment.json',result);return result

    def finalize(self,output):
        self.assertTrue(self.held)
        if self.mode=='late':raise Error('late_producer_changed')

    def receipt(self):return build.load(self.operation/'operation.json')

    def test_one_lease_and_released_operation_after_exact_case(self):
        driver.execute(self.path);value=self.receipt()
        self.assertEqual(self.events,['acquire','release']);self.assertTrue(value['lock']['released'])
        self.assertEqual(value['status'],'passed');self.assertEqual(len(value['intervals']),1)

    def test_late_producer_change_prevents_pass_after_result_written(self):
        self.mode='late'
        with self.assertRaisesRegex(Error,'late_producer_changed'):driver.execute(self.path)
        value=self.receipt();self.assertEqual(value['status'],'failed');self.assertTrue(value['lock']['released'])
        self.assertNotIn('result_ref',value);self.assertTrue(value['cleanup']['complete'])

    def test_owned_error_retains_cleanup_and_releases_lease(self):
        self.mode='error'
        with self.assertRaisesRegex(Error,'original_owned_error'):driver.execute(self.path)
        value=self.receipt();self.assertEqual(value['error']['code'],'original_owned_error')
        self.assertTrue(value['cleanup']['complete']);self.assertTrue(value['lock']['released'])

    def test_wrong_interval_cannot_create_a_case(self):
        self.mode='wrong'
        with self.assertRaisesRegex(Error,'cpu_live_interval_scope'):driver.execute(self.path)
        value=self.receipt();self.assertEqual(value['intervals'],[]);self.assertFalse(self.output.exists())

    def test_second_interval_is_rejected_with_first_evidence_retained(self):
        self.mode='twice'
        with self.assertRaisesRegex(Error,'cpu_live_interval_scope'):driver.execute(self.path)
        value=self.receipt();self.assertEqual(len(value['intervals']),1);self.assertTrue(value['cleanup']['complete'])


class ModuleEntrypoint(unittest.TestCase):
    def test_module_invocation_runs_request_admission(self):
        import subprocess,sys
        with tempfile.TemporaryDirectory() as directory:
            request=Path(directory).resolve()/'bad.json';request.write_text('{}')
            result=subprocess.run([sys.executable,'-B','-m','pear_runtime.fixtures.controls.cpu_driver',
                                   'inspect','--request',str(request)],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,1)
            self.assertIn(b'cpu_request_shape',result.stderr)
            self.assertEqual(result.stdout,b'')
