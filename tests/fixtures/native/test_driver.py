# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock,patch
from pear_runtime.errors import Error
from pear_runtime.fixtures.inputs import save,fact
from pear_runtime import build
from pear_runtime.fixtures.native import driver


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.path=self.root/'request.json'
        self.value={'schema_version':1,'scope':'development_native_fixture_request','descriptor_ref':{},
                    'fixture':'api','output_name':'api-1','limits':{'whole_timeout_seconds':600,'worker_log_bytes':1048576}}
    def request(self):
        save(self.path,self.value)
        with patch.object(driver,'descriptor',return_value={'runtime_ref':{'path':str(self.root/'runtime.json')}}):
            return driver.request(self.path)
    def test_scope_and_name(self):self.assertEqual(self.request()[0]['fixture'],'api')
    def test_game_case_refused(self):
        self.value['fixture']='game'
        with self.assertRaisesRegex(Error,'native_request_case'):self.request()
    def test_alias_output_refused(self):
        self.value['output_name']='../api'
        with self.assertRaisesRegex(Error,'native_request_output'):self.request()
    def test_numeric_bool_deadline_refused(self):
        self.value['limits']['whole_timeout_seconds']=True
        with self.assertRaisesRegex(Error,'native_request_limits'):self.request()
    def test_old_fixture_scope_refused(self):
        self.value['scope']='development_fixture_verification'
        with self.assertRaisesRegex(Error,'native_request_shape'):self.request()
    def test_execute_requires_owned_worker_group(self):
        with patch.object(driver.os,'getpid',return_value=20),patch.object(driver.os,'getpgrp',return_value=30):
            with self.assertRaisesRegex(Error,'native_worker_group_required'):driver.execute(self.path)

class FinalOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.output=self.root/'api';self.operation=self.root/'api.native-operation'
        for name in ('request','descriptor','runtime','assembly'):
            save(self.root/(name+'.json'),{'bound':name})
        self.ref=fact(self.root/'request.json');self.descriptor=fact(self.root/'descriptor.json')
        self.value={'limits':{'whole_timeout_seconds':600,'worker_log_bytes':1024**2},'fixture':'api',
                    'descriptor_ref':self.descriptor}
        self.context=Mock();self.context.value={'runtime_ref':fact(self.root/'runtime.json'),
                                                'operation_ref':fact(self.root/'assembly.json')}
        self.plan={'output':str(self.output),'operation_output':str(self.operation)}
    def execute(self, corrupt_case=False, finish_error=None):
        @contextmanager
        def lease():yield {'path':str(self.root/'lock'),'acquired':{}}
        @contextmanager
        def quiet(*args):yield
        def run(context,case,output):
            with context.execution_interval(output):
                output.mkdir();(output/case).mkdir()
                if corrupt_case:(output/case/'case.json').write_text('{broken')
                else:save(output/case/'case.json',{'processes':{'loader':{}},'cleanup':{'complete':True},'sentinel_survived':True})
                save(output/'native-assessment.json',{'passed':True})
                return {'passed':True}
        if finish_error:self.context.finalize_assessment.side_effect=Error(finish_error)
        with patch.object(driver.os,'getpid',return_value=20),patch.object(driver.os,'getpgrp',return_value=20),\
             patch.object(driver,'request',return_value=(self.value,self.ref,{},None)),\
             patch.object(driver,'review',return_value=(self.value,self.ref,self.context,self.plan)),\
             patch.object(driver,'lease',lease),patch.object(driver,'deadline',quiet),patch.object(driver,'interrupts',quiet),\
             patch.object(driver.execution,'run',side_effect=run):
            return driver.execute(self.root/'request.json')
    def test_final_operation_binds_assessment_and_release(self):
        result=self.execute();record=build.load(self.operation/'operation.json')
        self.assertEqual(record['status'],'passed');self.assertIs(record['released'],True)
        self.assertIs(record['lock']['released'],True);self.assertEqual(record['assessment_ref'],result['assessment_ref'])
        self.assertEqual(record['scope'],'development_native_fixture_execution')
    def test_inner_success_finalization_failure_is_failed(self):
        with self.assertRaisesRegex(Error,'changed-producer'):self.execute(finish_error='changed-producer')
        record=build.load(self.operation/'operation.json');self.assertEqual(record['status'],'failed')
        self.assertIs(record['released'],True);self.assertNotIn('assessment_ref',record)
    def test_evidence_failure_after_success_is_failed(self):
        with self.assertRaises(Exception):self.execute(corrupt_case=True)
        record=build.load(self.operation/'operation.json');self.assertEqual(record['status'],'failed')
        self.assertEqual(record['runtime_execution_performed'],'unknown');self.assertTrue(record['evidence_errors'])

if __name__=='__main__':unittest.main()
