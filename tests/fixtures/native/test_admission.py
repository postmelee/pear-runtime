# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from pear_runtime.errors import Error
from pear_runtime.fixtures.inputs import fact,save
from pear_runtime.fixtures.native.provider import validate_suite_authorization
from pear_runtime.fixtures.native.context import completed_fixture


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        for name in ('runtime','assembly'):save(self.root/(name+'.json'),{'bound':name})
        self.runtime=fact(self.root/'runtime.json');self.operation=fact(self.root/'assembly.json')
        self.control={'passed':True,'runtime_sha256':self.runtime['sha256'],'operation_ref':self.operation,'seconds':0.25}
        self.packet={'entrypoints':{'stage4_pe':'a','window_pe':'b','window_driver_pe':'c'},'code_publication_policy':'page-wx',
            'native_fixture_policy':{'scope':'development_native_wine_controls','runtime_ref':self.runtime,
                'operation_ref':self.operation,'authority_ref':None,'requirements':{}}}
    def validate(self):
        save(self.root/'control.json',self.control);self.packet['native_fixture_policy']['authority_ref']=fact(self.root/'control.json')
        return validate_suite_authorization('mac-driver',self.packet)
    def test_float_current_control_accepts(self):self.validate()
    def test_numeric_pass_refused(self):
        self.control['passed']=1
        with self.assertRaisesRegex(Error,'native_current_authority_required'):self.validate()
    def test_wrong_operation_refused(self):
        self.control['operation_ref']=self.runtime
        with self.assertRaisesRegex(Error,'native_current_authority_required'):self.validate()
    def test_changed_control_refused(self):
        self.validate();save(self.root/'control.json',{'passed':True})
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):validate_suite_authorization('mac-driver',self.packet)
    def prerequisite(self,status='passed',released=True):
        assessment={'scope':'development_native_fixture_assessment','passed':True,'case_id':'api','runtime_ref':self.runtime,
          'assembly_operation_ref':self.operation,'case_ref':self.runtime,'producer_snapshot_ref':self.runtime,
          'before_ref':None,'after_ref':None,'execution_operation':{'path':str(self.root/'operation.json'),'operation_id':'unique'}}
        self.validate();assessment['before_ref']=assessment['after_ref']=fact(self.root/'control.json')
        save(self.root/'native-assessment.json',assessment);aref=fact(self.root/'native-assessment.json')
        operation={'scope':'development_native_fixture_execution','status':status,'released':released,'assessment_ref':aref,
          'case_id':'api','runtime_ref':self.runtime,'assembly_operation_ref':self.operation,'operation_id':'unique',
          'lock':{'released':released},'plan':{'output':str(self.root)}}
        save(self.root/'operation.json',operation)
        return fact(self.root/'operation.json'),aref
    def test_inner_pass_outer_failed_refused(self):
        o,a=self.prerequisite(status='failed')
        with self.assertRaisesRegex(Error,'native_completed_operation'):completed_fixture(o,a,'api',self.runtime,self.operation)
    def test_unreleased_refused(self):
        o,a=self.prerequisite(released=False)
        with self.assertRaisesRegex(Error,'native_completed_operation'):completed_fixture(o,a,'api',self.runtime,self.operation)
    def test_completed_pair(self):
        o,a=self.prerequisite();self.assertTrue(completed_fixture(o,a,'api',self.runtime,self.operation)['passed'])
    def test_other_candidate_refused(self):
        o,a=self.prerequisite()
        with self.assertRaisesRegex(Error,'native_completed_operation'):completed_fixture(o,a,'api',self.operation,self.operation)

if __name__=='__main__':unittest.main()
