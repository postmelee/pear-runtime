# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Full portable fixture checks with actual current-authority JSON decoding."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pear_runtime.errors import Error
from pear_runtime.fixtures import checks
from pear_runtime.fixtures.context import FixtureContext
from pear_runtime.fixtures.inputs import fact
from pear_runtime.fixtures.types import CandidateDescription


class AuthorityChecksTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve()
        self.runtime=self.root/'runtime';self.runtime.mkdir()
        self.run=self.root/'case';self.run.mkdir();(self.run/'run').mkdir()
        self.write(self.runtime/'runtime.json',{'synthetic':True})
        self.write(self.root/'operation.json',{'synthetic_operation':'reviewed'})
        self.operation_ref=fact(self.root/'operation.json')
        fixture=self.runtime/'configured-memory.exe';fixture.write_bytes(b'synthetic fixture bytes')
        self.runtime_ref=fact(self.runtime/'runtime.json')
        events=[
            {'event':'bootstrap','cpu_type':16777228,'translation_value':0,'translation_error':0},
            {'event':'image','cpu_type':16777228},
            {'event':'stage3_process_exit','exit_code':42},
        ]
        (self.run/'run/loader.events').write_text(''.join(json.dumps(row)+'\n' for row in events))
        self.record={
            'diagnostic_fixture':{'name':'configured-memory','artifact':fact(fixture)},
            'runtime_ref':self.runtime_ref,'runtime_sha256':self.runtime_ref['sha256'],
            'requested':{'candidate':'d25-game','signal_resume':'off'},
            'error':None,'cleanup_errors':[],
            'logs':[{'role':'loader','channel':'events','path':'loader.events'}],
            'events':{'loader':events},
        }
        self.write(self.run/'case.json',self.record)
        self.runtime_value={'fixtures':{'configured-memory':{'path':fixture.name,'sha256':fact(fixture)['sha256']}}}
        # Only the already completed context admission is mocked. Its exact type
        # and reviewed operation reference still participate in the real checks.
        self.context=object.__new__(FixtureContext)
        self.context.value={'operation_ref':self.operation_ref}
        self.assessed={'fixture_passed':True,'signal_resume':{'enabled':False},'query_observation':{'enabled':False}}
        for side in ('before','after'):
            (self.run/side).mkdir()
            self.write(self.run/side/'control.json',self.control())

    @staticmethod
    def write(path,value):
        path.write_text(json.dumps(value,indent=2)+'\n')

    def control(self):
        return {'passed':True,'runtime_sha256':self.runtime_ref['sha256'],
                'operation_ref':self.operation_ref,
                'timings':[{'phase':'current_authority','seconds':0.125,'started':{'monotonic_ns':100}}]}

    def assess(self):
        with patch.object(checks.direct,'assess',return_value=self.assessed), \
             patch.object(FixtureContext,'assessed_runtime',return_value=(self.runtime,self.runtime_value)):
            return checks.fixture(self.run,CandidateDescription('d25-game','synthetic fixture check'),fixture_context=self.context)

    def test_new_authority_fractional_phase_timings_pass(self):
        result=self.assess()
        self.assertIs(result['passed'],True)
        self.assertEqual(result['fixture'],'configured-memory')
        self.assertEqual(result['runtime_ref'],self.runtime_ref)
        self.assertFalse(result['full_graphics_qualification'])
        saved=json.loads((self.run/'shared-fixture-assessment.json').read_text())
        self.assertEqual(saved,result)

    def test_integer_passed_is_refused_for_either_authority(self):
        for side in ('before','after'):
            with self.subTest(side=side):
                row=self.control();row['passed']=1
                self.write(self.run/side/'control.json',row)
                with self.assertRaisesRegex(Error,'checkpoint_fixture_authority'):self.assess()
                self.assertFalse((self.run/'shared-fixture-assessment.json').exists())
                self.write(self.run/side/'control.json',self.control())

    def test_other_operation_reference_is_refused_for_either_authority(self):
        for side in ('before','after'):
            with self.subTest(side=side):
                row=self.control();row['operation_ref']={**self.operation_ref,'sha256':'0'*64}
                self.write(self.run/side/'control.json',row)
                with self.assertRaisesRegex(Error,'checkpoint_fixture_authority'):self.assess()
                self.assertFalse((self.run/'shared-fixture-assessment.json').exists())
                self.write(self.run/side/'control.json',self.control())

    def test_duplicate_authority_json_keys_are_refused(self):
        for side in ('before','after'):
            with self.subTest(side=side):
                raw=json.dumps(self.control())
                (self.run/side/'control.json').write_text('{"passed": true,'+raw[1:]+'\n')
                with self.assertRaisesRegex(Error,'duplicate_json_key'):self.assess()
                self.assertFalse((self.run/'shared-fixture-assessment.json').exists())
                self.write(self.run/side/'control.json',self.control())


if __name__=='__main__':unittest.main()
