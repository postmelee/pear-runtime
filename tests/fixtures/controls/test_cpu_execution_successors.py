# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Original four execution refusal groups against the current D36 contract.

The synthetic fixture is shared by composition, without inheriting and
rediscovering its unrelated test methods. No host or guest process is launched.
"""
import unittest
from pear_runtime.errors import Error
from tests.fixtures.controls import test_cpu_evidence as evidence_fixture


class ExecutionEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = evidence_fixture.CPUObservationTests(methodName='runTest')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.record = self.fixture.record

    def observe(self):
        return self.fixture.observe()

    def test_admits_only_complete_observation_shape(self):
        row, evidence, _ = self.observe()
        self.assertEqual(row['exit_code'], 42)
        self.assertFalse(evidence['late_load_coverage_complete'])

    def test_cleanup_and_sentinel_failures_cannot_pass(self):
        self.record['cleanup']['complete'] = False
        with self.assertRaisesRegex(Error, 'cpu_execution_boundary'):
            self.observe()
        self.record['cleanup']['complete'] = True
        self.record['sentinel_survived'] = False
        with self.assertRaisesRegex(Error, 'cpu_execution_boundary'):
            self.observe()

    def test_rosetta_or_foreign_image_cannot_pass(self):
        self.record['events']['loader'][0]['translation_value'] = 1
        self.fixture.logs()
        with self.assertRaisesRegex(Error, 'cpu_translated_host_process'):
            self.observe()
        self.record['events']['loader'][0]['translation_value'] = 0
        self.record['events']['loader'][1]['cpu_type'] = 16777223
        self.fixture.logs()
        with self.assertRaisesRegex(Error, 'cpu_non_arm64_image'):
            self.observe()

    def test_other_binary_cannot_stand_in_for_requested_case(self):
        self.record['launches'][-1]['argv'][-1] = 'other.exe'
        with self.assertRaisesRegex(Error, 'cpu_different_fixture_launched'):
            self.observe()


if __name__ == '__main__':
    unittest.main()
