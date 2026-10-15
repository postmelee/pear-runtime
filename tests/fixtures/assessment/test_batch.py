# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
import unittest
from pear_runtime.fixtures.assessment.batch import parse
class BatchEvidence(unittest.TestCase):
    def test_empty(self):self.assertEqual(parse(b'other log\n'),[])
    def test_failure_fields(self):
        self.assertEqual(parse(b'Pear FEX error: PEAR_BATCH phase=mutation seq=0 status=5 domain=2 code=-123\n'),[dict(phase='mutation',sequence=0,status=5,domain=2,code=-123)])
    def test_ambiguous_process_sequence_refused(self):
        row=b'PEAR_BATCH phase=writer-linked seq=0 status=5 domain=0 code=0\n'
        with self.assertRaisesRegex(Exception,'batch_phase_ambiguous_sequence'):parse(row*2)
    def test_bound(self):
        with self.assertRaisesRegex(Exception,'batch_phase_values'):parse(b'PEAR_BATCH phase=mutation seq=8 status=5 domain=0 code=0')
    def test_unknown_phase(self):
        with self.assertRaisesRegex(Exception,'batch_phase_values'):parse(b'PEAR_BATCH phase=unknown seq=0 status=5 domain=0 code=0')
    def test_success_not_failure(self):
        with self.assertRaisesRegex(Exception,'batch_phase_values'):parse(b'PEAR_BATCH phase=mutation seq=0 status=0 domain=0 code=0')
    def test_incomplete(self):
        with self.assertRaisesRegex(Exception,'batch_phase_syntax'):parse(b'PEAR_BATCH phase=mutation seq=0 status=5 domain=0')
if __name__=='__main__':unittest.main()
