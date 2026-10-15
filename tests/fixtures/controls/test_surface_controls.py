# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
import unittest
from pear_runtime.fixtures.controls.pairing import SURFACE_CASES as CASES,controls
from pear_runtime.errors import Error

class SurfaceControls(unittest.TestCase):
    def evidence(self):
        return b'\n'.join(('PEAR_SURFACE_CONTROL name=%s status=%d expected=%d facts=1'%(name,status,status)).encode() for name,status in CASES)
    def test_complete_observation(self):
        self.assertEqual(controls(self.evidence())['case_count'],len(CASES))
    def test_missing_rollback_is_not_pass(self):
        raw=b'\n'.join(x for x in self.evidence().splitlines() if b'name=registration_rollback ' not in x)
        with self.assertRaises(Error):controls(raw)
    def test_failed_ownership_is_not_pass(self):
        raw=self.evidence().replace(b'name=share_owned status=0 expected=0 facts=1',b'name=share_owned status=0 expected=0 facts=0')
        with self.assertRaises(Error):controls(raw)
    def test_self_reported_expected_cannot_override_oracle(self):
        raw=self.evidence().replace(b'name=foreign_surface status=11 expected=11',b'name=foreign_surface status=0 expected=0')
        with self.assertRaises(Error):controls(raw)
if __name__=='__main__':unittest.main()
