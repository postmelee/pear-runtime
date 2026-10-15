# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
from unittest import TestCase,main
from pear_runtime.fixtures.assessment.repair_epoch import records
class RepairRecords(TestCase):
 line=b'PEAR_REPAIR1 pid=123 tid=45 seq=0 reason=1 a0=10 a1=12 d0=5 d1=5\n'
 def test_advanced_target(self):self.assertEqual(records(self.line,{123})[0]['target_after'],12)
 def test_nonadvance_or_rollback(self):
  for a,b in [(b'a1=12',b'a1=10'),(b'a1=12',b'a1=9'),(b'd1=5',b'd1=4')]:
   with self.assertRaises(Exception):records(self.line.replace(a,b),{123})
 def test_rejections_retained(self):
  for reason in (2,3):self.assertEqual(records(self.line.replace(b'reason=1',('reason='+str(reason)).encode()),{123})[0]['reason'],reason)
 def test_bad_identity_or_sequence(self):
  with self.assertRaises(Exception):records(self.line,{124})
  with self.assertRaises(Exception):records(self.line*2,{123})
  with self.assertRaises(Exception):records(self.line.replace(b'seq=0',b'seq=16'),{123})
if __name__=='__main__':main()
