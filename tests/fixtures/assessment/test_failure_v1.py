# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
from unittest import TestCase,main
from pear_runtime.fixtures.assessment.failure import records
from pear_runtime.fixtures.direct import trace_environment
class FailureRecords(TestCase):
 line=b'PEAR_FAILURE1 pid=123 tid=45 seq=0 kind=1 caller=301000abc prior=0 status=6 domain=0 code=0 first=6 allocation=0\n'
 def test_exact_record(self):
  row=records(self.line,{123})[0];self.assertEqual(row['caller'],0x301000abc);self.assertEqual(row['status'],6)
 def test_owned_child(self):
  self.assertEqual(len(records(self.line+self.line.replace(b'pid=123',b'pid=124'),{123,124})),2)
 def test_unknown_process(self):
  with self.assertRaises(Exception):records(self.line,{124})
 def test_duplicate_or_exhausted(self):
  for raw in (self.line*2,self.line.replace(b'seq=0',b'seq=16')):
   with self.assertRaises(Exception):records(raw,{123})
 def test_corrupt_records(self):
  for a,b in [(b'caller=301000abc',b'caller=0'),(b'kind=1',b'kind=4'),(b'status=6',b'status=9'),(b'first=6',b'first=9'),(b'code=0',b'code=2147483648')]:
   with self.assertRaises(Exception):records(self.line.replace(a,b),{123})
 def test_closed_platform_trace(self):
  self.assertIn('+nsi',trace_environment('d14-optimized','platform-prepare-native','platform'))
  for candidate,fixture in [('d14-optimized',None),('d13-optimized','platform-prepare-native')]:
   with self.assertRaises(Exception):trace_environment(candidate,fixture,'platform')
if __name__=='__main__':main()
