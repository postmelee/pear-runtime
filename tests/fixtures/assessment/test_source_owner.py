# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
from unittest import TestCase,main
from pear_runtime.fixtures.assessment import source_owner as m
class SourceOwner(TestCase):
 def row(self,**change):
  v=dict(pid=7,tid=9,seq=0,executor=1,owner=3,state=1,wine_tid=36,serial=17,role=1,lease=2,holds=2,flags=0);v.update(change)
  return ('PEAR_SOURCE_OWNER1 '+' '.join(f'{k}={x}' for k,x in v.items())+'\n').encode()
 def test_known_and_unknown_are_distinct(self):
  self.assertEqual(m.records(self.row(),{7})[0]['wine_thread'],36)
  for state in (2,3,4,5):
   r=m.records(self.row(state=state,wine_tid=0,serial=0,role=0,lease=0,holds=0),{7})[0]
   self.assertFalse(r['available'])
 def test_shape_identity_and_unsupported_claims(self):
  for change in ({'pid':8},{'seq':16},{'executor':3},{'owner':0},{'state':0},{'state':6},{'state':2},{'wine_tid':0},{'role':3},{'lease':4},{'holds':2**32},{'flags':64}):
   with self.subTest(change=change),self.assertRaises(Exception):m.records(self.row(**change),{7})
  for raw in (self.row()[:-1],self.row()+self.row(),b'x'+self.row()):
   with self.assertRaises(Exception):m.records(raw,{7})
 def test_requires_matching_failed_wait_and_opt_in(self):
  wait=b'PEAR_MUTATION1 pid=7 tid=9 seq=0 executor=1 first=3 last=3 attempts=1000 owner_changes=0 sequence_changes=0 waits_ok=0 wait_timeouts=1000 polls=0\n'
  v=dict(processes={'loader':{'identity':{'pid':7}}},requested={'candidate':'d20-optimized','entry_observation':'on'})
  self.assertFalse(m.assess(v,wait+self.row())['native_thread_mapping_proven'])
  for raw in (self.row(),wait+self.row(owner=4),wait+wait+self.row()):
   with self.assertRaises(Exception):m.assess(v,raw)
  for name,mode in (('d19-optimized','on'),('d20-optimized','off')):
   v['requested']=dict(candidate=name,entry_observation=mode)
   with self.assertRaises(Exception):m.assess(v,wait+self.row())
if __name__=='__main__':main()
