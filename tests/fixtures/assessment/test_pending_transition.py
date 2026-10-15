# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
from unittest import TestCase,main
from pear_runtime.fixtures.assessment import pending_transition as m
class PendingTransition(TestCase):
 def row(self,**change):
  values=dict(pid=7,tid=9,seq=0,executor=1,owner=3,state=1,wine_tid=36,serial=17,role=1,lease=0,holds=3,flags=1,transition=4);values.update(change)
  return ('PEAR_SOURCE_OWNER2 '+' '.join(f'{k}={v}' for k,v in values.items())+'\n').encode()
 def test_kind_requires_available_pending_state(self):
  for kind,name in enumerate(m.KINDS):
   self.assertEqual(m.records(self.row(transition=kind),{7})[0]['transition_name'],name)
  for state in (2,3,4,5):
   unknown=dict(state=state,wine_tid=0,serial=0,role=0,lease=0,holds=0,flags=0,transition=0)
   self.assertFalse(m.records(self.row(**unknown),{7})[0]['available'])
   unknown['transition']=1
   with self.assertRaises(Exception):m.records(self.row(**unknown),{7})
  with self.assertRaises(Exception):m.records(self.row(flags=0),{7})
  self.assertEqual(m.records(self.row(flags=0,transition=0),{7})[0]['transition_name'],'unknown')
 def test_original_identity_framing_and_bounds_remain_enforced(self):
  bad=[self.row(pid=8),self.row(seq=16),self.row(executor=3),self.row(transition=8),self.row(transition=-1),self.row(flags=64),self.row()[:-1],self.row()+self.row(),b'x'+self.row(),self.row().replace(b'OWNER2',b'OWNER1')]
  for raw in bad:
   with self.subTest(raw=raw),self.assertRaises(Exception):m.records(raw,{7})
 def test_matching_wait_opt_in_and_candidate_are_required(self):
  wait=b'PEAR_MUTATION1 pid=7 tid=9 seq=0 executor=1 first=3 last=3 attempts=1000 owner_changes=0 sequence_changes=0 waits_ok=0 wait_timeouts=1000 polls=0\n'
  v=dict(processes={'loader':{'identity':{'pid':7}}},requested={'candidate':'d21-optimized','entry_observation':'on'})
  self.assertFalse(m.assess(v,wait+self.row())['native_opcode_proven'])
  for raw in (self.row(),wait+self.row(owner=4),wait+wait+self.row()):
   with self.assertRaises(Exception):m.assess(v,raw)
  for name,mode in (('d20-optimized','on'),('d21-optimized','off')):
   v['requested']=dict(candidate=name,entry_observation=mode)
   with self.assertRaises(Exception):m.assess(v,wait+self.row())
if __name__=='__main__':main()
