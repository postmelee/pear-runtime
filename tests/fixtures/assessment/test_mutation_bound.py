# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
from unittest import TestCase,main
from pear_runtime.fixtures.assessment import mutation_bound as m

class Counters(TestCase):
    def row(self,**changes):
        v=dict(pid=7,tid=9,seq=0,executor=1,first=2,last=2,attempts=1000,owner_changes=0,sequence_changes=0,waits_ok=0,wait_timeouts=1000,polls=0);v.update(changes)
        return ('PEAR_MUTATION1 '+' '.join(f'{k}={x}' for k,x in v.items())+'\n').encode()
    def test_timeout_and_churn_remain_distinct(self):
        self.assertEqual(m.records(self.row(),{7})[0]['timeout_waits'],1000)
        row=m.records(self.row(last=3,owner_changes=999,sequence_changes=999,waits_ok=1000,wait_timeouts=0,polls=1000),{7})[0]
        self.assertEqual(row['observed_owner_changes'],999)
        self.assertEqual(row['timeout_waits'],0)
    def test_identity_shape_and_counter_failures(self):
        for change in ({'pid':8},{'seq':16},{'executor':2},{'first':0},{'attempts':999},{'owner_changes':1000},
                       {'last':3},{'waits_ok':1},{'polls':1001},{'sequence_changes':1000}):
            with self.subTest(change=change),self.assertRaises(Exception):m.records(self.row(**change),{7})
        for raw in (self.row()[:-1],self.row()+self.row(),b'x'+self.row()):
            with self.assertRaises(Exception):m.records(raw,{7})
    def test_per_process_bound_and_observation_opt_in(self):
        raw=b''.join(self.row(seq=i) for i in range(16))
        self.assertEqual(len(m.records(raw,{7})),16)
        with self.assertRaises(Exception):m.records(raw+self.row(seq=16),{7})
        value=dict(processes={'loader':{'identity':{'pid':7}}},requested={'candidate':'d18-optimized','entry_observation':'on'})
        a=m.assess(value,self.row());self.assertFalse(a['elapsed_wait_time_known']);self.assertFalse(a['complete_timeline'])
        for candidate,mode in (('d17-optimized','on'),('d18-optimized','off')):
            value['requested']=dict(candidate=candidate,entry_observation=mode)
            with self.assertRaises(Exception):m.assess(value,self.row())

if __name__=='__main__':main()
