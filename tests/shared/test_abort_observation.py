# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
import unittest
from pear_runtime import abort_observation as obs

def line(side,**changes):
    r=dict(pid=42,tid=24,guard=4096,call=1,life=9,executor=3,allocation=7,generation=2,
      extent=16384,size=16384,epoch=22,expected=2,aclass=1,role=1,continuation=0,
      before_epoch=20,before_state=3,begin_state=2,bridge=1,validated=1,
      reason=3,previous_known=1,previous=3,status=8,domain=0,code=0)
    r.update(changes)
    return ('PEAR_ABORT1 side='+side+' '+' '.join(f'{k}={r[k]}' for k in obs.FIELDS[side])+'\n').encode()
def packet(**owner):return line('owner',**owner)+line('source')+line('core')

class AbortJoinTests(unittest.TestCase):
    def test_join_is_independent_of_delivery_order(self):
        a=obs.assess(packet(),{42});self.assertTrue(a['received_records_joined'])
        self.assertEqual(a['joined'][0]['reason'],'abort-nonreserved-write')
        self.assertFalse(a['first_global_cause_proven']);self.assertFalse(a['mismatch_cause_proven'])
    def test_missing_record_is_unknown(self):
        for raw in (b'',line('source')+line('core'),line('owner')):
            a=obs.assess(raw,{42});self.assertFalse(a['received_records_joined']);self.assertEqual(a['joined'],[])
    def test_exact_request_tuple_rejects_false_join(self):
        for key in obs.TUPLE:
            if key=='pid':continue
            default=dict(executor=3,allocation=7,generation=2,extent=16384,size=16384,epoch=22,expected=2,aclass=1,role=1,continuation=0)[key]
            if key in ('expected','aclass','role'):
                with self.assertRaises(Exception):obs.assess(packet(**{key:99}),{42})
            else:
                a=obs.assess(packet(**{key:default+1}),{42});self.assertFalse(a['received_records_joined'])
    def test_duplicate_is_not_unique_call(self):
        for side in obs.FIELDS:
            with self.assertRaises(Exception):obs.assess(packet()+line(side),{42})
    def test_unknown_prior_state_is_not_invented(self):
        a=obs.assess(packet(reason=1,previous_known=0,previous=0),{42})
        self.assertTrue(a['received_records_joined']);self.assertFalse(a['joined'][0]['previous_known'])
        with self.assertRaises(Exception):obs.assess(packet(reason=3,previous_known=0,previous=0),{42})
    def test_preserves_original_error_and_rejects_conflict(self):
        raw=b''.join(line(s,domain=2,code=-7) for s in obs.FIELDS)
        self.assertEqual(obs.assess(raw,{42})['joined'][0]['code'],-7)
        with self.assertRaises(Exception):obs.assess(packet(code=1,domain=2),{42})
    def test_foreign_truncated_or_malformed_refused(self):
        for raw in (packet()[:-1],packet().replace(b'PEAR_ABORT1',b'PEAR_ABORT2'),packet().replace(b'life=9',b'life=0'),packet().replace(b'validated=1',b'validated=0')):
            with self.assertRaises(Exception):obs.assess(raw,{42})
        with self.assertRaises(Exception):obs.assess(packet(),{43})
    def test_cross_call_partial_records_do_not_join(self):
        for change in [dict(allocation=8,generation=3,executor=4),dict(call=2,life=10)]:
            raw=line('core')+line('source',**change)+line('owner',**change)
            a=obs.assess(raw,{42});self.assertFalse(a['received_records_joined']);self.assertEqual(a['joined'],[])
    def test_full_received_triples_do_not_prove_complete_observation(self):
        raw=b''.join(line(s,epoch=22+i,call=1+i) for i in range(8) for s in obs.FIELDS)
        a=obs.assess(raw,{42});self.assertTrue(a['received_records_joined']);self.assertTrue(a['record_cap_reached'])
        self.assertFalse(a['observation_complete']);self.assertFalse(a['invocation_uniqueness_proven'])
    def test_guard_reuse_requires_distinct_epoch(self):
        raw=packet()+b''.join(line(s,epoch=23,before_epoch=22,call=2) for s in obs.FIELDS)
        a=obs.assess(raw,{42});self.assertTrue(a['received_records_joined']);self.assertEqual(len(a['joined']),2)

if __name__=='__main__':unittest.main()
