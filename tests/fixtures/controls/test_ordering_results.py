# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Reject incomplete, forbidden and unbound multithread observations."""
import copy
import unittest
from pear_runtime.fixtures.controls.corpus import assess, policy_records, retirements

class OrderingResultsTests(unittest.TestCase):
    def setUp(self):
        self.events=[dict(event='ordering_round',round=0,coordinator=10,workers=[11,12],
            iterations=8,joined=2,tls_ok=True,counts=[[4,4,0,0],[2,2,0,4],[3,2,2,1],[0,3,3,2]]),
            dict(event='ordering_complete',rounds=1,iterations=8)]
        self.log=b'Pear CPU policy state=abc scalar=true vector=true memcpy=true\nPear CPU thread tid=10 state=abc\n'
        for tid in (11,12):
            self.log+=f'Pear CPU policy state={tid:x} scalar=true vector=true memcpy=true\nPear CPU thread tid={tid} state={tid:x}\n'.encode()
    def run_case(self):return assess(self.events,8,1,42)
    def test_permitted_plain_store_buffer_zero_is_not_failure(self):
        self.assertTrue(self.run_case()['passed'])
        self.events[0]['counts'][2]=[0,3,3,2]
        self.assertTrue(self.run_case()['passed'])
    def test_missing_final_round_worker_or_iteration_cannot_pass(self):
        for change in ('final','worker','count','join','tls'):
            with self.subTest(change=change):
                events=copy.deepcopy(self.events)
                if change=='final':events.pop()
                elif change=='worker':events[0]['workers']=[11,11]
                elif change=='count':events[0]['counts'][0][0]-=1
                elif change=='join':events[0]['joined']=1
                else:events[0]['tls_ok']=False
                with self.assertRaises(ValueError):assess(events,8,1,42)
    def test_forbidden_message_or_fenced_outcome_cannot_pass(self):
        for mode,counts in [(1,[2,1,1,4]),(3,[1,2,3,2]),(0,[3,4,1,0])]:
            events=copy.deepcopy(self.events);events[0]['counts'][mode]=counts
            with self.assertRaises(ValueError):assess(events,8,1,42)
    def test_failure_exit_is_preserved(self):
        with self.assertRaisesRegex(ValueError,'ordering_exit'):assess(self.events,8,1,108)
    def test_boolean_and_negative_counts_are_rejected(self):
        for counts in ([True,7,0,0],[-1,9,0,0]):
            events=copy.deepcopy(self.events);events[0]['counts'][0]=counts
            with self.assertRaisesRegex(ValueError,'ordering_counts'):assess(events,8,1,42)
    def test_actual_policy_maps_every_guest_participant(self):
        self.assertEqual([r['tid'] for r in policy_records(self.log,self.run_case())],[10,11,12])
    def test_disabled_or_missing_policy_cannot_pass(self):
        for raw in (self.log.replace(b'vector=true',b'vector=false',1),
                    self.log.replace(b'tid=12',b'tid=13'),
                    self.log.replace(b'policy state=c',b'policy state=d')):
            with self.assertRaises(ValueError):policy_records(raw,self.run_case())
    def test_thread_state_reuse_needs_new_policy_observation(self):
        raw=self.log+b'Pear CPU thread tid=12 state=c\n'
        with self.assertRaisesRegex(ValueError,'thread_without_policy'):policy_records(raw,self.run_case())

    def test_guest_join_does_not_replace_checked_source_retirement(self):
        line=b'Pear FEX init ThreadTerm.complete: status=00000000 domain=0 code=0\n'
        self.assertEqual(retirements(line*2,2),2)
        for raw in (line,line.replace(b'status=00000000',b'status=c00000bb')+line):
            with self.assertRaisesRegex(ValueError,'worker_source_retirement_incomplete'):retirements(raw,2)

if __name__=='__main__':unittest.main()
