# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
import unittest
from pear_runtime.fixtures.assessment.wake import parse
H=b'Pear FEX error: PEAR_WAKE seq=0 writer=7 epoch=42 writing=1 nested=0 rows=1\n'
P=b'Pear FEX error: PEAR_WAKE_PEER seq=0 index=0 id=8 serial=11 role=1 lease=1 flags=1991 before=0 checkpoint=1 phase=4 status=0\n'
class WakeObservation(unittest.TestCase):
    def test_published_peer(self):
        s=parse(H+P)[0];self.assertTrue(s['peers'][0]['wake_published']);self.assertEqual(s['peers'][0]['checkpoint_phase'],4)
    def test_nested_nonwriting(self):
        s=parse(H.replace(b'writing=1 nested=0 rows=1',b'writing=0 nested=1 rows=0'))[0]
        self.assertFalse(s['owning_turn_writing']);self.assertEqual(s['nested_writing'],1)
    def test_unknown_checkpoint(self):
        s=parse(H+P.replace(b'checkpoint=1 phase=4',b'checkpoint=0 phase=0'))[0];self.assertFalse(s['peers'][0]['checkpoint_available'])
    def test_incomplete_or_ambiguous(self):
        for raw in (H,P,H+P+H+P,H+P+P,H+P.replace(b'id=8',b'id=7'),H+P.replace(b'index=0',b'index=1'),H+P.replace(b'seq=0',b'seq=8'),H+P[:-5]):
            with self.subTest(raw=raw),self.assertRaises(Exception):parse(raw)
    def test_invalid_states_or_bounds(self):
        for raw in (H.replace(b'rows=1',b'rows=65')+P,H.replace(b'writing=1',b'writing=0')+P,H+P.replace(b'flags=1991',b'flags=1024'),H+P.replace(b'lease=1',b'lease=0'),H+P.replace(b'phase=4',b'phase=7'),H.replace(b'epoch=42',b'epoch=0')+P,H+P.replace(b'serial=11',b'serial=65536'),H+P.replace(b'checkpoint=1',b'checkpoint=0'),H+P.replace(b'status=0',b'status=9'),H+P.replace(b'phase=4 status=0',b'phase=3 status=5')):
            with self.subTest(raw=raw),self.assertRaises(Exception):parse(raw)
    def test_empty(self):self.assertEqual(parse(b''),[])
if __name__=='__main__':unittest.main()
