# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
import unittest
from pear_runtime.fixtures.assessment.write import parse
H=b'PEAR_OWNER_TIMEOUT seq=0 opcode=2 writer=7 active=1 pinned=1 rows=2 truncated=0\n'
R=b'PEAR_OWNER_ROW seq=0 index=0 id=8 state=2 role=1\nPEAR_OWNER_ROW seq=0 index=1 id=9 state=3 role=2\n'
W=b'Pear FEX error: PEAR_WRITE phase=invoke seq=0 status=5 domain=0 code=0 called=1 validated=1\n'
class WriteObservation(unittest.TestCase):
    def test_matched(self):
        r=parse(H+R+W);self.assertEqual(r['native_timeouts'][0]['pinned'],1);self.assertTrue(r['write_failures'][0]['validated_refusal'])
    def test_replay_and_empty(self):
        self.assertEqual(parse(b'')['native_timeouts'],[])
        self.assertFalse(parse(W.replace(b'invoke',b'admission').replace(b'called=1 validated=1',b'called=0 validated=0'))['write_failures'][0]['bridge_called'])
    def test_incomplete_duplicate_ambiguous_invalid(self):
        for raw in (H,H+R+H+R,R,H+R.replace(b'index=1',b'index=0'),H+R.replace(b'id=9',b'id=7'),H.replace(b'active=1',b'active=0')+R,W+W,W.replace(b'seq=0',b'seq=8'),W.replace(b'invoke',b'admission'),W.replace(b'called=1',b'called=0'),W[:-5],H.replace(b'rows=2',b'rows=9')+R,H.replace(b'active=1',b'active=99').replace(b'rows=2 truncated=0',b'rows=8 truncated=92')+R):
            with self.subTest(raw=raw),self.assertRaises(Exception):parse(raw)
    def test_truncated(self):
        raw=b'PEAR_OWNER_TIMEOUT seq=0 opcode=2 writer=7 active=10 pinned=0 rows=8 truncated=2\n'
        raw+=b''.join(f'PEAR_OWNER_ROW seq=0 index={i} id={100+i} state=2 role=1\n'.encode() for i in range(8))
        self.assertEqual(parse(raw)['native_timeouts'][0]['truncated'],2)
if __name__=='__main__':unittest.main()
