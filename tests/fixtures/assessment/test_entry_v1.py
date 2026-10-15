# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
from unittest import TestCase,main
from pear_runtime.fixtures.assessment import entry as e
class EntryRecords(TestCase):
    def row(self,phase=11,facts=1,known=1):
        return f'PEAR_ECENTRY1 pid=123 tid=456 mode=1 phase={phase} status=6 domain=0 code=0 facts={facts} known={known}\n'.encode()
    def test_phase_and_identity(self):
        row=e.records(self.row(),123)[0];self.assertEqual(row['phase_name'],'mutation-snapshot');self.assertEqual(row['thread'],456)
        self.assertEqual(e.records(self.row(26,0,0))[0]['phase'],26)
        self.assertEqual(e.records(self.row(11,3,1))[0]['facts'],3)
    def test_malformed_disabled_and_bounds(self):
        for raw in (self.row()[:-1],self.row()*17,self.row(99),self.row(26,1,1),self.row().replace(b'status=6',b'status=0'),self.row().replace(b'pid=123',b'pid=0'),self.row().replace(b'PEAR_ECENTRY1',b'PEAR_ECENTRY0'),self.row().replace(b'code=0',b'code=2147483648')):
            with self.subTest(raw=raw),self.assertRaises(Exception):e.records(raw)
        with self.assertRaises(Exception):e.records(self.row(),999)
        self.assertEqual(len(e.records(self.row()*16)),16)
    def test_closed_policy_route(self):
        self.assertEqual(e.settings('d12-optimized','on'),{e.KEY:'1'});self.assertEqual(e.settings('d11-original','historical'),{})
        with self.assertRaises(Exception):e.settings('d11-original','on')
        # Historical builder routing is replaced by parent-owned descriptor admission tests.
if __name__=='__main__':main()
