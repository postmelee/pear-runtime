# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
from unittest import TestCase,main
from pear_runtime.fixtures.assessment import query_context as q
from . import test_query_v1 as legacy

class ContextRecords(TestCase):
    def row(self,tail=b' ctx=1 syscall=23 pc=1020 lr=2030\n'):
        return legacy.QueryPolicy().row().replace(b'PEAR_QUERY ',b'PEAR_QUERY2 ').rstrip(b'\n')+tail
    def test_known_and_unavailable_are_distinct(self):
        r=q.records(self.row())[0];self.assertEqual(r['context']['lr'],0x2030);self.assertFalse(r['context']['caller_attributed'])
        self.assertFalse(q.records(self.row(b' ctx=0 syscall=0 pc=0 lr=0\n'))[0]['context']['available'])
    def test_invalid_partial_or_mixed_context_refused(self):
        for raw in (self.row(b' ctx=0 syscall=23 pc=0 lr=0\n'),self.row(b' ctx=1 syscall=24 pc=1020 lr=2030\n'),self.row(b' ctx=1 syscall=23 pc=0 lr=2030\n'),self.row()[:-1],self.row()+legacy.QueryPolicy().row(),self.row()*2,self.row(b' ctx=1 syscall=23 pc='+b'f'*17+b' lr=1\n')):
            with self.subTest(raw=raw),self.assertRaises(Exception):q.records(raw)
    def test_policy_and_route(self):
        self.assertEqual(q.environment('d11-original','on'),{q.KEY:'1'})
        with self.assertRaises(Exception):q.environment('d10-original','on')
        # Historical builder routing is replaced by parent-owned descriptor admission tests.
        v=legacy.QueryPolicy().receipt();v['requested']['candidate']='d11-original'
        self.assertEqual(q.assess(v,self.row())['count'],1)
        v['launches'][0]['environment'][q.KEY]='0'
        with self.assertRaises(Exception):q.assess(v,self.row())
if __name__=='__main__':main()
