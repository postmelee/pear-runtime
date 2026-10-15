# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""D10 refusal tests for policy, loss and contradictory result records."""
from unittest import TestCase,main
from pear_runtime.fixtures.assessment import query as q
from pear_runtime.fixtures import direct

class QueryPolicy(TestCase):
    def receipt(self,setting='on'):
        env=q.environment('d10-original',setting)
        return dict(requested=dict(candidate='d10-original',query_observation=setting),applied=dict(query_environment=env.copy()),observed=dict(loader_query_environment=env.copy()),processes=dict(loader=dict(identity=dict(pid=42))),launches=[dict(role='loader',environment=env.copy())])
    def row(self,**change):
        values=dict(pid='42',seq='1',slot='0',tid='17',thread_ok='1',sec='3',nsec='8',clock_ok='1',addr='1000',status='00000000',valid='1',base='1000',size='1000',state='1000',protect='4',type='20000');values.update(change)
        return ('PEAR_QUERY '+' '.join(k+'='+v for k,v in values.items())+'\n').encode()
    def test_closed_options_and_routes(self):
        for n in q.CANDIDATES:
            self.assertEqual(q.environment(n,'off'),{q.KEY:'0'})
            self.assertEqual(q.environment(n,'historical'),{})
            self.assertEqual(direct.trace_environment(n,None,'progress'),direct.PROGRESS_TRACE)
        for n,v in [('d9-original','on'),('d10-original',True),('d10-original','0')]:
            with self.assertRaises(Exception):q.environment(n,v)
        # Historical builder routing is replaced by parent-owned descriptor admission tests.
    def test_policy_contradictions_refused(self):
        for key in ('request','applied','observed','actual'):
            v=self.receipt()
            if key=='request':v['requested']['query_observation']='off'
            elif key=='actual':v['launches'][0]['environment'][q.KEY]='0'
            else:v[key]['query_environment' if key=='applied' else 'loader_query_environment'][q.KEY]='0'
            with self.subTest(key=key),self.assertRaises(Exception):q.assess(v,self.row())
    def test_disabled_and_historical_output_is_not_silently_filtered(self):
        for setting in ('off','historical'):
            with self.assertRaises(Exception):q.assess(self.receipt(setting),self.row())
        v=self.receipt('historical');del v['requested']['query_observation'];del v['applied']['query_environment']
        self.assertIsNone(q.assess(v,b'')['requested'])
    def test_failures_require_zero_result_without_hiding_status(self):
        row=self.row(status='c000000d',valid='0',base='0',size='0',state='0',protect='0',type='0')
        self.assertEqual(q.records(row)[0]['status'],0xc000000d)
        for row in (self.row(status='c000000d'),self.row(status='c000000d',valid='0')):
            with self.assertRaises(Exception):q.records(row)
    def test_unrelated_process_is_rejected(self):
        with self.assertRaisesRegex(Exception,'query_process_identity'):q.assess(self.receipt(),self.row(pid='43'))
    def test_loss_duplicates_truncation_and_bounds_refused(self):
        for raw in (self.row()*2,self.row(seq='17'),self.row(slot='1'),self.row(tid='0'),self.row(clock_ok='0'),self.row(nsec='1000000000'),self.row()[:-10],self.row()[:-1],b'x'+self.row(),self.row(addr='1'*513)):
            with self.subTest(raw=raw[:60]),self.assertRaises(Exception):q.records(raw)
    def test_concurrent_write_order_can_differ_from_query_order(self):
        rows=q.records(self.row(seq='32',slot='1')+self.row())
        self.assertEqual([r['ordinal'] for r in rows],[1,32])
        # A zero-sized successful region is diagnostic evidence, not filtered out.
        self.assertEqual(q.records(self.row(size='0'))[0]['size'],0)

if __name__=='__main__':main()
