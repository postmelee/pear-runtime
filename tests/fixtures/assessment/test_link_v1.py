# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
from unittest import TestCase,main
from pear_runtime.fixtures.assessment import link as l
class LinkRecords(TestCase):
 def row(self,kind=2,reason=3,n=1,a=64,b=64):return f'PEAR_LINK1 pid=123 tid=456 kind={kind} reason={reason} ordinal={n} a={a} b={b}\n'.encode()
 def test_actual_capacity_and_completed(self):
  self.assertEqual(l.records(self.row(),123)[0]['a'],64)
  self.assertEqual(l.records(self.row(1,121,16,100,200))[0]['reason'],121)
 def test_malformed_bounds_and_identity(self):
  for raw in (self.row()[:-1],self.row()*2,self.row(reason=3,a=63),self.row(n=9),self.row(n=2**64),self.row(kind=3),self.row(reason=6),self.row().replace(b'PEAR_LINK1',b'PEAR_LINK0')):
   with self.subTest(raw=raw),self.assertRaises(Exception):l.records(raw)
  with self.assertRaises(Exception):l.records(self.row(),999)
 def test_registered_process_streams_remain_distinct(self):
  child=self.row().replace(b'pid=123',b'pid=124');raw=self.row()+child
  self.assertEqual(len(l.records(raw,{123,124})),2)
  with self.assertRaises(Exception):l.records(raw,{123})
  with self.assertRaises(Exception):l.records(raw+child,{123,124})
  with self.assertRaises(Exception):l.records(raw,set())
 def test_launch_contract(self):
  env={l.KEY:'1'};v={'requested':{'candidate':'d13-optimized','link_observation':'on'},'applied':{'link_environment':env},'observed':{'loader_link_environment':env},'launches':[{'role':'loader','environment':env}],'processes':{'loader':{'identity':{'pid':123}}}}
  self.assertEqual(l.assess_link(v,self.row())['count'],1)
  v['observed']['loader_link_environment']={l.KEY:'0'}
  with self.assertRaises(Exception):l.assess_link(v,self.row())
 def test_closed_route_and_entry_reuse(self):
  self.assertEqual(l.settings('d13-optimized','on'),{l.KEY:'1'})
  self.assertEqual(l.entry_settings('d13-optimized','on'),{'PEAR_FEX_ENTRY_OBSERVE':'1'})
  with self.assertRaises(Exception):l.settings('d12-optimized','on')
  # Historical builder routing is replaced by parent-owned descriptor admission tests.
if __name__=='__main__':main()
