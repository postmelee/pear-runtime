# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
from unittest import TestCase,main
from unittest.mock import patch
from pathlib import Path
import tempfile
from types import SimpleNamespace
from pear_runtime.fixtures import direct, types as prep
from pear_runtime.fixtures.assessment import early_wait as m
class EarlyWait(TestCase):
 def wait(self,**changes):
  v=dict(pid=7,tid=9,seq=0,executor=1,owner=3,state=1,wine_tid=36,serial=3,role=1,lease=0,holds=3,flags=1,transition=1,mutation_seq=5,attempts=200);v.update(changes)
  return ('PEAR_SOURCE_WAIT1 '+' '.join(f'{k}={v}' for k,v in v.items())+'\n').encode()
 def registration(self,**changes):
  v=dict(pid=7,seq=0,id=3,role=1,valid=1,host=12345,register_lo=100,register_hi=105);v.update(changes)
  return ('PEAR_OWNER_REGISTER1 '+' '.join(f'{k}={v}' for k,v in v.items())+'\n').encode()
 def test_exact_owner_identity_join(self):
  w=m.wait_records(self.wait(),{7});r=m.registration_records(self.registration(),{7});j=m.owner_joins(w,r)[0]
  self.assertTrue(j['mapped']);self.assertEqual(j['host_thread'],12345);self.assertEqual(w[0]['mutation_sequence'],5)
 def test_unknown_and_absent_registration_remain_unknown(self):
  w=m.wait_records(self.wait(),{7})
  for r in ([],m.registration_records(self.registration(id=4),{7}),m.registration_records(self.registration(valid=0,host=0,register_lo=0,register_hi=0),{7}),m.registration_records(self.registration(role=2),{7})):
   self.assertFalse(m.owner_joins(w,r)[0]['mapped'])
 def test_snapshot_must_be_available(self):
  w=m.wait_records(self.wait(state=2,wine_tid=0,serial=0,role=0,holds=0,flags=0,transition=0),{7})
  self.assertFalse(m.owner_joins(w,m.registration_records(self.registration(),{7}))[0]['mapped'])
 def test_wait_framing_identity_and_bounds(self):
  for raw in (self.wait(pid=8),self.wait(attempts=199),self.wait(seq=16),self.wait(mutation_seq=2**32),self.wait()[:-1],b'x'+self.wait(),self.wait()+self.wait(),self.wait(flags=0),self.wait(executor=3)):
   with self.subTest(raw=raw),self.assertRaises(Exception):m.wait_records(raw,{7})
 def test_registration_framing_identity_and_bounds(self):
  for raw in (self.registration(pid=8),self.registration(seq=128),self.registration(id=0),self.registration(role=3),self.registration(valid=2),self.registration(host=0),self.registration(register_hi=99),self.registration(valid=0),self.registration()[:-1],b'x'+self.registration(),self.registration()+self.registration(seq=1)):
   with self.subTest(raw=raw),self.assertRaises(Exception):m.registration_records(raw,{7})
 def test_maximum_frames_are_bounded_and_process_scoped(self):
  self.assertEqual(len(m.registration_records(b''.join(self.registration(seq=i,id=i+1) for i in range(128)),{7})),128)
  self.assertEqual(len(m.wait_records(b''.join(self.wait(seq=i) for i in range(16)),{7})),16)
  r=m.registration_records(self.registration()+self.registration(pid=8),{7,8});self.assertEqual(len(r),2)
 def test_ambiguous_join_is_rejected(self):
  r=m.registration_records(self.registration(),{7})
  with self.assertRaises(Exception):m.owner_joins(m.wait_records(self.wait(),{7}),r+r)
 def test_trigger_uses_complete_owned_rows(self):
  raw=self.registration()+self.wait()
  self.assertTrue(m.trigger(raw,7)['owner_identity']['mapped'])
  self.assertIsNone(m.trigger(self.wait()[:-1],7))
  self.assertEqual(m.trigger(raw+self.wait(seq=1)[:-1],7)['wait']['sequence'],0)
  with self.assertRaises(Exception):m.trigger(raw,8)
  with self.assertRaises(Exception):m.wait_records(self.wait()[:-1],{7})
 def test_event_sampler_starts_once_only_after_attach(self):
  sampler=direct.SampleWindows(None,Path('/unused'),100,{},None,('source-wait',),10)
  target=SimpleNamespace(pid=7,exited=False);calls=[]
  def start(t):calls.append(t.pid);sampler.rows.append({})
  sampler.start=start
  with patch.object(direct.time,'monotonic',return_value=1):
   sampler.tick(target,None,self.registration()+self.wait());self.assertFalse(calls)
   sampler.tick(target,0,b'');self.assertFalse(calls)
   sampler.tick(target,0,self.registration()+self.wait());self.assertEqual(calls,[7])
   sampler.tick(target,0,self.registration()+self.wait());self.assertEqual(calls,[7])
  self.assertTrue(sampler.rows[0]['source_wait_trigger']['owner_identity']['mapped'])
 def test_event_sampler_preserves_deadline_and_exit(self):
  for exited,deadline in ((True,100),(False,2)):
   sampler=direct.SampleWindows(None,Path('/unused'),deadline,{},None,('source-wait',),10)
   sampler.start=lambda target:self.fail('unexpected sampling')
   with patch.object(direct.time,'monotonic',return_value=1):sampler.tick(SimpleNamespace(pid=7,exited=exited),0,self.registration()+self.wait())
 def test_event_sampling_has_closed_scope(self):
  selected=prep.Selection('d22-optimized',Path('/unused'));mode=('source-wait',)
  self.assertEqual(direct.options(selected,'on',mode)['PEAR_FEX_THREAD_OBSERVE'],'1')
  self.assertEqual(direct.sample_interval(selected,mode),10)
  for name in direct.CANDIDATES:
   if name not in ('d22-optimized','d23-16384','d23-65536','d24-131072'):
    with self.assertRaisesRegex(Exception,'direct_event_sample_scope'):direct.options(prep.Selection(name,Path('/unused')),'on',mode)
  with self.assertRaisesRegex(Exception,'direct_event_sample_scope'):direct.options(selected,'off',mode)
 def test_disabled_observations_cannot_pass(self):
  v=dict(processes={'loader':{'identity':{'pid':7}}},requested=dict(candidate='d22-optimized',entry_observation='on',observations={'PEAR_FEX_THREAD_OBSERVE':'1'}))
  self.assertTrue(m.assess(v,self.registration()+self.wait())['owner_joins'][0]['mapped'])
  for changes,raw in (({'entry_observation':'off'},self.wait()),({'observations':{}},self.registration()),({'candidate':'d21-optimized'},self.registration())):
   with self.assertRaises(Exception):m.assess({**v,'requested':{**v['requested'],**changes}},raw)
 def test_sample_receipt_matches_observed_trigger(self):
  raw=self.registration()+self.wait();row=dict(source_wait_trigger=m.trigger(raw,7),requested_offset_seconds=None,interval_ms=10,duration_seconds=2)
  v=dict(processes={'loader':{'identity':{'pid':7}}},requested=dict(candidate='d22-optimized',entry_observation='on',observations={'PEAR_FEX_THREAD_OBSERVE':'1'},samples=['source-wait']),observed={'samples':[row]})
  self.assertTrue(m.assess(v,raw)['owner_joins'][0]['mapped'])
  for samples in ([row,row],[{**row,'source_wait_trigger':None}],[{**row,'interval_ms':1}],[{**row,'duration_seconds':20}]):
   with self.assertRaises(Exception):m.assess({**v,'observed':{'samples':samples}},raw)
 def test_shared_owned_pipe_selects_only_target_wait(self):
  raw=self.registration(pid=8,host=888)+self.wait(pid=8)+self.registration()+self.wait()
  event=m.trigger(raw,7,{7,8})
  self.assertEqual(event['wait']['process'],7)
  self.assertEqual(event['owner_identity']['host_thread'],12345)
  self.assertIsNone(m.trigger(self.registration(pid=8)+self.wait(pid=8),7,{7,8}))
  missing=m.trigger(self.registration(pid=8)+self.wait(),7,{7,8})
  self.assertFalse(missing['owner_identity']['mapped'])
 def test_shared_pipe_keeps_unknown_duplicate_and_target_rejection(self):
  for raw,owned in ((self.registration(pid=8)+self.wait(),{7}),
                    (self.registration(pid=8)+self.registration(pid=8)+self.wait(),{7,8}),
                    (self.registration()+self.wait(),{8}),
                    (self.registration(pid=8,valid=0)+self.wait(),{7,8})):
   with self.subTest(raw=raw,owned=owned),self.assertRaises(Exception):m.trigger(raw,7,owned)
 def test_shared_pipe_sampler_waits_for_target_event(self):
  sampler=direct.SampleWindows(None,Path('/unused'),100,{},None,('source-wait',),10)
  target=SimpleNamespace(pid=7,exited=False);calls=[]
  def start(t):calls.append(t.pid);sampler.rows.append({})
  sampler.start=start;child=self.registration(pid=8)+self.wait(pid=8)
  with patch.object(direct.time,'monotonic',return_value=1):
   sampler.tick(target,0,child,{7,8});self.assertFalse(calls)
   sampler.tick(target,0,child+self.registration()+self.wait(),{7,8});self.assertEqual(calls,[7])
  self.assertEqual(sampler.rows[0]['source_wait_trigger']['wait']['process'],7)
 def test_shared_pipe_final_receipt_has_same_owned_selection(self):
  raw=self.registration(pid=8)+self.wait(pid=8)+self.registration()+self.wait()
  row=dict(source_wait_trigger=m.trigger(raw,7,{7,8}),requested_offset_seconds=None,interval_ms=10,duration_seconds=2)
  v=dict(processes={'loader':{'identity':{'pid':7}}},registrations=[{'identity':{'pid':8}}],requested=dict(candidate='d22-optimized',entry_observation='on',observations={'PEAR_FEX_THREAD_OBSERVE':'1'},samples=['source-wait']),observed={'samples':[row]})
  self.assertEqual(len(m.assess(v,raw)['waits']),2)
  with self.assertRaises(Exception):m.assess({**v,'registrations':[]},raw)
  foreign=dict(row,source_wait_trigger=m.trigger(raw,8,{7,8}))
  with self.assertRaises(Exception):m.assess({**v,'observed':{'samples':[foreign]}},raw)
 def test_short_event_sample_uses_one_second_without_upfront_symbols(self):
  with tempfile.TemporaryDirectory() as tmp:
   identity={'pid':7,'start':1};launched=[]
   def arch(pid,flavor,arg,info,size):info._obj[0]=16777228;return size
   observer=SimpleNamespace(refresh=lambda:None,identity=lambda pid:identity,executable=lambda pid:'/owned/loader',lib=SimpleNamespace(proc_pidinfo=arch))
   target=SimpleNamespace(pid=7,identity=identity,reaped=False,exited=False,allowed_paths={'/owned/loader'})
   def launch(role,args,env,**kwargs):launched.append((role,args,kwargs));return SimpleNamespace(pid=8,identity={'pid':8,'start':2})
   sampler=direct.SampleWindows(SimpleNamespace(observer=observer),Path(tmp),100,{},launch,('source-wait-short',),10)
   with patch.object(direct.time,'monotonic',return_value=20):sampler.start(target)
   self.assertEqual(launched[0][1],['/usr/bin/arch','-arm64','/usr/bin/sample','7','1','10','-file',str(Path(tmp)/'sample-0.txt')])
   self.assertEqual(launched[0][2]['allowed_paths'],['/usr/bin/arch','/usr/bin/sample'])
   self.assertEqual(sampler.active[3],30)
   self.assertEqual(sampler.rows[0]['duration_seconds'],1)
   self.assertIsNone(sampler.rows[0]['requested_offset_seconds'])
   self.assertFalse(sampler.rows[0]['valid'])
 def test_short_event_scope_and_receipt_duration(self):
  mode=('source-wait-short',);selected=prep.Selection('d22-optimized',Path('/unused'))
  direct.options(selected,'on',mode);self.assertEqual(direct.sample_interval(selected,mode),10)
  for name in direct.CANDIDATES:
   if name not in ('d22-optimized','d23-16384','d23-65536','d24-131072'):
    with self.assertRaisesRegex(Exception,'direct_event_sample_scope'):direct.options(prep.Selection(name,Path('/unused')),'on',mode)
  with self.assertRaisesRegex(Exception,'direct_event_sample_scope'):direct.options(selected,'off',mode)
  raw=self.registration()+self.wait();row=dict(source_wait_trigger=m.trigger(raw,7),requested_offset_seconds=None,interval_ms=10,duration_seconds=1)
  v=dict(processes={'loader':{'identity':{'pid':7}}},requested=dict(candidate='d22-optimized',entry_observation='on',observations={'PEAR_FEX_THREAD_OBSERVE':'1'},samples=list(mode)),observed={'samples':[row]})
  m.assess(v,raw)
  with self.assertRaises(Exception):m.assess({**v,'observed':{'samples':[{**row,'duration_seconds':2}]}},raw)
 def test_short_event_deadline_and_single_launch(self):
  for deadline,want in ((1.5,[]),(2,[7])):
   sampler=direct.SampleWindows(None,Path('/unused'),deadline,{},None,('source-wait-short',),10);calls=[]
   def start(t):calls.append(t.pid);sampler.rows.append({})
   sampler.start=start;target=SimpleNamespace(pid=7,exited=False)
   with patch.object(direct.time,'monotonic',return_value=1):
    sampler.tick(target,0,self.registration()+self.wait());sampler.tick(target,0,self.registration()+self.wait())
   self.assertEqual(calls,want)
if __name__=='__main__':main()
