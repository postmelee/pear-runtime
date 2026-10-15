# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Current exact-input counterparts; no historical collector or host execution."""
import copy
from contextlib import ExitStack
import errno
import json
from pathlib import Path
import tempfile
import sys
from types import ModuleType
import unittest
from unittest.mock import patch
from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.assembly import core
from pear_runtime.assembly.helpers import SourcePack, signing_helpers
from pear_runtime.fixtures import context,producers
from pear_runtime.recipes import fex
from tests.fixtures import test_context as context_fixtures
from tests.build import test_fex as fex_fixtures

class CurrentInputCases(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name).resolve()
 def file(self,name,data=b'fixture'):
  p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);return p
 def input_context(self,output='output',wrong_header=False):
  p=self.file('input/wine/pear_fex_memory.h',b'#define PEAR_FEX_MEMORY_ABI 3\n');row=build.fact(p)
  recipe={'schema_version':1,'name':'synthetic-input-only','roots':{'wine':{'kind':'input'}},'inputs':[dict(root='wine',path='wine/pear_fex_memory.h',sha256='0'*64 if wrong_header else row['sha256'],size_bytes=row['size_bytes'])],'budget':{'additional_bytes':4096,'floor_bytes':0}}
  return build.Context(recipe,{'wine':str(p.parent.parent)},self.root/output,lock_path=self.root/'local-test.lock')
 def receipt(self):
  return {'schema_version':1,'scope':'development_component_build','status':'passed','runtime_eligible':False,'game_qualified':False,'recipe_sha256':'a'*64,'roots':{'fex':{'kind':'git','commit':'b'*40}},'commands':[{'exit_code':0,'error':None,'logs':{'stdout':{'later':'stdout'},'stderr':{'later':'stderr'}}}]}
 def request(self):return {'ref':{'synthetic':'receipt'},'recipe_sha256':'a'*64,'source_commits':{'fex':'b'*40}}
 def boundary_refusal(self,value,code):
  with patch.object(core,'read_ref',return_value=value),patch.object(core,'checked_ref',side_effect=AssertionError('later byte read')) as later,patch.object(core,'_operation_record',side_effect=AssertionError('later operation read')) as operation:
   with self.assertRaisesRegex(Error,code):core._build_artifacts(self.request())
   later.assert_not_called();operation.assert_not_called()
 def test_scope_schema_and_claim_refusals_precede_artifact_reads(self):
  for key,value in [('schema_version',True),('schema_version',2),('scope','other'),('status','unperformed'),('runtime_eligible',True),('game_qualified',True)]:
   with self.subTest(key=key,value=value):
    row=self.receipt();row[key]=value;self.boundary_refusal(row,'assembly_build_scope')
  with patch.object(core,'read_ref',return_value=self.receipt()),patch.object(core,'checked_ref',side_effect=RuntimeError('positive advanced to log read')):
   with self.assertRaisesRegex(RuntimeError,'positive advanced'):core._build_artifacts(self.request())
 def test_boolean_missing_failed_exit_and_error_refused(self):
  for exit,error in [(False,None),(None,None),(1,None),(0,'original failure')]:
   with self.subTest(exit=exit,error=error):
    row=self.receipt();row['commands'][0].update(exit_code=exit,error=error);self.boundary_refusal(row,'assembly_build_commands')
  row=self.receipt();row['commands']=[];self.boundary_refusal(row,'assembly_build_commands')
 def test_copy_existing_leaf_refused_without_overwrite(self):
  with self.input_context() as ctx:
   dest=ctx.path('copied.h');dest.write_bytes(b'keep me')
   with self.assertRaisesRegex(Error,'build_copy_output_exists'):ctx.copy_input('wine','wine/pear_fex_memory.h','copied.h')
   self.assertEqual(dest.read_bytes(),b'keep me');self.assertEqual(ctx.commands,[]);ctx.finish('passed')
 def test_output_symlink_refused_before_fact_and_regular_control(self):
  with self.input_context() as ctx:
   regular=ctx.path('regular');regular.write_bytes(b'owned');alias=ctx.path('alias');alias.symlink_to('regular')
   with patch.object(build,'fact',side_effect=AssertionError('must refuse before bytes')):
    with self.assertRaisesRegex(Error,'build_output_alias'):ctx.record_output('alias')
   self.assertEqual(ctx.record_output('regular'),build.fact(regular));ctx.finish('passed')
 def test_finish_runtime_claim_override_cannot_succeed(self):
  for index,key in enumerate(('runtime_eligible','game_qualified')):
   with self.subTest(key=key):
    ctx=self.input_context('out'+str(index))
    with self.assertRaisesRegex(Error,'build_receipt_override'):
     with ctx:ctx.finish('passed',extra={key:True})
    row=build.load(ctx.output/'build.json');self.assertEqual(row['status'],'failed');self.assertIs(row[key],False);self.assertEqual(row['commands'],[])
 def test_metadata_only_and_empty_archive_refused(self):
  for index,data in enumerate((b'!<arch>\n',fex_fixtures.archive(('/',b'index')),fex_fixtures.archive(('//',b'name.obj/\n')),fex_fixtures.archive(('/<ECSYMBOLS>/',b'index')))):
   with self.subTest(index=index),self.assertRaisesRegex(Error,'fex_archive_members'):fex.archive_members(self.file(str(index)+'.a',data))
  self.assertEqual(len(fex.archive_members(self.file('positive.a',fex_fixtures.archive(('a.obj/',b'body'))))),1)
 def test_native_errno_preserved(self):
  self.assertEqual(core.failure_details(OSError(errno.EACCES,'denied'))['errno'],errno.EACCES)
 def test_non_os_failure_does_not_invent_errno(self):
  for error in (Error('original'),ValueError('original')):
   details=core.failure_details(error);self.assertNotIn('errno',details);self.assertNotIn('native_error',details)
 def test_bound_command_receipt_tamper_is_refused(self):
  original={'commands':[{'argv':['/known/compiler','-c','a.cpp'],'env':{'LANG':'C'},'cwd':'/owned/root','exit_code':0,'started':{'monotonic_seconds':1.0}}]}
  p=self.file('build.json');mutations={'argv':['/known/compiler','-c','a.cpp','extra'],'env':{'LANG':'other'},'cwd':'/different/root','exit_code':1,'started':{'monotonic_seconds':1.1}}
  for key,value in mutations.items():
   with self.subTest(key=key):
    build.write_json(p,original);ref=build.fact(p);core.checked_ref(ref)
    changed=copy.deepcopy(original);changed['commands'][0][key]=value;build.write_json(p,changed)
    with self.assertRaisesRegex(Error,'assembly_reference_changed'):core.checked_ref(ref)
 def test_reference_fields_refused_before_any_fact(self):
  ref=build.fact(self.file('reference'))
  for bad in ({k:v for k,v in ref.items() if k!='sha256'},dict(ref,unknown=1),dict(ref,size_bytes=True)):
   with self.subTest(ref=bad),patch.object(build,'fact',side_effect=AssertionError('no byte read')):
    with self.assertRaisesRegex(Error,'assembly_reference_(shape|identity)'):core.checked_ref(bad)
 def test_raw_reference_lexical_spelling_and_symlink_refused(self):
  p=self.file('sub/file');ref=build.fact(p)
  for name in (str(p.parent)+'/./file',str(p.parent)+'//file'):
   with self.subTest(name=name),self.assertRaisesRegex(Error,'assembly_reference_changed'):core.checked_ref(dict(ref,path=name))
  alias=self.root/'alias';alias.symlink_to(p)
  with self.assertRaisesRegex(Error,'assembly_reference_alias'):core.checked_ref(dict(ref,path=str(alias)))
 def producer_sources(self,**limits):
  code=self.root/'code';(code/'pear_runtime').mkdir(parents=True,exist_ok=True)
  (code/'pear_runtime/__init__.py').write_bytes(b'')
  (code/'pear_runtime/synthetic.py').write_bytes(b'raise AssertionError("SOURCE MUST NEVER EXECUTE")\n')
  with ExitStack() as stack:
   stack.enter_context(patch.object(producers,'_root_map',return_value={'runtime':code}))
   stack.enter_context(patch.object(producers.supervision,'SOURCE_PATHS',()))
   for key,value in limits.items():stack.enter_context(patch.object(producers,key,value))
   return producers.required_sources({'runtime':str(code)},entry_modules=('pear_runtime.synthetic',),dynamic_paths=())
 def test_source_text_is_data_not_executed(self):
  roots,refs,raw=self.producer_sources();self.assertEqual(len(refs),2)
  self.assertIn(b'SOURCE MUST NEVER EXECUTE',raw[('runtime','pear_runtime/synthetic.py')])
 def test_per_file_source_limit_refused(self):
  with self.assertRaisesRegex(Error,'input_size_limit'):self.producer_sources(FILE_LIMIT=8)
  self.assertFalse((self.root/'producer-sources').exists())
 def test_source_count_limit_refused(self):
  with self.assertRaisesRegex(Error,'fixture_producer_budget'):self.producer_sources(MAX_FILES=1)
  self.assertFalse((self.root/'producer-sources').exists())
 def test_source_total_limit_refused(self):
  with self.assertRaisesRegex(Error,'fixture_producer_budget'):self.producer_sources(TOTAL_LIMIT=8)
  self.assertFalse((self.root/'producer-sources').exists())
 def test_wrong_wire_digest_refused_before_output_or_compile(self):
  ctx=self.input_context(wrong_header=True)
  with self.assertRaisesRegex(Error,'build_input_mismatch'):
   with ctx:self.fail('header must fail admission')
  self.assertFalse(ctx.output.exists())
 def test_snapshot_name_substitution_refused(self):
  fixture=context_fixtures.ContextTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
  ctx,out,source,snapshot=fixture.prepared_final_context();rows=json.loads((out/'producers.json').read_text())
  alternative=out/'different-name.py';alternative.write_bytes(snapshot.read_bytes());rows[0]['snapshot']=build.fact(alternative);build.write_json(out/'producers.json',rows)
  with patch.object(ctx,'_admit',return_value=(fixture.runtime,fixture.value)),patch.dict(sys.modules,{'ctypes':ModuleType('ctypes_forbidden_in_pure_test')}):
   with self.assertRaisesRegex(Error,'fixture_context_producer_rows_changed'):ctx.finalize_assessment(out)
  self.assertFalse(ctx._assessment_finalized)
 def test_original_wrapped_native_error_is_preserved_without_native_call(self):
  provider=Path(__file__).resolve().parents[2]/'pear_runtime/providers/pear_legacy'
  helpers,_=signing_helpers(SourcePack(provider))
  wrapped=helpers.wrapped_error(OSError(errno.EACCES,'observed denial'),'synthetic_wrapped_failure')
  wrapped.bound_outcome={'exit_code':9};wrapped.evidence_errors=['original evidence failure']
  expected={'domain':'POSIX','code':errno.EACCES,'exception_type':'PermissionError'}
  details=core.failure_details(wrapped)
  self.assertEqual(details['native_error'],expected)
  self.assertEqual(details['bound_outcome'],wrapped.bound_outcome)
  self.assertEqual(details['evidence_errors'],wrapped.evidence_errors)
  self.assertNotIn('errno',details)
  ordinary=helpers.wrapped_error(ValueError('ordinary'),'synthetic_non_native_failure')
  self.assertNotIn('native_error',core.failure_details(ordinary))
