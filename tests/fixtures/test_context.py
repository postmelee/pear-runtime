# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compiled capability, descriptor state and conservative storage controls."""
import copy
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import uuid
from unittest.mock import Mock,patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import context
from pear_runtime.fixtures.types import Selection
from tests.fixtures.header_fixture import SelectedFixture

REPO=Path(__file__).resolve().parents[2]


class CompiledTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name).resolve()
        self.fixture=SelectedFixture(self.root,json.loads((REPO/'pear_runtime/fixtures/capabilities/d36.json').read_text()))
        self.catalog=self.fixture.catalog;self.built=self.fixture.built

    def test_three_actual_compile_commands_and_depfile_sources_admitted(self):
        with patch('subprocess.run',side_effect=AssertionError('no native execution')):
            context.compiled_capabilities(self.built,self.catalog)

    def test_missing_define_in_each_unit_refused(self):
        for index in range(3):
            value=copy.deepcopy(self.built);value['commands'][index]['argv'].remove(self.catalog['compile_units'][index]['required_defines'][0])
            with self.subTest(unit=index),self.assertRaisesRegex(Error,'fixture_capability_compile_defines'):
                context.compiled_capabilities(value,self.catalog)

    def test_macro_override_undefine_response_and_forwarding_refused(self):
        for extra in (['-DPEAR_FEX_MEMORY_OWNER=0'],['-UPEAR_FEX_MEMORY_OWNER'],['@more.rsp'],['-Xclang','-UPEAR_FEX_MEMORY_OWNER'],['-D','OTHER=1']):
            value=copy.deepcopy(self.built);value['commands'][0]['argv']+=extra
            with self.subTest(extra=extra),self.assertRaisesRegex(Error,'fixture_capability_compile_defines'):
                context.compiled_capabilities(value,self.catalog)

    def test_failed_command_wrong_source_and_duplicate_compile_refused(self):
        variants=[]
        value=copy.deepcopy(self.built);value['commands'][0]['exit_code']=1;variants.append(value)
        value=copy.deepcopy(self.built);argv=value['commands'][0]['argv'];argv[argv.index('-c')+1]=str(self.root/'wrong.cpp');variants.append(value)
        value=copy.deepcopy(self.built);value['commands'].append(value['commands'][0]);variants.append(value)
        for value in variants:
            with self.assertRaises(Error):context.compiled_capabilities(value,self.catalog)

    def test_source_size_and_depfile_binding_are_required(self):
        value=copy.deepcopy(self.built);value['dependencies'][0]['files'][0]['size_bytes']+=1
        with self.assertRaisesRegex(Error,'fixture_capability_unit'):context.compiled_capabilities(value,self.catalog)
        value=copy.deepcopy(self.built);value['dependencies'][0]['depfile']=value['dependencies'][1]['depfile']
        with self.assertRaisesRegex(Error,'fixture_capability_depfile'):context.compiled_capabilities(value,self.catalog)

    def test_changed_compile_log_refused(self):
        Path(self.built['commands'][0]['logs']['stdout']['path']).write_bytes(b'changed log')
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):context.compiled_capabilities(self.built,self.catalog)


class ContextTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name).resolve()
        self.runtime=self.root/'runtime';self.seed=self.root/'seed';self.provider=self.root/'provider';self.output=self.root/'outputs';self.code=self.root/'code'
        for p in (self.runtime,self.seed,self.provider,self.output,self.code):p.mkdir()
        private=self.root/'private';private.mkdir()
        def ref(name,data=b'synthetic'):
            p=(private if name=='profile' else self.root)/name;p.write_bytes(data);return build.fact(p)
        self.profile=ref('profile');self.capabilities=ref('capabilities');self.producer=ref('producers')
        seed={'scope':'translated_graphics','fixture_id':'device','outcome':'exited','error':None,'cleanup':{'complete':True},'sentinel_survived':True,'cleanup_errors':[]}
        build.write_json(self.seed/'case.json',seed)
        self.value={'passed':True,'diagnostic_only':True,'runtime_qualified':False,'runtime_eligible':False,'game_qualified':False,
                    'execution_authorized_by_this_record':False,'development_assembly':{'profile_ref':self.profile},
                    'assembly_operation':{'path':str(self.root/'operation.json'),'operation_id':str(uuid.uuid4())}}
        build.write_json(self.runtime/'runtime.json',self.value);runtime_ref=build.fact(self.runtime/'runtime.json')
        build.write_json(self.root/'operation.json',{'schema_version':1,'scope':'development_candidate_assembly_operation','operation_id':self.value['assembly_operation']['operation_id'],
            'status':'passed','runtime_ref':runtime_ref,'lock':{'released':True},'plan':{'output':str(self.runtime),'operation_output':str(self.root)}})
        fixtures={name:ref('fixture-'+name) for name in context.NAMES}
        self.modules={name:dict(seed_sha256='a'*64,selected_ref=ref('module-'+name)) for name in ('ntdll.dll','xtajit64.dll')}
        self.inventory=[dict(path='drive_c/windows/system32/'+name,kind='file',mode=0o600,size=10,sha256='a'*64) for name in self.modules]
        self.descriptor={'schema_version':1,'scope':'redistributable_runtime_fixtures','candidate':'d25-game','runtime_ref':runtime_ref,
            'operation_ref':build.fact(self.root/'operation.json'),'profile_ref':self.profile,'capabilities_ref':self.capabilities,
            'provider_root':str(self.provider),'producer_manifest_ref':self.producer,'fixture_refs':fixtures,
            'seed_root':str(self.seed),'seed_ref':build.fact(self.seed/'case.json'),'seed_inventory':self.inventory,
            'modules':self.modules,'output_root':str(self.output)}
        self.path=self.root/'descriptor.json';self.freeze()
        self.captured=Mock(roots={'runtime':self.code},logical_bytes=256);self.captured.preserve.return_value=[{'preserved':'synthetic'}]
        self.capture=patch.object(context.producers,'capture',return_value=self.captured);self.capture.start();self.addCleanup(self.capture.stop)
        self.capability=patch.object(context,'capability_binding',return_value={name:True for name in context.CAPABILITIES});self.capability.start();self.addCleanup(self.capability.stop)

    def freeze(self):build.write_json(self.path,self.descriptor);self.ref=build.fact(self.path)
    def construct(self):return context.FixtureContext(self.ref,Selection('d25-game',self.runtime),lambda out:nullcontext())

    def test_exact_descriptor_and_candidate_type(self):
        ctx=self.construct();self.assertEqual(ctx.seed,self.seed)
        with self.assertRaisesRegex(Error,'fixture_context_bindings'):
            context.FixtureContext(self.ref,SimpleNamespace(name='d25-game',runtime=self.runtime),lambda out:nullcontext())
        with self.assertRaisesRegex(Error,'fixture_context_candidate'):
            context.FixtureContext(self.ref,Selection('d25-game',self.seed),lambda out:nullcontext())

    def test_other_candidate_fixture_set_or_qualified_runtime_refused(self):
        self.descriptor['candidate']='d25-fixture';self.freeze()
        with self.assertRaisesRegex(Error,'fixture_context_shape'):self.construct()
        self.descriptor['candidate']='d25-game';self.descriptor['fixture_refs'].pop('configured-memory');self.freeze()
        with self.assertRaisesRegex(Error,'fixture_context_fixture_set'):self.construct()

    def test_malformed_seed_inventory_and_overlap_refused(self):
        self.descriptor['seed_inventory']=[dict(self.inventory[0],path='../secret')];self.freeze()
        with self.assertRaisesRegex(Error,'fixture_context_seed_path_unsafe'):self.construct()
        self.descriptor['seed_inventory']=self.inventory;self.descriptor['output_root']=str(self.code);self.freeze()
        with self.assertRaisesRegex(Error,'fixture_context_output_source_overlap'):self.construct()

    def test_source_manifest_validation_is_not_optional(self):
        self.capture.stop()
        with self.assertRaises(Exception):self.construct()

    def test_storage_requires_full_logical_peak_plus_reserve(self):
        ctx=self.construct();output=self.output/'run'
        required=842557436+1024**3+256+6*1024**3
        with patch.object(context.shutil,'disk_usage',return_value=SimpleNamespace(free=required)):
            row=ctx.storage_admission(output)
        self.assertEqual(row['required_free_bytes'],required);self.assertFalse(row['apfs_clone_savings_assumed'])
        self.assertFalse(output.exists());self.assertFalse(row['execution_authorized_by_this_record'])
        with patch.object(context.shutil,'disk_usage',return_value=SimpleNamespace(free=required-1)):
            with self.assertRaisesRegex(Error,'fixture_storage_capacity'):ctx.storage_admission(output)

    def test_larger_seed_and_positive_module_growth_are_budgeted(self):
        self.descriptor['seed_inventory'][0]['size']=1024**3;self.freeze();ctx=self.construct()
        ctx.value['modules']['xtajit64.dll']['selected_ref']['size_bytes']=100
        with patch.object(context.shutil,'disk_usage',return_value=SimpleNamespace(free=20*1024**3)):
            row=ctx.storage_admission(self.output/'run')
        self.assertEqual(row['budgeted_seed_bytes'],1024**3+10);self.assertEqual(row['positive_module_growth_bytes'],90)

    def test_fresh_output_alias_existing_and_outside_root_refused(self):
        ctx=self.construct();existing=self.output/'run';existing.mkdir()
        for path in (existing,self.root/'outside',self.output/'nested'/'run'):
            with self.subTest(path=path),self.assertRaises(Error):ctx.fresh_output(path)

    def test_sources_require_active_exact_output_and_preserve_state(self):
        ctx=self.construct();output=self.output/'run'
        with self.assertRaisesRegex(Error,'fixture_context_source_output'):ctx.preserve_sources(output)
        with patch.object(ctx,'_admit',return_value=(self.runtime,self.value)):
            ctx.begin('configured-memory',output);output.mkdir()
            self.assertEqual(ctx.preserve_sources(output),[{'preserved':'synthetic'}]);ctx.finish()
        self.captured.preserve.assert_called_once_with(output)
        with self.assertRaisesRegex(Error,'fixture_context_single_run'):ctx.begin('configured-memory',self.output/'other')

    def prepared_final_context(self):
        ctx=self.construct();output=self.output/'run';output.mkdir()
        source=self.code/'synthetic.py';source.write_bytes(b'source');snapshot=output/'snapshot.py';snapshot.write_bytes(b'source')
        rows=[dict(original=build.fact(source),snapshot=build.fact(snapshot))]
        build.write_json(output/'producers.json',rows)
        ctx._completed=True;ctx._validated_end=True;ctx._output=output
        ctx._runtime=self.runtime;ctx._runtime_value=self.value;ctx._producer_rows=context.encoded(rows)
        return ctx,output,source,snapshot

    def test_final_assessment_rechecks_runtime_and_original_snapshot_oracle(self):
        ctx,output,_,_=self.prepared_final_context()
        with patch.object(ctx,'_admit',return_value=(self.runtime,self.value)) as admit:
            result=ctx.finalize_assessment(output)
        admit.assert_called_once();self.assertEqual(result['producers_ref'],build.fact(output/'producers.json'))
        self.assertTrue(ctx._assessment_finalized)
        with self.assertRaisesRegex(Error,'fixture_context_final_assessment_scope'):ctx.finalize_assessment(output)

    def test_final_assessment_refuses_source_or_snapshot_drift(self):
        for which in ('source','snapshot'):
            with self.subTest(which=which):
                # Each subcase has a fresh output owned by this test.
                ctx,output,source,snapshot=self.prepared_final_context()
                (source if which=='source' else snapshot).write_bytes(b'changed after oracle')
                with patch.object(ctx,'_admit',return_value=(self.runtime,self.value)):
                    with self.assertRaisesRegex(Error,'direct_producer_changed_during_run'):ctx.finalize_assessment(output)
                self.assertFalse(ctx._assessment_finalized)
                import shutil
                shutil.rmtree(output)

    def test_final_assessment_refuses_omitted_snapshot_or_unfinished_context(self):
        ctx,output,_,_=self.prepared_final_context();build.write_json(output/'producers.json',[])
        with patch.object(ctx,'_admit',return_value=(self.runtime,self.value)):
            with self.assertRaisesRegex(Error,'fixture_context_producer_rows_changed'):ctx.finalize_assessment(output)
        ctx._validated_end=False
        with self.assertRaisesRegex(Error,'fixture_context_final_assessment_scope'):ctx.finalize_assessment(output)

    def test_failed_admission_terminal_and_assessment_before_finish_refused(self):
        ctx=self.construct()
        with patch.object(ctx,'_admit',side_effect=Error('synthetic_changed')):
            with self.assertRaisesRegex(Error,'synthetic_changed'):ctx.begin('configured-memory',self.output/'run')
        with self.assertRaisesRegex(Error,'fixture_context_single_run'):ctx.begin('configured-memory',self.output/'other')
        with self.assertRaisesRegex(Error,'fixture_context_assessment_before_finish'):ctx.assessed_runtime(self.output/'run',{})


if __name__=='__main__':unittest.main()
