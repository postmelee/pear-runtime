# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from pear_runtime.errors import Error
from pear_runtime.fixtures.inputs import fact,save
from pear_runtime.fixtures import release_controls as checker


class ReleaseInputsTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.output=self.root/'owned';self.output.mkdir();self.oproot=self.root/'worker';self.oproot.mkdir()
        for name in ('runtime','assembly','descriptor'):save(self.root/(name+'.json'),{'input':name})
        self.runtime=fact(self.root/'runtime.json');self.assembly=fact(self.root/'assembly.json');self.descriptor=fact(self.root/'descriptor.json')
    def prepare(self,case_id='api',scope='development_native_fixture_execution',status='passed',released=True):
        native=scope=='development_native_fixture_execution'
        self.case_path=(self.output/case_id/'case.json' if native else
                        self.output/('run/case.json' if case_id=='native-pairing' else 'case.json'))
        self.case_path.parent.mkdir(exist_ok=True)
        processes={role:{'identity':{'pid':100+i,'ppid':50,'start_sec':200,'start_usec':i},'fork_seen':False}
                   for i,role in enumerate(('loader','server','sentinel'))}
        bootstrap=native and case_id in checker.NATIVE_BOOTSTRAP
        self.case={'schema_version':1,'processes':processes}
        if not bootstrap:self.case['registrations']=[processes['loader']]
        if native:self.case.update(record_kind='wine_bootstrap_case' if bootstrap else 'wine_api_case',case={'id':case_id})
        elif case_id=='native-pairing':self.case.update(record_kind='dxmt_pairing_case',case={'id':'metal'})
        else:
            self.case.pop('schema_version')
            self.case.update(kind='translated_graphics_observation',scope='translated_graphics',fixture_id=case_id,
                             runtime_sha256=self.runtime['sha256'],fixture_sha256='0'*64)
        self.request={'schema_version':1,'scope':'development_native_fixture_request' if native else 'development_control_verification',
            'descriptor_ref':self.descriptor,'output_name':'owned',('fixture' if native else 'case_id'):case_id}
        save(self.root/'worker-request.json',self.request)
        self.operation={'scope':scope,'schema_version':1,'status':status,'released':released,'operation_id':'one',
            'request_ref':fact(self.root/'worker-request.json'),
            'lock':{'released':released,'path':str(checker.release.GLOBAL_LOCK)},
            'worker':{'pid':50,'process_group':50},'case_id':case_id,'runtime_ref':self.runtime,'assembly_operation_ref':self.assembly,
            'plan':{'schema_version':1,'scope':'development_native_fixture_plan' if native else 'development_cpu_plan' if scope=='development_cpu_operation' else 'development_control_plan','output':str(self.output),'operation_output':str(self.oproot),'descriptor_ref':self.descriptor,
                    'runtime_ref':self.runtime,'assembly_operation_ref':self.assembly,'case_id':case_id,
                    'request_ref':fact(self.root/'worker-request.json')}}
        self.control={'schema_version':1,'scope':'development_native_fixture_run' if native else 'development_runtime_controls_run',
            'case_id':case_id,'runtime_ref':self.runtime,'context_ref':self.descriptor,'fixture_ref':{'sha256':'0'*64},
            'assembly_operation_ref':self.assembly,'operation_ref':self.assembly,
            'execution_operation':{'path':str(self.oproot/'operation.json'),'operation_id':'one'}}
        return self.refresh()
    def refresh(self):
        save(self.case_path,self.case);ref=fact(self.case_path);self.operation['case_ref']=self.control['case_ref']=ref
        save(self.output/'control.json',self.control);save(self.oproot/'operation.json',self.operation)
        save(self.root/'release-request.json',{'schema_version':1,'scope':'development_control_release',
                                             'operations':[fact(self.oproot/'operation.json')]})
        return fact(self.root/'release-request.json')
    def test_native_api_collects_original_direct_and_registered_identities(self):
        value=checker.inputs(self.prepare());self.assertEqual(len(value['identities']),3)
        self.assertEqual(value['workers'],[50]);self.assertEqual(len(value['groups']),4)
    def test_bootstrap_without_registration_is_exact_direct_scope(self):
        value=checker.inputs(self.prepare('bootstrap-timeout'));self.assertEqual(len(value['identities']),3)
    def test_failed_native_attempt_is_retained_as_failed(self):
        value=checker.inputs(self.prepare(status='failed'));self.assertEqual(value['operations'][0]['original_status'],'failed')
    def test_graphics_and_native_pairing_schemas(self):
        for case_id in ('device','native-pairing','presentation-original','presentation-frames'):
            value=checker.inputs(self.prepare(case_id,'development_controls_operation'))
            self.assertEqual(value['operations'][0]['case_id'],case_id)
    def test_released_numeric_one_refused(self):
        with self.assertRaisesRegex(Error,'release_operation_incomplete'):checker.inputs(self.prepare(released=1))
    def test_wrong_worker_parent_refused(self):
        self.prepare();self.case['processes']['loader']['identity']['ppid']=999
        with self.assertRaisesRegex(Error,'release_worker_parent'):checker.inputs(self.refresh())
    def test_bootstrap_unobserved_fork_refused(self):
        self.prepare('bootstrap');self.case['processes']['loader']['fork_seen']=True
        with self.assertRaisesRegex(Error,'release_bootstrap_fork_evidence'):checker.inputs(self.refresh())
    def test_case_identity_swap_refused(self):
        self.prepare();self.case['case']['id']='window'
        with self.assertRaisesRegex(Error,'release_case_binding'):checker.inputs(self.refresh())
    def test_wrong_assembly_ref_refused(self):
        self.prepare();self.control['assembly_operation_ref']=self.runtime
        with self.assertRaisesRegex(Error,'release_native_binding'):checker.inputs(self.refresh())
    def test_unavailable_probe_is_unknown_never_pass(self):
        ref=self.prepare()
        with patch.object(checker.release,'DarwinProbe',side_effect=Error('unavailable')):
            result=checker.inspect(ref)
        self.assertEqual(result['status'],'unknown');self.assertIs(result['resource_release_passed'],False)
    def test_all_control_join_versions_are_exact_integers(self):
        scopes=[('api','development_native_fixture_execution'),
                ('bootstrap','development_native_fixture_execution'),
                ('device','development_controls_operation'),
                ('native-pairing','development_controls_operation')]
        for case_id,scope in scopes:
            for version in (None,2,True):
                with self.subTest(case_id=case_id,version=version):
                    self.prepare(case_id,scope)
                    if version is None:self.control.pop('schema_version')
                    else:self.control['schema_version']=version
                    with self.assertRaisesRegex(Error,'release_control_binding'):checker.inputs(self.refresh())
    def test_reuses_original_verdict_for_pid_birth_and_groups(self):
        self.assertEqual(checker.release.verdict.__module__,'pear_runtime.fixtures.release')

class CPUReleaseTests(ReleaseInputsTests):
    def cpu(self, case_id='zero-extension', status='passed'):
        save(self.root/'runtime.json',{'fixtures':{case_id:{'sha256':'0'*64}}})
        self.runtime=fact(self.root/'runtime.json')
        save(self.root/'candidate.json',{'schema_version':1,'scope':'redistributable_runtime_fixtures',
            'runtime_ref':self.runtime,'operation_ref':self.assembly})
        save(self.root/'pack.json',{'scope':'retained_cpu_inputs'})
        self.pack=fact(self.root/'pack.json')
        save(self.root/'descriptor.json',{'schema_version':1,'scope':'development_cpu_controls',
            'candidate_context_ref':fact(self.root/'candidate.json'),'input_pack_ref':self.pack})
        self.descriptor=fact(self.root/'descriptor.json')
        self.prepare(case_id,'development_cpu_operation',status)
        self.request['scope']='development_cpu_verification'
        save(self.root/'worker-request.json',self.request)
        self.operation['request_ref']=self.operation['plan']['request_ref']=fact(self.root/'worker-request.json')
        self.control.update(scope='development_cpu_control_run',input_pack_ref=self.pack)
        self.case.update(schema_version=1,kind='development_cpu_observation',scope='development_cpu_fixture_v1',
                         context_ref=self.descriptor,runtime_ref=self.runtime)
        return self.refresh()
    def test_cpu_collects_exact_owned_processes(self):
        value=checker.inputs(self.cpu());self.assertEqual(len(value['identities']),3)
        self.assertEqual(value['operations'][0]['case_id'],'zero-extension')
    def test_cpu_failure_is_not_upgraded(self):
        value=checker.inputs(self.cpu('ordering','failed'))
        self.assertEqual(value['operations'][0]['original_status'],'failed')
    def test_cpu_wrong_fixture_digest_refused(self):
        self.cpu();self.case['fixture_sha256']='1'*64
        with self.assertRaisesRegex(Error,'release_cpu_case_binding'):checker.inputs(self.refresh())
    def test_cpu_other_context_refused(self):
        self.cpu();self.case['context_ref']=self.runtime
        with self.assertRaisesRegex(Error,'release_cpu_case_binding'):checker.inputs(self.refresh())
    def test_cpu_other_input_pack_refused(self):
        self.cpu();self.control['input_pack_ref']=self.runtime
        with self.assertRaisesRegex(Error,'release_cpu_binding'):checker.inputs(self.refresh())
    def test_cpu_unknown_case_refused(self):
        with self.assertRaisesRegex(Error,'release_cpu_binding'):checker.inputs(self.cpu('game'))
    def test_cpu_operation_version_refused(self):
        for version in (2,True):
            self.cpu();self.operation['schema_version']=version
            with self.assertRaisesRegex(Error,'release_operation_incomplete'):checker.inputs(self.refresh())
    def test_cpu_plan_scope_refused(self):
        self.cpu();self.operation['plan']['scope']='unrelated_plan'
        with self.assertRaisesRegex(Error,'release_plan_version_scope'):checker.inputs(self.refresh())
    def test_cpu_plan_version_refused(self):
        self.cpu();self.operation['plan']['schema_version']=True
        with self.assertRaisesRegex(Error,'release_plan_version_scope'):checker.inputs(self.refresh())
    def test_cpu_all_runner_ids_admitted(self):
        from pear_runtime.fixtures.controls.cpu_context import CASES
        self.assertEqual(checker.CPU,set(CASES))
        for case in CASES:
            self.assertEqual(checker.inputs(self.cpu(case))['operations'][0]['case_id'],case)
    def test_cpu_control_version_missing_other_or_bool_refused(self):
        for version in (None,2,True):
            with self.subTest(version=version):
                self.cpu()
                if version is None:self.control.pop('schema_version')
                else:self.control['schema_version']=version
                with self.assertRaisesRegex(Error,'release_control_binding'):checker.inputs(self.refresh())
    def test_cpu_descriptor_and_candidate_versions_exact(self):
        for target in ('descriptor','candidate'):
            for version in (None,2,True):
                with self.subTest(target=target,version=version):
                    self.cpu()
                    path=self.root/(target+'.json');value=checker.core.read_ref(fact(path))
                    if version is None:value.pop('schema_version')
                    else:value['schema_version']=version
                    save(path,value)
                    if target=='candidate':
                        path=self.root/'descriptor.json';value=checker.core.read_ref(fact(path))
                        value['candidate_context_ref']=fact(self.root/'candidate.json');save(path,value)
                    self.descriptor=fact(self.root/'descriptor.json')
                    self.operation['plan']['descriptor_ref']=self.control['context_ref']=self.case['context_ref']=self.request['descriptor_ref']=self.descriptor
                    save(self.root/'worker-request.json',self.request)
                    self.operation['request_ref']=self.operation['plan']['request_ref']=fact(self.root/'worker-request.json')
                    code='release_cpu_descriptor' if target=='descriptor' else 'release_cpu_candidate'
                    with self.assertRaisesRegex(Error,code):checker.inputs(self.refresh())
    def test_cpu_missing_registration_refused(self):
        self.cpu();self.case['registrations']=[]
        with self.assertRaisesRegex(Error,'release_process_evidence_incomplete'):checker.inputs(self.refresh())

if __name__=='__main__':unittest.main()
