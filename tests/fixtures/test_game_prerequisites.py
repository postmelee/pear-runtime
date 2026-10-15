# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact fifteen-control coverage and current resource checks on synthetic records."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import game_prerequisites as subject


class PrerequisiteTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.runtime=self.write('runtime.json',{'synthetic':'candidate'})
        self.assembly=self.write('assembly.json',{'synthetic':'completed operation'})
        self.control=dict(schema_version=1,scope='development_game_control_selection',runtime_ref=self.runtime,
            assembly_operation_ref=self.assembly,fixtures={},native={},graphics={},contextual_evidence={})
        for group,names in (('fixtures',subject.NAMES),('native',subject.NATIVE),('graphics',('presentation-frames',))):
            for name in names:self.control[group][name]=self.pair(group,name)
        for key in subject.CONTEXT:self.control['contextual_evidence'][key]=self.write('context-'+key,{'bounded':True})
        self.control_ref=self.write('selection.json',self.control)
        checkers=[self.write('checker-'+str(i),{'source':i}) for i in range(4)]
        groups={'native_and_frames':[self.control['native'][name]['operation_ref'] for name in subject.NATIVE[:4]]+
                [self.control['graphics']['presentation-frames']['operation_ref']],
                'native_bootstrap':[self.control['native'][name]['operation_ref'] for name in subject.NATIVE[4:]],
                'fixtures':[row['operation_ref'] for row in self.control['fixtures'].values()]}
        self.releases=dict(schema_version=1,scope='development_game_predecessor_release_selection',
            control_selection_ref=self.control_ref,groups={},checker_sources=[])
        for group,operations in groups.items():
            fixture=group=='fixtures';request=self.write(group+'-request.json',dict(schema_version=1,
                scope='development_fixture_release' if fixture else 'development_control_release',operations=operations))
            record=dict(schema_version=1,scope='development_fixture_independent_release' if fixture else 'development_control_independent_release',
                status='passed',resource_release_passed=True,root_holds_outer_lock=False,request_ref=request,
                lock={'available':True,'immediately_released':True},observation_count=2,runtime_processes_signaled=False,
                runtime_execution_performed=False,handles=[],original_group_members_present=[],original_identities_present=[],
                uncertain_observations=[],operations=[dict(operation_ref=r,original_status='passed') for r in operations])
            if fixture:record.update(checker_ref=checkers[0],provenance_ref=checkers[1])
            else:record['checker_refs']=checkers
            self.releases['groups'][group]=dict(request_ref=request,release_ref=self.write(group+'-release.json',record))
        for i,old in enumerate(checkers):
            path=self.root/f'preserved-{i}';path.write_bytes(Path(old['path']).read_bytes())
            self.releases['checker_sources'].append(dict(recorded_ref=old,preserved_ref=build.fact(path)))
        self.release_ref=self.write('release-selection.json',self.releases)

    def write(self,name,value):
        path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);build.write_json(path,value);return build.fact(path)

    def pair(self,group,name):
        out=self.root/group/name;oproot=out.with_name(name+'.operation');out.mkdir(parents=True);oproot.mkdir()
        desc=self.write(group+'/'+name+'/descriptor.json',{'runtime_ref':self.runtime,'operation_ref':self.assembly})
        rscope={'fixtures':'development_fixture_verification','native':'development_native_fixture_request',
                'graphics':'development_control_verification'}[group]
        req=dict(schema_version=1,scope=rscope,descriptor_ref=desc,output_name=name)
        req['case_id' if group=='graphics' else 'fixture']=name
        request=self.write(group+'/'+name+'/request.json',req)
        case=self.write(group+'/'+name+'/case.json',{'synthetic':'case'})
        pscope={'fixtures':'development_fixture_plan','native':'development_native_fixture_plan','graphics':'development_control_plan'}[group]
        plan=dict(schema_version=1,scope=pscope,request_ref=request,descriptor_ref=desc,runtime_ref=self.runtime,
                  output=str(out),operation_output=str(oproot))
        plan['case_id' if group=='graphics' else 'fixture']=name
        assessment=dict(passed=True,runtime_ref=self.runtime)
        if group=='fixtures':assessment.update(fixture=name,scope='isolated redistributable development runtime fixture',run_ref=case)
        elif group=='native':assessment.update(schema_version=1,scope='development_native_fixture_assessment',case_id=name,
            assembly_operation_ref=self.assembly,context_ref=desc,execution_operation={'path':str(oproot/'operation.json'),'operation_id':name},case_ref=case)
        else:
            plan['assembly_operation_ref']=self.assembly
            control=self.write(group+'/'+name+'/control.json',dict(runtime_ref=self.runtime,operation_ref=self.assembly,context_ref=desc,case_ref=case))
            assessment.update(scope='development_runtime_control_assessment',case_id=name,operation_ref=self.assembly,
                              context_ref=desc,case_ref=case,control_ref=control)
        aref=self.write(group+'/'+name+'/assessment.json',assessment)
        op=dict(schema_version=1,scope={'fixtures':'development_fixture_operation','native':'development_native_fixture_execution',
            'graphics':'development_controls_operation'}[group],status='passed',game_qualified=False,runtime_execution_performed=True,
            lock={'released':True},cleanup={'complete':True},sentinel_survived=True,plan=plan,request_ref=request,case_ref=case)
        op['assessment_ref' if group=='native' else 'result_ref']=aref
        if group=='native':op.update(released=True,runtime_ref=self.runtime,assembly_operation_ref=self.assembly,case_id=name,operation_id=name)
        build.write_json(oproot/'operation.json',op)
        return dict(operation_ref=build.fact(oproot/'operation.json'),assessment_ref=aref)

    def operations(self):return subject.selection(self.control_ref,self.runtime,self.assembly)[1]

    def test_exact_fifteen_successes_and_three_releases_are_static_inputs(self):
        with patch('subprocess.run',side_effect=AssertionError('static admission launches nothing')):
            operations=self.operations();rows=subject.predecessors(self.release_ref,self.control_ref,operations)
        self.assertEqual(sum(len(v) for v in operations.values()),15);self.assertEqual(len(rows),3)

    def test_missing_extra_duplicate_or_other_candidate_control_is_refused(self):
        for kind in ('missing','extra','duplicate','candidate'):
            value=copy.deepcopy(self.control)
            if kind=='missing':value['fixtures'].pop(subject.NAMES[0])
            elif kind=='extra':value['graphics']['device']=value['graphics']['presentation-frames']
            elif kind=='duplicate':value['fixtures'][subject.NAMES[0]]=value['fixtures'][subject.NAMES[1]]
            else:value['runtime_ref']=self.assembly
            ref=self.write('bad-selection.json',value)
            with self.subTest(kind=kind),self.assertRaises(Error):subject.selection(ref,self.runtime,self.assembly)

    def test_resealed_failed_or_unreleased_operation_is_not_a_completed_control(self):
        for key,value in (('status','failed'),('schema_version',True),('runtime_execution_performed',False),('lock',{'released':False})):
            control=copy.deepcopy(self.control);pair=control['fixtures'][subject.NAMES[0]]
            op=build.load(Path(pair['operation_ref']['path']));op[key]=value
            ref=self.write('changed-operation.json',op);pair['operation_ref']=ref
            cref=self.write('changed-control.json',control)
            with self.subTest(key=key),self.assertRaises(Error):subject.selection(cref,self.runtime,self.assembly)

    def test_release_coverage_and_original_status_cannot_be_resealed_as_pass(self):
        operations=self.operations()
        for change in ('duplicate','failed','unknown','boolean-version'):
            releases=copy.deepcopy(self.releases);row=releases['groups']['fixtures'];record=build.load(Path(row['release_ref']['path']))
            if change=='duplicate':record['operations'][0]=record['operations'][1]
            elif change=='failed':record['operations'][0]['original_status']='failed'
            elif change=='unknown':record['uncertain_observations']=[{'unavailable':True}]
            else:record['schema_version']=True
            row['release_ref']=self.write('changed-release.json',record)
            ref=self.write('changed-releases.json',releases)
            with self.subTest(change=change),self.assertRaises(Error):subject.predecessors(ref,self.control_ref,operations)

    def test_old_checker_current_path_can_change_only_with_exact_retained_bytes(self):
        operations=self.operations();old=Path(self.releases['checker_sources'][0]['recorded_ref']['path'])
        old.write_bytes(b'new current implementation')
        subject.predecessors(self.release_ref,self.control_ref,operations)
        preserved=Path(self.releases['checker_sources'][0]['preserved_ref']['path']);preserved.write_bytes(b'changed')
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):
            subject.predecessors(self.release_ref,self.control_ref,operations)

    def test_current_probe_uses_real_outer_lease_without_probe_reacquisition(self):
        output=self.root/'operation';output.mkdir();owner=SimpleNamespace(output=self.root/'run',operation_id='current',
            operation_output=output,request_ref={},context=SimpleNamespace(value={}),assert_current=Mock())
        plan=dict(refs=[],roots=[],identities=[{'pid':42,'start_sec':10,'start_usec':0}],workers=[],groups={42:{}},operations=[])
        before=dict(processes={},groups={42:[]},provider_ref={});after=copy.deepcopy(before)
        after['processes'][42]={'pid':42,'start_sec':10,'start_usec':0}
        probe=Mock();probe.observe.side_effect=[before,after]
        with patch.object(subject,'admit',return_value=({},[])),patch.object(subject,'resource_plan',return_value=plan),\
             patch.object(subject.release,'DarwinProbe',return_value=probe),\
             patch.object(subject.release,'handles',return_value={'handles':[],'tool_ref':{}}),\
             patch.object(subject.release,'lock_probe',side_effect=AssertionError('no second lease probe')):
            with self.assertRaisesRegex(Error,'game_predecessor_resources_unavailable'):subject.observe_predecessors(owner)
        record=build.load(output/'predecessor-resources.json')
        self.assertEqual([r['status'] for r in record['observations']],['passed','failed'])
        self.assertTrue(record['root_holds_outer_lock']);self.assertFalse(record['independent_post_run_release'])


if __name__=='__main__':unittest.main()
