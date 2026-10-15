# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact selected development controls and historical/current resource edges."""
from pathlib import Path
from pear_runtime import build
from pear_runtime.assembly import core
from pear_runtime.assembly._common import encoded
from pear_runtime.errors import need
from .context import NAMES
from . import release, release_controls

NATIVE=('api','abi','threads','window','bootstrap','bootstrap-timeout','wrong-prefix-server')
CONTEXT=('evidence_index_ref','bounded_reuse_policy_ref','source_delta_ref',
         'candidate_comparison_ref','cpu_historical_ref','graphics_historical_ref')
FIELDS={'schema_version','scope','runtime_ref','assembly_operation_ref','fixtures','native','graphics','contextual_evidence'}
RELEASE_FIELDS={'schema_version','scope','control_selection_ref','groups','checker_sources'}
GROUPS=('native_and_frames','native_bootstrap','fixtures')


def _shape(value,fields,scope):
    need(type(value) is dict and set(value)==set(fields) and
         type(value.get('schema_version')) is int and value['schema_version']==1 and value['scope']==scope,
         'game_prerequisite_shape')


def _key(ref):
    need(type(ref) is dict and set(ref)=={'path','sha256','size_bytes'} and
         type(ref['path']) is str and Path(ref['path']).is_absolute() and
         type(ref['size_bytes']) is int and 0<=ref['size_bytes']<=64*1024**2 and
         type(ref['sha256']) is str and len(ref['sha256'])==64 and
         all(c in '0123456789abcdef' for c in ref['sha256']),'game_prerequisite_ref')
    return ref['path'],ref['sha256'],ref['size_bytes']


def _pair(pair,name,group,runtime_ref,assembly_ref):
    need(type(pair) is dict and set(pair)=={'operation_ref','assessment_ref'},'game_control_pair')
    opref,aref=pair['operation_ref'],pair['assessment_ref']
    _key(opref);_key(aref);op=core.read_ref(opref);assessment=core.read_ref(aref)
    expected={'fixtures':('development_fixture_operation','development_fixture_plan','development_fixture_verification'),
              'native':('development_native_fixture_execution','development_native_fixture_plan','development_native_fixture_request'),
              'graphics':('development_controls_operation','development_control_plan','development_control_verification')}[group]
    need(type(op.get('schema_version')) is int and op['schema_version']==1 and op.get('scope')==expected[0] and
         op.get('status')=='passed' and op.get('game_qualified') is False and
         op.get('runtime_execution_performed') is True and op.get('lock',{}).get('released') is True and
         op.get('cleanup',{}).get('complete') is True and op.get('sentinel_survived') is True,
         'game_control_operation')
    plan=op['plan'];request=core.read_ref(op['request_ref']);descriptor=core.read_ref(plan['descriptor_ref'])
    need(type(plan.get('schema_version')) is int and plan['schema_version']==1 and plan['scope']==expected[1] and
         plan['runtime_ref']==runtime_ref and plan['request_ref']==op['request_ref'] and
         opref['path']==str(Path(plan['operation_output'])/'operation.json'),'game_control_plan')
    need(type(request.get('schema_version')) is int and request['schema_version']==1 and request['scope']==expected[2] and
         request['descriptor_ref']==plan['descriptor_ref'] and request['output_name']==Path(plan['output']).name,
         'game_control_request')
    need(assessment.get('passed') is True and assessment.get('runtime_ref')==runtime_ref and
         Path(aref['path']).parent==Path(plan['output']),'game_control_assessment')
    field='assessment_ref' if group=='native' else 'result_ref'
    need(op.get(field)==aref,'game_control_final_result')
    if group=='fixtures':
        need(request['fixture']==plan['fixture']==name and descriptor['runtime_ref']==runtime_ref and
             descriptor['operation_ref']==assembly_ref and assessment['fixture']==name and
             assessment['scope']=='isolated redistributable development runtime fixture' and
             assessment['run_ref']==op['case_ref'],'game_fixture_control')
    elif group=='native':
        need(op['released'] is True and op['runtime_ref']==runtime_ref and op['assembly_operation_ref']==assembly_ref and
             request['fixture']==plan['fixture']==op['case_id']==name and
             descriptor['runtime_ref']==runtime_ref and descriptor['operation_ref']==assembly_ref and
             type(assessment.get('schema_version')) is int and assessment['schema_version']==1 and
             assessment['scope']=='development_native_fixture_assessment' and assessment['case_id']==name and
             assessment['assembly_operation_ref']==assembly_ref and assessment['context_ref']==plan['descriptor_ref'] and
             assessment['execution_operation']=={'path':opref['path'],'operation_id':op['operation_id']} and
             assessment['case_ref']==op['case_ref'],'game_native_control')
    else:
        need(plan['assembly_operation_ref']==assembly_ref and plan['case_id']==request['case_id']==name and
             assessment['scope']=='development_runtime_control_assessment' and assessment['case_id']==name and
             assessment['operation_ref']==assembly_ref and assessment['context_ref']==plan['descriptor_ref'] and
             assessment['case_ref']==op['case_ref'],'game_graphics_control')
        control=core.read_ref(assessment['control_ref'])
        need(control['runtime_ref']==runtime_ref and control['operation_ref']==assembly_ref and
             control['context_ref']==plan['descriptor_ref'] and control['case_ref']==op['case_ref'],'game_graphics_control_join')
    core.checked_ref(op['case_ref'],limit=64*1024**2)
    return opref


def selection(ref,runtime_ref,assembly_ref):
    value=core.read_ref(ref);_shape(value,FIELDS,'development_game_control_selection')
    need(value['runtime_ref']==runtime_ref and value['assembly_operation_ref']==assembly_ref,'game_control_candidate')
    expected={'fixtures':NAMES,'native':NATIVE,'graphics':('presentation-frames',)};operations={}
    for group,names in expected.items():
        need(type(value[group]) is dict and set(value[group])==set(names),'game_control_set')
        operations[group]={name:_pair(value[group][name],name,group,runtime_ref,assembly_ref) for name in names}
    rows=[_key(ref) for group in operations.values() for ref in group.values()]
    need(len(rows)==len(set(rows))==15,'game_control_duplicate')
    need(type(value['contextual_evidence']) is dict and set(value['contextual_evidence'])==set(CONTEXT),'game_control_context')
    for row in value['contextual_evidence'].values():core.checked_ref(row,limit=64*1024**2)
    core.checked_ref(runtime_ref);core.checked_ref(assembly_ref);core.checked_ref(ref)
    return value,operations


def predecessors(ref,control_ref,operations):
    value=core.read_ref(ref);_shape(value,RELEASE_FIELDS,'development_game_predecessor_release_selection')
    need(value['control_selection_ref']==control_ref and type(value['groups']) is dict and set(value['groups'])==set(GROUPS),
         'game_release_selection')
    expected={'native_and_frames':{_key(operations['native'][name]) for name in NATIVE[:4]}|
              {_key(operations['graphics']['presentation-frames'])},
              'native_bootstrap':{_key(operations['native'][name]) for name in NATIVE[4:]},
              'fixtures':{_key(row) for row in operations['fixtures'].values()}}
    checkers={};requests=[];all_ops=[]
    for group in GROUPS:
        row=value['groups'][group]
        need(type(row) is dict and set(row)=={'request_ref','release_ref'},'game_release_group')
        record=core.read_ref(row['release_ref']);request=core.read_ref(row['request_ref'])
        fixture=group=='fixtures';scope='development_fixture_independent_release' if fixture else 'development_control_independent_release'
        need(type(record.get('schema_version')) is int and record['schema_version']==1 and record.get('scope')==scope and
             record.get('status')=='passed' and record.get('resource_release_passed') is True and
             record.get('root_holds_outer_lock') is False and record.get('request_ref')==row['request_ref'] and
             record.get('lock')=={'available':True,'immediately_released':True} and
             record.get('observation_count')==2 and type(record['observation_count']) is int and
             record.get('runtime_processes_signaled') is False and record.get('runtime_execution_performed') is False,
             'game_release_record')
        need(all(type(record.get(k)) is list and not record[k] for k in
                 ('handles','original_group_members_present','original_identities_present','uncertain_observations')),
             'game_release_incomplete')
        _shape(request,{'schema_version','scope','operations'},'development_fixture_release' if fixture else 'development_control_release')
        need(type(request['operations']) is list and type(record['operations']) is list,'game_release_operations')
        actual=[_key(r['operation_ref']) for r in record['operations']]
        need(len(actual)==len(set(actual)) and set(actual)==expected[group] and
             actual==[_key(r) for r in request['operations']] and
             all(r['original_status']=='passed' for r in record['operations']),'game_release_coverage')
        all_ops.extend(actual);requests.append((group,row['request_ref']))
        refs=[record['checker_ref'],record['provenance_ref']] if fixture else record['checker_refs']
        need(type(refs) is list and len(refs)==(2 if fixture else 4),'game_release_checkers')
        for item in refs:checkers[_key(item)]=item
    need(len(all_ops)==len(set(all_ops))==15,'game_release_duplicate')
    snapshots=value['checker_sources'];need(type(snapshots) is list and 2<=len(snapshots)<=8,'game_release_sources')
    seen=set()
    for row in snapshots:
        need(type(row) is dict and set(row)=={'recorded_ref','preserved_ref'},'game_release_source')
        old,new=row['recorded_ref'],row['preserved_ref'];key=_key(old);_key(new)
        need(key in checkers and key not in seen and old['sha256']==new['sha256'] and old['size_bytes']==new['size_bytes'],
             'game_release_source_identity')
        core.checked_ref(new);seen.add(key)
    need(seen==set(checkers),'game_release_source_coverage');core.checked_ref(ref)
    return requests


def admit(value):
    control,operations=selection(value['required_controls_ref'],value['runtime_ref'],value['operation_ref'])
    requests=predecessors(value['predecessor_release_ref'],value['required_controls_ref'],operations)
    return control,requests


def resource_plan(requests):
    refs=[];roots=set();identities={};workers=set();groups={};operations=[]
    for group,ref in requests:
        current=(release.inputs if group=='fixtures' else release_controls.inputs)(ref)
        refs.extend(current['refs']);roots.update(current['roots']);workers.update(current['workers']);operations.extend(current['operations'])
        for row in current['identities']:identities[(row['pid'],row['start_sec'],row['start_usec'])]=row
        for pid,row in current['groups'].items():
            need(pid not in groups or groups[pid]==row,'game_predecessor_group_conflict');groups[pid]=row
    return dict(refs=refs,roots=sorted(roots),identities=list(identities.values()),workers=sorted(workers),groups=groups,operations=operations)


def observe_predecessors(operation):
    """Original read-only resources under a real held lease; no lock probe."""
    operation.assert_current(operation.output,operation.operation_id)
    _,requests=admit(operation.context.value);plan=resource_plan(requests)
    probe=release.DarwinProbe();before=probe.observe(plan);handles=release.handles(plan['roots']);after=probe.observe(plan)
    results=[release.resource_verdict(plan,row,handles) for row in (before,after)]
    for ref in plan['refs']:core.checked_ref(ref,limit=64*1024**2)
    operation.assert_current(operation.output,operation.operation_id)
    record=dict(schema_version=1,scope='development_game_predecessor_resources',operation_id=operation.operation_id,
        request_ref=operation.request_ref,observed_at=build.point(),root_holds_outer_lock=True,
        coordination_mode='current_operation_holds_lease',independent_post_run_release=False,
        runtime_processes_signaled=False,observations=results,provider_ref=before['provider_ref'],
        handle_tool_ref=handles['tool_ref'],checker_ref=build.fact(Path(__file__)),
        resource_checker_ref=build.fact(Path(release.__file__)),operations=plan['operations'])
    build.write_json(operation.operation_output/'predecessor-resources.json',record)
    need(all(row['status']=='passed' for row in results),'game_predecessor_resources_unavailable')
    return build.fact(operation.operation_output/'predecessor-resources.json')
