# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Recorded game companions and independent read-only resource release.

The original observer, process/group census, handle query and lock probe remain
single-owned in release. No runtime process is launched, signaled or reaped here.
"""
import argparse
import json
from pathlib import Path
import re
import sys

from pear_runtime import build
from pear_runtime.assembly import core
from pear_runtime.assembly._common import encoded
from pear_runtime.errors import need
from . import release

RECORDS=('companion-result.json','hud-result.json','witness-config.json','witness-ready.json',
         'witness-final.json','hud-binding.json')
CHILD_FIELDS={'identity','exit_code','reaped','allowed_paths','fork_seen','setup_error','emergency_cleanup'}


def capture_companions(adapter,output):
    """Read the original retained Child maps after cleanup; never infer identities."""
    output=Path(output);root=output/'play'
    need(output.is_absolute() and output.is_dir() and output.resolve(strict=True)==output,'game_companion_output')
    if not root.exists():root.mkdir(mode=0o700)
    need(root.resolve(strict=True)==root and not root.is_symlink(),'game_companion_output')
    sessions={}
    for name,attribute,destination in (('helpers','helpers',root),('hud','hud_helpers',root/'hud')):
        session=getattr(adapter,attribute,None);children={}
        if session is not None:
            need(Path(session.output)==destination and type(session.children) is dict and len(session.children)<=98,
                 'game_companion_session')
            for role,child in session.children.items():
                need(type(role) is str and role==child.role,'game_companion_role')
                children[role]={field:(sorted(child.allowed_paths) if field=='allowed_paths' else getattr(child,field))
                                for field in CHILD_FIELDS}
        sessions[name]=dict(present=session is not None,output=str(destination),processes=children)
    refs={}
    for name in RECORDS:
        path=root/name
        if path.exists():refs[name]=build.fact(core.checked_ref(build.fact(path),limit=64*1024**2))
    record=dict(schema_version=1,scope='owned_game_companion_processes',output=str(output),
        operation_id=getattr(adapter,'operation',None),sessions=sessions,record_refs=refs,
        producer_ref=build.fact(Path(__file__).resolve()),identity_source='original retained Child.identity',
        observation_performed=False)
    path=root/'owned-companion-processes.json'
    if path.exists():need(core.read_ref(build.fact(path))==record,'game_companion_evidence_changed')
    else:build.write_json(path,record)
    return build.fact(path)


def _companions(ref,output,operation_id,worker,refs,identities,groups):
    need(ref['path']==str(output/'play/owned-companion-processes.json'),'game_release_companion_path')
    value=core.read_ref(ref);refs.append(ref)
    need(type(value.get('schema_version')) is int and value['schema_version']==1 and
         value.get('scope')=='owned_game_companion_processes' and value['output']==str(output) and
         value['operation_id']==operation_id and type(value['sessions']) is dict and
         set(value['sessions'])=={'helpers','hud'} and type(value['record_refs']) is dict,
         'game_release_companion_binding')
    for family,row in value['sessions'].items():
        expected=output/'play' if family=='helpers' else output/'play/hud'
        need(set(row)=={'present','output','processes'} and type(row['present']) is bool and
             row['output']==str(expected) and type(row['processes']) is dict and len(row['processes'])<=98 and
             (row['present'] or not row['processes']),'game_release_companion_session')
        for role,child in row['processes'].items():
            need((family=='helpers' and (role=='owner-witness' or re.fullmatch(r'capture-\d{1,3}',role))) or
                 (family=='hud' and role=='hud-log'),'game_release_companion_role')
            need(type(child) is dict and set(child)==CHILD_FIELDS,'game_release_companion_child')
            current=release.identity(child['identity'])
            need(child['identity']['ppid']==worker,'release_worker_parent')
            need(groups.setdefault(current['pid'],current)==current,'release_group_identity_conflict')
            identities[(current['pid'],current['start_sec'],current['start_usec'])]=current
    need(set(value['record_refs'])<=set(RECORDS),'game_release_companion_records')
    for name,row in value['record_refs'].items():
        need(row['path']==str(output/'play'/name),'game_release_companion_record_path')
        core.checked_ref(row,limit=64*1024**2);refs.append(row)
    helpers=value['sessions']['helpers']['processes'];hud=value['sessions']['hud']['processes']
    if 'owner-witness' in helpers:
        need('witness-config.json' in value['record_refs'],'game_release_witness_config')
        config=core.read_ref(value['record_refs']['witness-config.json'])
        need(config['run']==str(output) and config['operation_id']==operation_id and
             config['owner_identity']['pid']==worker,'game_release_witness_binding')
        for name in ('witness-ready.json','witness-final.json'):
            if name in value['record_refs']:
                record=core.read_ref(value['record_refs'][name])
                need(record['config']==value['record_refs']['witness-config.json'] and
                     record['watcher_identity']==helpers['owner-witness']['identity'],
                     'game_release_witness_binding')
    if 'hud-binding.json' in value['record_refs']:
        row=core.read_ref(value['record_refs']['hud-binding.json'])
        need('hud-log' in hud and row['collector_identity']==hud['hud-log']['identity'],'game_release_hud_binding')
    return value


def inputs(request_ref):
    request=core.read_ref(request_ref)
    need(type(request) is dict and set(request)==release.FIELDS and type(request['schema_version']) is int and
         request['schema_version']==1 and request['scope']=='development_game_release' and
         type(request['operations']) is list and 1<=len(request['operations'])<=16,'game_release_request')
    need(len({r['path'] for r in request['operations']})==len(request['operations']),'release_duplicate_operation')
    refs=[request_ref];roots=[];identities={};workers=set();groups={};statuses=[]
    for ref in request['operations']:
        op=core.read_ref(ref);refs.append(ref)
        need(type(op.get('schema_version')) is int and op['schema_version']==1 and
             op.get('scope')=='development_game_operation' and op['status'] in ('passed','failed') and
             op['lock']['released'] is True and op['lock']['path']==str(release.GLOBAL_LOCK),
             'release_operation_incomplete')
        worker=op['worker'];pid=worker['pid']
        need(type(pid) is int and pid>1 and worker['process_group']==pid,'release_worker_identity')
        workers.add(pid);groups.setdefault(pid,None);plan=op['plan']
        need(type(plan.get('schema_version')) is int and plan['schema_version']==1 and plan['scope']=='development_game_plan',
             'game_release_plan')
        output=Path(plan['output']);oproot=Path(plan['operation_output'])
        need(output.is_absolute() and output.parent.resolve(strict=True)==output.parent and
             (not output.exists() or output.is_dir() and output.resolve(strict=True)==output) and
             oproot.is_absolute() and oproot.resolve(strict=True)==oproot and oproot.is_dir() and
             ref['path']==str(oproot/'operation.json'),'release_output_binding')
        roots.extend((output,oproot));request_value=core.read_ref(op['request_ref']);refs.append(op['request_ref'])
        need(type(request_value.get('schema_version')) is int and request_value['schema_version']==1 and
             request_value['scope']=='development_game_observation' and request_value['descriptor_ref']==plan['descriptor_ref'] and
             request_value['output_name']==output.name and plan['request_ref']==op['request_ref'],'release_request_binding')
        descriptor=core.read_ref(plan['descriptor_ref']);refs.append(plan['descriptor_ref'])
        need(descriptor['runtime_ref']==plan['runtime_ref'] and descriptor['operation_ref']==plan['assembly_operation_ref'],
             'game_release_candidate')
        for row in (plan['runtime_ref'],plan['assembly_operation_ref']):core.checked_ref(row);refs.append(row)
        case_ref=op.get('case_ref')
        if case_ref is None:
            need(op['runtime_execution_attempted'] is False and op['runtime_execution_performed'] is False,
                 'game_release_process_evidence_unavailable')
        else:
            need(case_ref['path']==str(output/'case.json'),'release_case_unavailable')
            case=core.read_ref(case_ref,limit=64*1024**2);refs.append(case_ref)
            need(type(case.get('schema_version')) is int and case['schema_version']==1 and
                 case['scope']=='development_direct_game_v1' and case['game_context_ref']==plan['descriptor_ref'] and
                 case['runtime_ref']==plan['runtime_ref'] and case['execution_operation']=={
                     'path':ref['path'],'operation_id':op['operation_id']} and
                 type(case['processes']) is dict and set(case['processes'])<=release.ROLES and
                 type(case['registrations']) is list,'game_release_case')
            for child in case['processes'].values():
                current=release.identity(child['identity']);need(child['identity']['ppid']==pid,'release_worker_parent')
                need(groups.setdefault(current['pid'],current)==current,'release_group_identity_conflict')
            for child in [*case['processes'].values(),*case['registrations']]:
                current=release.identity(child['identity']);identities[(current['pid'],current['start_sec'],current['start_usec'])]=current
            companion_ref=op.get('companion_processes_ref')
            need(companion_ref==case.get('companion_processes_ref') and type(companion_ref) is dict,
                 'game_release_companion_unavailable')
            _companions(companion_ref,output,op['operation_id'],pid,refs,identities,groups)
        statuses.append(dict(operation_ref=ref,original_status=op['status'],case_ref=case_ref))
    return dict(refs=refs,roots=sorted(set(roots)),identities=list(identities.values()),workers=sorted(workers),
                groups=groups,operations=statuses)


def inspect(request_ref):
    record=dict(schema_version=1,scope='development_game_independent_release',request_ref=request_ref,
        status='unknown',resource_release_passed=False,game_qualified=False,runtime_processes_signaled=False,
        runtime_execution_performed=False,checked_at=build.point())
    sources=[build.fact(Path(__file__).resolve()),build.fact(Path(release.__file__).resolve()),
             build.fact(Path(__file__).resolve().parents[2]/'provenance/fixture-game-seam.json')]
    record['checker_refs']=sources
    try:
        plan=inputs(request_ref);record.update(operations=plan['operations'],checked_identities=plan['identities'],
            worker_pids=plan['workers'],checked_group_ids=sorted(plan['groups']),handle_roots=[str(p) for p in plan['roots']])
        probe=release.DarwinProbe();before=probe.observe(plan);handles=release.handles(plan['roots'])
        lock=release.lock_probe();after=probe.observe(plan)
        for observed in (before,after):
            result=release.verdict(plan,observed,handles,lock)
            if result['status']!='passed':break
        for ref in [*plan['refs'],*sources]:core.checked_ref(ref,limit=64*1024**2)
        record.update(result,provider_ref=before['provider_ref'],handle_tool_ref=handles['tool_ref'],
                      observation_count=2,root_holds_outer_lock=False)
    except (Exception,KeyboardInterrupt) as failure:
        record.update(status='unknown',resource_release_passed=False,error=core.failure_details(failure))
    return record


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        output=args.output
        need(output.is_absolute() and output.parent.resolve(strict=True)==output.parent and
             not output.exists() and not output.is_symlink(),'release_output_fresh')
        result=inspect(build.fact(args.request))
        with output.open('x') as stream:stream.write(json.dumps(result,indent=2,sort_keys=True)+'\n')
        print(json.dumps(dict(status=result['status'],resource_release_passed=result['resource_release_passed'],
                              receipt=build.fact(output))))
        return 0 if result['resource_release_passed'] else 1
    except (Exception,KeyboardInterrupt) as failure:
        print(json.dumps(dict(status='unknown',resource_release_passed=False,error=core.failure_details(failure))),file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
