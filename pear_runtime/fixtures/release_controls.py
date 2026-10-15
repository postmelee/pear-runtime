# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent post-worker release for exact native, graphics and CPU control schemas.

Only schema admission is extended. The reviewed libproc identity/group queries,
handle census, noncreating flock probe and verdict remain the original checker.
No workload is launched, signaled, reaped, truncated or deleted.
"""
import argparse
import json
from pathlib import Path
import sys

from pear_runtime import build
from pear_runtime.assembly import core
from pear_runtime.errors import need
from . import release

NATIVE_API={'api','abi','threads','window'}
NATIVE_BOOTSTRAP={'bootstrap','bootstrap-timeout','wrong-prefix-server'}
GRAPHICS={'device','native-pairing','presentation-original','presentation-frames'}
CPU={'zero-extension','carry-widths','xor-flags','zero-shift-flags','cmpxchg-eax','xadd-widths',
     'packed-float-add','scalar-double-add','float-to-integer','absolute-displacement',
     'avx-lane-preservation','api-callback','abi-state','tls-thread','seh-unwind','suspend-context',
     'code-invalidation','guest-fault-guard','configured-memory','ordering'}


def inputs(request_ref):
    request=core.read_ref(request_ref)
    need(type(request) is dict and set(request)==release.FIELDS and
         type(request['schema_version']) is int and request['schema_version']==1 and
         request['scope']=='development_control_release' and type(request['operations']) is list and
         1<=len(request['operations'])<=32,'control_release_request')
    need(len({row['path'] for row in request['operations']})==len(request['operations']),
         'release_duplicate_operation')
    refs=[request_ref];roots=[];identities={};workers=set();groups={};statuses=[]
    for ref in request['operations']:
        operation=core.read_ref(ref);refs.append(ref);scope=operation['scope']
        need(type(operation.get('schema_version')) is int and operation['schema_version']==1 and
             scope in ('development_native_fixture_execution','development_controls_operation','development_cpu_operation') and
             operation['status'] in ('passed','failed') and operation['lock']['released'] is True and
             operation['lock']['path']==str(release.GLOBAL_LOCK),'release_operation_incomplete')
        if scope=='development_native_fixture_execution':
            need(operation.get('released') is True,'release_operation_incomplete')
        plan=operation['plan']
        expected_plan={'development_native_fixture_execution':'development_native_fixture_plan',
                       'development_controls_operation':'development_control_plan',
                       'development_cpu_operation':'development_cpu_plan'}[scope]
        need(type(plan.get('schema_version')) is int and plan['schema_version']==1 and
             plan.get('scope')==expected_plan,'release_plan_version_scope')
        output=Path(plan['output']);oproot=Path(plan['operation_output'])
        need(output.is_absolute() and output.resolve(strict=True)==output and output.is_dir() and
             oproot.is_absolute() and oproot.resolve(strict=True)==oproot and oproot.is_dir() and
             ref['path']==str(oproot/'operation.json'),'release_output_binding')
        request_value=core.read_ref(operation['request_ref']);refs.append(operation['request_ref'])
        need(request_value['descriptor_ref']==plan['descriptor_ref'],'release_descriptor_binding')
        runtime_ref=plan['runtime_ref']
        cpu=scope=='development_cpu_operation'
        if cpu:
            descriptor=core.read_ref(plan['descriptor_ref'])
            need(type(descriptor.get('schema_version')) is int and descriptor['schema_version']==1 and
                 descriptor.get('scope')=='development_cpu_controls','release_cpu_descriptor')
            base=core.read_ref(descriptor['candidate_context_ref']);refs.append(descriptor['candidate_context_ref'])
            need(type(base.get('schema_version')) is int and base['schema_version']==1 and
                 base.get('scope')=='redistributable_runtime_fixtures' and base['runtime_ref']==runtime_ref,
                 'release_cpu_candidate')
            assembly_ref=base['operation_ref']
        else:
            assembly_ref=(operation['assembly_operation_ref'] if scope=='development_native_fixture_execution'
                          else plan['assembly_operation_ref'])
        expected_scope=('development_native_fixture_request' if scope=='development_native_fixture_execution'
                        else 'development_cpu_verification' if cpu else 'development_control_verification')
        need(type(request_value.get('schema_version')) is int and request_value['schema_version']==1 and
             request_value['scope']==expected_scope and request_value['output_name']==output.name and
             plan['request_ref']==operation['request_ref'],'release_request_binding')
        core.checked_ref(plan['descriptor_ref']);refs.append(plan['descriptor_ref'])
        core.checked_ref(runtime_ref);core.checked_ref(assembly_ref);refs.extend((runtime_ref,assembly_ref))
        control_ref=build.fact(output/'control.json');control=core.read_ref(control_ref);refs.append(control_ref)
        case_id=operation['case_id'] if scope=='development_native_fixture_execution' else plan['case_id']
        need(type(control.get('schema_version')) is int and control['schema_version']==1 and
             control['case_id']==case_id and control['runtime_ref']==runtime_ref and
             control['context_ref']==plan['descriptor_ref'] and
             request_value['fixture' if scope=='development_native_fixture_execution' else 'case_id']==case_id,
             'release_control_binding')
        if scope=='development_native_fixture_execution':
            need(case_id in NATIVE_API|NATIVE_BOOTSTRAP and operation['runtime_ref']==runtime_ref and
                 operation['assembly_operation_ref']==assembly_ref and
                 control['scope']=='development_native_fixture_run' and
                 control['assembly_operation_ref']==assembly_ref and
                 control['execution_operation']=={'path':ref['path'],'operation_id':operation['operation_id']},
                 'release_native_binding')
            case_path=output/case_id/'case.json'
        elif cpu:
            need(case_id in CPU and control['scope']=='development_cpu_control_run' and
                 control['operation_ref']==assembly_ref and
                 control['input_pack_ref']==descriptor['input_pack_ref'],'release_cpu_binding')
            core.checked_ref(descriptor['input_pack_ref']);refs.append(descriptor['input_pack_ref'])
            selected=core.read_ref(runtime_ref).get('fixtures',{}).get(case_id)
            need(type(selected) is dict and type(selected.get('sha256')) is str,'release_cpu_fixture')
            case_path=output/'case.json'
        else:
            need(case_id in GRAPHICS and control['scope']=='development_runtime_controls_run' and
                 control['operation_ref']==assembly_ref,'release_graphics_binding')
            case_path=output/('run/case.json' if case_id=='native-pairing' else 'case.json')
        case_ref=operation.get('case_ref')
        need(type(case_ref) is dict and case_ref['path']==str(case_path) and control['case_ref']==case_ref,
             'release_case_unavailable')
        case=core.read_ref(case_ref,limit=64*1024**2);refs.append(case_ref)
        need(set(case['processes'])==release.ROLES,'release_process_evidence_incomplete')
        if scope=='development_native_fixture_execution' or case_id=='native-pairing':
            need(type(case.get('schema_version')) is int and case['schema_version']==1,'release_case_version')
        if scope=='development_native_fixture_execution':
            kind='wine_api_case' if case_id in NATIVE_API else 'wine_bootstrap_case'
            need(case.get('record_kind')==kind and case.get('case',{}).get('id')==case_id,'release_case_binding')
        elif cpu:
            need(type(case.get('schema_version')) is int and case['schema_version']==1 and
                 case.get('kind')=='development_cpu_observation' and
                 case.get('scope')=='development_cpu_fixture_v1' and case.get('fixture_id')==case_id and
                 case.get('context_ref')==plan['descriptor_ref'] and case.get('runtime_ref')==runtime_ref and
                 case.get('runtime_sha256')==runtime_ref['sha256'] and
                 case.get('fixture_sha256')==selected['sha256'],'release_cpu_case_binding')
        elif case_id=='native-pairing':
            need(case.get('record_kind')=='dxmt_pairing_case' and case.get('case',{}).get('id')=='metal',
                 'release_case_binding')
        else:need('schema_version' not in case and case.get('kind')=='translated_graphics_observation' and
                  case.get('scope')=='translated_graphics' and case.get('fixture_id')==case_id and
                  case.get('runtime_sha256')==runtime_ref['sha256'] and
                  case.get('fixture_sha256')==control['fixture_ref']['sha256'],'release_case_binding')
        registrations=case.get('registrations')
        if scope=='development_native_fixture_execution' and case_id in NATIVE_BOOTSTRAP:
            need(registrations is None and all(row.get('fork_seen') is False for row in case['processes'].values()),
                 'release_bootstrap_fork_evidence')
            registrations=[]
        else:need(type(registrations) is list and registrations,'release_process_evidence_incomplete')
        worker=operation['worker']
        need(type(worker['pid']) is int and worker['pid']>1 and worker['process_group']==worker['pid'],
             'release_worker_identity')
        workers.add(worker['pid']);groups.setdefault(worker['pid'],None)
        for row in case['processes'].values():
            current=release.identity(row['identity'])
            need(row['identity']['ppid']==worker['pid'],'release_worker_parent')
            prior=groups.setdefault(current['pid'],current);need(prior==current,'release_group_identity_conflict')
        for row in [*case['processes'].values(),*registrations]:
            current=release.identity(row['identity']);identities[(current['pid'],current['start_sec'],current['start_usec'])]=current
        roots.extend((output,oproot));statuses.append({'operation_ref':ref,'original_status':operation['status'],
            'case_ref':case_ref,'control_ref':control_ref,'case_id':case_id})
    return dict(refs=refs,roots=sorted(set(roots)),identities=list(identities.values()),workers=sorted(workers),
                groups=groups,operations=statuses)


def inspect(request_ref):
    record=dict(schema_version=1,scope='development_control_independent_release',request_ref=request_ref,
                status='unknown',resource_release_passed=False,game_qualified=False,
                runtime_processes_signaled=False,runtime_execution_performed=False,checked_at=build.point())
    root=Path(__file__).resolve().parents[2]
    refs=[build.fact(Path(__file__).resolve()),build.fact(Path(release.__file__).resolve()),
          build.fact(root/'provenance/fixture-controls-release-import.json'),
          build.fact(root/'provenance/fixture-release-import.json')]
    record['checker_refs']=refs
    try:
        origin=core.read_ref(refs[2])['origin']
        need(origin['sha256']==refs[1]['sha256'] and origin['size_bytes']==refs[1]['size_bytes'],
             'release_original_checker_changed')
        plan=inputs(request_ref);record.update(operations=plan['operations'],checked_identities=plan['identities'],
             worker_pids=plan['workers'],checked_group_ids=sorted(plan['groups']),handle_roots=[str(p) for p in plan['roots']])
        probe=release.DarwinProbe();observed=probe.observe(plan)
        handle_result=release.handles(plan['roots']);lock=release.lock_probe();final=probe.observe(plan)
        for observation in (observed,final):
            result=release.verdict(plan,observation,handle_result,lock)
            if result['status']!='passed':break
        for ref in [*plan['refs'],*refs]:core.checked_ref(ref)
        record.update(result,provider_ref=observed['provider_ref'],handle_tool_ref=handle_result['tool_ref'],
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
        print(json.dumps(dict(status=result['status'],resource_release_passed=result['resource_release_passed'],receipt=build.fact(output))))
        return 0 if result['resource_release_passed'] else 1
    except (Exception,KeyboardInterrupt) as failure:
        print(json.dumps(dict(status='unknown',resource_release_passed=False,error=core.failure_details(failure))),file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
