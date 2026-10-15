# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later AND MIT
"""Bind original CPU result oracles to explicit development-run evidence.

The execution assertions are adapted from Pear tools/cpu/compare.py
observe_pear (MIT). D36 diagnostic records keep their actual kind/options.
A completed seven-fixture operation can supply only its exact overlapping row;
this module never launches a process or treats six rows as the full corpus.
"""
from pathlib import Path
import json
import re
import subprocess

from pear_runtime.assembly import core
from pear_runtime.assembly._common import read_relative, encoded
from pear_runtime.errors import need
from pear_runtime.fixtures.inputs import fact, read, digest
from . import corpus

OVERLAP = ('configured-memory', 'tls-thread', 'guest-fault-guard',
           'code-invalidation', 'suspend-context', 'seh-unwind')
OPTIONS = dict(observations='on', trace='historical', signal_resume='off',
               query_observation='off', entry_observation='on',
               link_observation='off', abort_observation='on')
OBSERVATIONS = {key:'1' for key in ('PEAR_PHASE_OBSERVE', 'PEAR_FEX_WAKE_OBSERVE',
    'PEAR_FEX_WRITE_OBSERVE', 'PEAR_FEX_BATCH_OBSERVE', 'PEAR_FEX_OWNER_OBSERVE', 'PEAR_FEX_THREAD_OBSERVE')}
ENVIRONMENT = {**OBSERVATIONS, 'WINEDEBUG':'-all,+loaddll,+seh,+module,+file,+thread',
    'PEAR_FEX_ABORT_OBSERVE':'1', 'PEAR_FEX_ENTRY_OBSERVE':'1', 'PEAR_FEX_LINK_OBSERVE':'0',
    'PEAR_QUERY_OBSERVE':'0', 'PEAR_SIGNAL_RESUME_OBSERVE':'0',
    'PEAR_IMAGE_ADMISSION_DIAGNOSTIC':'1', 'PEAR_METAL_PIPELINE_OBSERVE':'1',
    'MTL_DEBUG_LAYER':'1', 'MTL_DEBUG_LAYER_ERROR_MODE':'assert', 'MTL_DEBUG_LAYER_WARNING_MODE':'nslog',
    'MTL_SHADER_VALIDATION':'1', 'MTL_SHADER_VALIDATION_FAIL_MODE':'zerofill',
    'MTL_SHADER_VALIDATION_REPORT_TO_STDERR':'1'}
STREAM_LIMIT = 2*1024**2


def canonical_directory(value):
    path=Path(value)
    need(path.is_absolute() and path.is_dir() and path.resolve(strict=True)==path,
         'cpu_directory_alias')
    return path


def admit_pack(inventory_ref, provider, runtime_ref=None):
    """Admit every staged byte; historical source_ref paths are provenance only."""
    root=core.checked_ref(inventory_ref).parent
    value=core.read_ref(inventory_ref)
    need(value['schema_version']==1 and value['scope']=='immutable_cpu_controls_inputs', 'cpu_pack_scope')
    rows=value['files']
    need(type(rows) is list and len(rows)==180 and len({r['path'] for r in rows})==len(rows), 'cpu_pack_files')
    total=0
    for row in rows:
        raw=read_relative(root,row['path'],8*1024**2)
        need(digest(raw)==row['sha256'] and len(raw)==row['size_bytes'], 'cpu_pack_changed')
        total+=len(raw)
    need(total==value['logical_bytes'] and total<=1024**2, 'cpu_pack_bytes')
    build_raw=read_relative(root,'cpu_build/build.json');built=corpus.decode(build_raw)
    corpus.admit_build(corpus.manifest(),corpus.canonical(corpus.manifest()),built,root/'cpu_build',provider=provider)
    native=corpus.read(root/'cpu_reference/results.json')
    corpus.assess_records(corpus.manifest(),build_raw,native,'native',provider=provider)
    ordering=corpus.read(root/'ordering_build/build.json')
    need(ordering['scope']=='cpu_ordering_build' and ordering['passed'] is True and
         ordering['iterations']==2048 and ordering['rounds']==4 and
         len(ordering['cases'])==1 and ordering['cases'][0]['id']=='ordering', 'cpu_ordering_build')
    cases=built['cases']+ordering['cases']
    for row in cases:
        group='ordering_build' if row['id']=='ordering' else 'cpu_build'
        need(row['path']==row['id']+'.exe', 'cpu_pack_binary_path')
        raw=read_relative(root,group+'/'+row['path'])
        offset=int.from_bytes(raw[60:64],'little') if len(raw)>64 else 0
        need(digest(raw)==row['sha256'] and raw[:2]==b'MZ' and
             raw[offset:offset+6]==b'PE\0\0\x64\x86','cpu_pack_binary')
    if runtime_ref is not None:
        runtime=core.checked_ref(runtime_ref).parent;packet=core.read_ref(runtime_ref)
        for row in cases:
            selected=packet['fixtures'][row['id']]
            need(selected['sha256']==row['sha256'] and
                 digest(read_relative(runtime,selected['path'],8*1024**2))==row['sha256'], 'cpu_runtime_binary')
    core.checked_ref(inventory_ref);provider.recheck()
    return dict(root=root,build_raw=build_raw,built=built,reference=native,ordering=ordering,cases=cases)


def verify_logs(run, record):
    raw={};events={};total=0
    for row in record['logs']:
        need(type(row) is dict and set(row)=={'role','channel','path','sha256','bytes','observed_bytes','eof','write_error'},'cpu_log_shape')
        role,channel=row['role'],row['channel'];key=(role,channel)
        need(type(role) is str and re.fullmatch(r'(loader|server|sentinel|process-[0-9]{2})',role) and
             channel in ('stdout','stderr','events') and key not in raw and
             row['path']==role+'.'+channel+'.log','cpu_log_identity')
        data=read_relative(run/'run',row['path'],STREAM_LIMIT)
        need(type(row['bytes']) is int and type(row['observed_bytes']) is int and
             row['bytes']==row['observed_bytes']==len(data) and row['eof'] is True and
             row['write_error'] is None and row['sha256']==digest(data),'cpu_log_changed')
        raw[key]=data;total+=len(data)
        if channel=='events':
            need(not data or data.endswith(b'\n'),'cpu_event_truncated')
            events[role]=[corpus.decode(line) for line in data.splitlines() if line]
    wanted={(r,c) for r in ('loader','server','sentinel') for c in ('stdout','stderr')}
    wanted|={(r,'events') for r in record['events']}
    need(set(raw)==wanted and events==record['events'] and total<=32*1024**2,'cpu_log_coverage')
    return raw


def configuration(record, fixture_id):
    request=record['requested'];applied=record['applied']
    expected={**OPTIONS,'candidate':'d25-game','fixture':fixture_id,'budget':'standard120',
              'log_budget':'standard2','samples':[],'observations':OBSERVATIONS}
    need(request==expected,'cpu_d36_requested_configuration')
    need(applied['candidate']=='d25-game' and applied['deadline_seconds']==120 and
         applied['stream_limit_bytes']==STREAM_LIMIT and
         applied['observation_environment']==OBSERVATIONS and
         applied['trace_environment']==ENVIRONMENT['WINEDEBUG'] and
         applied['entry_environment']=={'PEAR_FEX_ENTRY_OBSERVE':'1'} and
         applied['link_environment']=={'PEAR_FEX_LINK_OBSERVE':'0'} and
         applied['query_environment']=={'PEAR_QUERY_OBSERVE':'0'} and
         applied['signal_environment']=={'PEAR_SIGNAL_RESUME_OBSERVE':'0'},'cpu_d36_applied_configuration')
    launches=record['launches']
    need([row['role'] for row in launches]==['sentinel','server','loader'],'cpu_launch_set')
    for launch in launches:
        need(all(launch['environment'].get(k)==v for k,v in ENVIRONMENT.items()),'cpu_d36_launch_environment')
    loader=launches[-1]
    need(loader['environment']['WINEDLLOVERRIDES']=='d3d11,dxgi,d3d10core,winemetal=b;mscoree=' and
         loader['environment']['PEAR_WINE_ABI_FIXTURE']=='1','cpu_loader_policy')
    need(applied['launches']==launches,'cpu_applied_launches')
    return loader


def authority(run, side, runtime_ref, operation_ref):
    ref=fact(run/side/'control.json');control=core.read_ref(ref)
    need(control['passed'] is True and control['runtime_sha256']==runtime_ref['sha256'] and
         control['operation_ref']==operation_ref,'cpu_authorization_pair')
    need(control['commands'] and len(control['commands'])<=512,'cpu_authorization_commands')
    for command in control['commands']:
        need(command['status']=='completed' and command['exit_code']==0 and
             command['error'] is None and command['evidence_error'] is None and
             command['bound_outcome'] is None and command['cwd']==str(run/side),'cpu_authorization_command_failed')
        for log in command['logs'].values():
            data=read_relative(run/side,log['path'],16*1024**2)
            need(digest(data)==log['sha256'] and len(data)==log['size_bytes'],'cpu_authorization_log_changed')
    core.checked_ref(ref)
    return ref


def authority_interval(run,operation):
    interval=operation['intervals'][0]
    need(interval['name']=='current_authority_owned_execution_cleanup','cpu_operation_interval_kind')
    before=core.read_ref(fact(run/'before/control.json'))['timing']
    after=core.read_ref(fact(run/'after/control.json'))['timing']
    points=[operation['lock']['acquired']['monotonic_seconds'],interval['started']['monotonic_seconds'],
            before['started']['monotonic_seconds'],before['ended']['monotonic_seconds'],
            after['started']['monotonic_seconds'],after['ended']['monotonic_seconds'],
            interval['ended']['monotonic_seconds'],operation['lock']['release_observed']['monotonic_seconds']]
    need(all(type(p) in (int,float) and 0<=p<float('inf') for p in points) and
         points==sorted(points),'cpu_authorization_interval_join')


def observed_row(run, record, fixture, runtime_ref):
    """Original observe_pear execution/log/bootstrap checks, independent of kind."""
    runtime=core.checked_ref(runtime_ref).parent;packet=core.read_ref(runtime_ref)
    need(record['runtime_sha256']==runtime_ref['sha256'] and record['runtime_ref']==runtime_ref,'cpu_run_runtime')
    need(record['outcome']=='exited' and not record['error'] and not record['stream_error'] and
         not record['cleanup_errors'] and record['cleanup']['complete'] is True and
         record['sentinel_survived'] is True and record['authorization_before_after_passed'] is True,
         'cpu_execution_boundary')
    need(record['cleanup'].get('observation_gap') is False and record['cleanup'].get('errors')==[] and
         all(p['reaped'] is True for p in record['processes'].values()),'cpu_owned_cleanup')
    loader=configuration(record,fixture['id'])
    selected=packet['fixtures'][fixture['id']];binary=runtime/selected['path']
    need(selected['sha256']==fixture['sha256'] and digest(read_relative(runtime,selected['path']))==fixture['sha256'], 'cpu_runtime_binary')
    need(loader['argv']==[str(runtime/packet['entrypoints']['bootstrap_helper']),'--exec-4k',
         str(runtime/packet['entrypoints']['loader']),str(binary)],'cpu_different_fixture_launched')
    raw=verify_logs(run,record)
    events=[event for rows in record['events'].values() for event in rows]
    translated=[r for r in events if 'translation_value' in r];images=[r for r in events if r.get('event')=='image']
    need(translated and all(r['translation_value']==0 and r['translation_error']==0 and r['cpu_type']==16777228
         for r in translated),'cpu_translated_host_process')
    need(images and all(r['cpu_type']==16777228 for r in images),'cpu_non_arm64_image')
    stdout=raw[('loader','stdout')]
    need(len(stdout)<=1024**2,'cpu_guest_output_bound')
    parsed=[corpus.decode(line) for line in stdout.splitlines() if line.strip()]
    need(parsed and parsed[0].get('record_kind')=='pear_bootstrap_helper','cpu_bootstrap_record')
    helper=parsed.pop(0);identity=record['processes']['loader']['identity']
    need(helper.get('version')==1 and helper.get('cpu_type')==16777228 and helper.get('translation_value')==0 and
         helper.get('query_errno')==0 and all(helper.get(k)==identity[k] for k in ('pid','ppid','start_sec','start_usec')),
         'cpu_bootstrap_identity')
    row=dict(id=fixture['id'],binary_sha256=fixture['sha256'],exit_code=record['processes']['loader']['exit_code'],
             outcome=record['outcome'],events=parsed)
    evidence=dict(case_ref=fact(run/'case.json'),runtime_ref=runtime_ref,
        translation_observations=len(translated),arm64_image_events=len(images),
        authorization_before_after=True,cleanup_complete=True,sentinel_survived=True,
        stdout_sha256=digest(stdout),stderr_sha256=digest(raw[('loader','stderr')]),
        d36_options=OPTIONS,late_load_coverage_complete=False,diagnostic_only=True)
    return row,evidence,raw


def frozen_sources(run, context, roots, pins):
    """Verify historical snapshots against the reviewed frozen Git checkpoints."""
    manifest=core.read_ref(context['producer_manifest_ref']);rows=core.read_ref(fact(run/'producers.json'))
    need(manifest['scope']=='fixture_producer_sources' and manifest['roots']=={k:str(v) for k,v in roots.items()},
         'cpu_reuse_producer_roots')
    expected={str(roots[r['root']]/r['path']):dict(path=str(roots[r['root']]/r['path']),sha256=r['sha256'],size_bytes=r['size_bytes'])
              for r in manifest['files']}
    expected[context['producer_manifest_ref']['path']]=context['producer_manifest_ref']
    need(len(expected)==len(rows) and {r['original']['path']:r['original'] for r in rows}==expected,
         'cpu_reuse_snapshot_coverage')
    for row in rows:
        snapshot=core.checked_ref(row['snapshot'])
        need(snapshot.is_relative_to(run/'producer-sources') and row['snapshot']['sha256']==row['original']['sha256'] and
             row['snapshot']['size_bytes']==row['original']['size_bytes'],'cpu_reuse_snapshot_changed')
    snapshots={r['original']['path']:r['snapshot'] for r in rows}
    for row in manifest['files']:
        need(row['root'] in pins,'cpu_reuse_source_pin')
        try:
            raw=subprocess.check_output(['git','-C',str(roots[row['root']]),'show',pins[row['root']]+':'+row['path']],timeout=10)
        except (OSError,subprocess.SubprocessError) as exc:raise ValueError('cpu_reuse_checkpoint_unavailable') from exc
        need(digest(raw)==row['sha256'] and len(raw)==row['size_bytes'],'cpu_reuse_checkpoint_source')
    return snapshots


def observe_seven(run, fixture, operation_ref, runtime_ref, *, source_roots, checkpoint_pins):
    """Read-only adaptation of one of the six frozen Stage4.1 observations."""
    run=canonical_directory(run)
    need(fixture['id'] in OVERLAP,'cpu_reuse_case')
    operation=core.read_ref(operation_ref);plan=operation['plan']
    need(Path(operation_ref['path'])==run.with_name(run.name+'.fixture-operation')/'operation.json' and
         operation['scope']=='development_fixture_operation' and operation['status']=='passed' and
         operation['lock']['released'] is True and operation['runtime_execution_performed'] is True and
         operation['runtime_execution_attempted'] is True and operation['game_qualified'] is False,
         'cpu_reuse_operation')
    need(plan['scope']=='development_fixture_plan' and plan['fixture']==fixture['id'] and
         plan['output']==str(run) and plan['operation_output']==str(Path(operation_ref['path']).parent) and
         plan['runtime_ref']==runtime_ref and plan['options']==OPTIONS and
         len(operation['intervals'])==1 and operation['worker']['pid']==operation['worker']['process_group'],
         'cpu_reuse_operation_binding')
    request=core.read_ref(operation['request_ref'])
    need(set(request)=={'schema_version','scope','descriptor_ref','fixture','output_name','options','limits'} and
         type(request['schema_version']) is int and request['schema_version']==1 and
         plan['request_ref']==operation['request_ref'] and request['scope']=='development_fixture_verification' and
         request['descriptor_ref']==plan['descriptor_ref'] and request['fixture']==fixture['id'] and
         request['options']==OPTIONS and request['output_name']==run.name and request['limits']==plan['limits'],
         'cpu_reuse_request')
    context=core.read_ref(plan['descriptor_ref'])
    need(context['scope']=='redistributable_runtime_fixtures' and context['candidate']=='d25-game' and
         context['runtime_ref']==runtime_ref and run.parent==Path(context['output_root']),'cpu_reuse_context')
    core.completed_operation(runtime_ref,core.read_ref(runtime_ref),context['operation_ref'])
    need(operation['case_ref']==fact(run/'case.json'),'cpu_reuse_case_changed')
    record=core.read_ref(operation['case_ref'])
    need(record['scope']=='development_direct_fixture_v1' and record['kind']=='runtime_fixture_observation' and
         record['diagnostic_only'] is True and record['fixture_context_ref']==plan['descriptor_ref'] and
         record['game_inputs_required'] is False and record['game_qualified'] is False and
         record['runtime_unchanged'] is True and record['producer_dependencies_unchanged'] is True,
         'cpu_reuse_development_scope')
    selected=context['fixture_refs'][fixture['id']]
    need(record['diagnostic_fixture']==dict(name=fixture['id'],artifact=selected,expected_exit=42) and
         selected['sha256']==fixture['sha256'],'cpu_reuse_fixture_identity')
    core.checked_ref(selected)
    for item in context['modules'].values():core.checked_ref(item['selected_ref'])
    need(operation['result_ref']==fact(run/'shared-fixture-assessment.json'),'cpu_reuse_result_ref')
    result=core.read_ref(operation['result_ref'])
    need(result['passed'] is True and result['fixture']==fixture['id'] and result['run_ref']==operation['case_ref'] and
         result['runtime_ref']==runtime_ref,'cpu_reuse_result_binding')
    snapshots=frozen_sources(run,context,source_roots,checkpoint_pins)
    need(result['checker']['path'] in snapshots and
         snapshots[result['checker']['path']]['sha256']==result['checker']['sha256'],'cpu_reuse_checker_source')
    for log in operation['logs'].values():core.checked_ref(log)
    core.checked_ref(operation['worker']['interpreter_ref'])
    before=authority(run,'before',runtime_ref,context['operation_ref'])
    after=authority(run,'after',runtime_ref,context['operation_ref'])
    authority_interval(run,operation)
    row,evidence,raw=observed_row(run,record,fixture,runtime_ref)
    evidence.update(operation_ref=operation_ref,descriptor_ref=plan['descriptor_ref'],
        result_ref=operation['result_ref'],producer_manifest_ref=context['producer_manifest_ref'],
        producer_snapshot_count=len(snapshots),checkpoint_pins=checkpoint_pins,before_ref=before,after_ref=after,
        route='explicit_frozen_seven_fixture_development_adapter')
    core.checked_ref(operation_ref);core.checked_ref(runtime_ref)
    return row,evidence,raw


def reference_logs(pack):
    return {(row['id'],stream):read_relative(pack['root'],'cpu_reference/'+row['id']+'.'+stream)
            for row in pack['reference']['cases'] for stream in ('stdout','stderr')}


def compare_overlap(pack, rows, evidence, *, provider):
    need({r['id'] for r in rows}==set(OVERLAP) and len(rows)==6,'cpu_overlap_complete')
    expected=corpus.assess_records(corpus.manifest(),pack['build_raw'],pack['reference'],'native',provider=provider)
    logs=reference_logs(pack)
    for row in pack['reference']['cases']:
        for channel in ('stdout','stderr'):
            need(digest(logs[(row['id'],channel)])==row[channel+'_sha256'],'reference_log_changed')
        need([corpus.decode(x) for x in logs[(row['id'],'stdout')].splitlines() if x.strip()]==row['events'],
             'reference_events_changed')
    cases={c['id']:c for c in corpus.manifest()['cases']};boundaries={c['id']:c for c in corpus.manifest()['boundaries']}
    binaries={r['id']:r for r in pack['built']['cases']};results=[]
    for row in rows:
        name=row['id'];need(row['binary_sha256']==binaries[name]['sha256'] and row['outcome']=='exited','case_binary_or_outcome')
        actual=(corpus.case_result(cases[name],row,pack['built']['manifest_sha256'],provider=provider)
                if name in cases else corpus.boundary_result(boundaries[name],row))
        need(actual==expected[name] and actual['status']=='passed','cpu_overlap_native_mismatch')
        results.append(dict(id=name,status='passed',evidence=evidence[name]))
    return dict(scope='development_cpu_six_overlap_comparison',passed=True,cases=results,
        remaining_cpu_ids=[r['id'] for r in pack['built']['cases'] if r['id'] not in OVERLAP],ordering='unperformed',
        full_corpus_complete=False,diagnostic_only=True,cpu_qualified=False,game_qualified=False)


def completed_cpu_operation(run,case_id,operation_ref,context_ref,runtime_ref):
    operation=core.read_ref(operation_ref);plan=operation['plan']
    need(Path(operation_ref['path'])==run.with_name(run.name+'.cpu-operation')/'operation.json' and
         operation['scope']=='development_cpu_operation' and operation['status']=='passed' and
         operation['lock']['released'] is True and operation['runtime_execution_performed'] is True and
         operation['runtime_execution_attempted'] is True and operation['game_qualified'] is False,
         'cpu_operation_not_complete')
    need(plan['scope']=='development_cpu_plan' and plan['case_id']==case_id and plan['output']==str(run) and
         plan['operation_output']==str(Path(operation_ref['path']).parent) and plan['options']==OPTIONS and
         plan['descriptor_ref']==context_ref and plan['runtime_ref']==runtime_ref and
         len(operation['intervals'])==1 and type(operation['worker']['pid']) is int and
         operation['worker']['pid']>1 and operation['worker']['pid']==operation['worker']['process_group'],
         'cpu_operation_binding')
    request=core.read_ref(operation['request_ref'])
    need(set(request)=={'schema_version','scope','descriptor_ref','case_id','output_name','limits'} and
         type(request['schema_version']) is int and request['schema_version']==1 and
         plan['request_ref']==operation['request_ref'] and request['scope']=='development_cpu_verification' and
         request['descriptor_ref']==context_ref and request['case_id']==case_id and request['output_name']==run.name and
         request['limits']==plan['limits'],'cpu_operation_request')
    need(operation['case_ref']==fact(run/'case.json') and operation['result_ref']==fact(run/'cpu-assessment.json'),
         'cpu_operation_result_ref')
    result=core.read_ref(operation['result_ref'])
    need(result['passed'] is True and result['scope']=='development_cpu_case_assessment' and
         result['case_id']==case_id and result['context_ref']==context_ref and result['runtime_ref']==runtime_ref and
         result['case_ref']==operation['case_ref'] and result['control_ref']==fact(run/'control.json'),
         'cpu_operation_result_binding')
    need(set(operation['logs'])=={'stdout','stderr'},'cpu_operation_log_set')
    for log in operation['logs'].values():
        need(core.checked_ref(log).parent==Path(operation_ref['path']).parent,'cpu_operation_log_path')
    core.checked_ref(operation['worker']['interpreter_ref']);core.checked_ref(operation_ref)
    authority_interval(run,operation)
    return operation,result


def compare_index(index_ref):
    """Read-only full19 + finite ordering replay with every operation rejoined."""
    from .cpu_context import CPUContext,CPU_IDS
    from . import cpu_execution
    from pear_runtime.fixtures.types import Selection
    index=core.read_ref(index_ref)
    need(set(index)=={'schema_version','scope','runtime_ref','input_pack_ref','source_provider',
                      'case_operations','ordering_operation_ref','reuse_source_roots'} and
         type(index['schema_version']) is int and index['schema_version']==1 and
         index['scope']=='development_cpu_corpus_comparison','cpu_comparison_index')
    source=index['source_provider']
    need(set(source)=={'root','commit'},'cpu_comparison_provider')
    provider=corpus.bind_provider(source['root'],source['commit'])
    pack=admit_pack(index['input_pack_ref'],provider,index['runtime_ref'])
    need(type(index['case_operations']) is list and [r['id'] for r in index['case_operations']]==list(CPU_IDS),
         'cpu_comparison_complete_case_set')
    roots={k:canonical_directory(v) for k,v in index['reuse_source_roots'].items()}
    need(roots=={'runtime':Path(__file__).resolve().parents[3]},'cpu_reuse_canonical_root')
    policy=read(Path(__file__).resolve().parents[3]/'provenance/fixture-cpu-import.json')
    pins=policy['seven_reuse_checkpoint_pins']
    rows=[];evidence=[];descriptor_ref=None
    def fresh(operation_ref,case_id):
        nonlocal descriptor_ref
        operation=core.read_ref(operation_ref);ref=operation['plan']['descriptor_ref'];value=core.read_ref(ref)
        need(value['input_pack_ref']==index['input_pack_ref'] and value['source_provider']==source,
             'cpu_comparison_input_set')
        if descriptor_ref is None:descriptor_ref=ref
        need(descriptor_ref==ref,'cpu_comparison_mixed_contexts')
        selection=Selection('d25-game',Path(index['runtime_ref']['path']).parent)
        context=CPUContext(ref,selection);run=canonical_directory(operation['plan']['output'])
        need(context.base['runtime_ref']==index['runtime_ref'],'cpu_comparison_runtime')
        context.admit_record(run,case_id,operation_ref)
        _,saved=completed_cpu_operation(run,case_id,operation_ref,ref,index['runtime_ref'])
        current=cpu_execution.assess(context,run)
        need(current==saved,'cpu_comparison_assessment_changed')
        return current,dict(operation_ref=operation_ref,result_ref=operation['result_ref'],
                            route='current_cpu_operation',evidence=current['evidence'])
    for fixture,item in zip(pack['built']['cases'],index['case_operations']):
        need(set(item)=={'id','route','operation_ref'},'cpu_comparison_case_shape')
        if item['route']=='frozen_seven':
            operation=core.read_ref(item['operation_ref']);run=canonical_directory(operation['plan']['output'])
            row,observed,_=observe_seven(run,fixture,item['operation_ref'],index['runtime_ref'],
                                        source_roots=roots,checkpoint_pins=pins)
        else:
            need(item['route']=='cpu_operation','cpu_comparison_case_route')
            result,observed=fresh(item['operation_ref'],item['id']);row=result['row']
        rows.append(row);evidence.append(dict(id=item['id'],**observed))
    comparison=corpus.compare_result_rows(pack['build_raw'],pack['reference'],reference_logs(pack),rows,provider=provider)
    ordering,ordering_evidence=fresh(index['ordering_operation_ref'],'ordering')
    need(ordering['comparison']['passed'] is True,'cpu_comparison_ordering')
    provider.recheck();core.checked_ref(index_ref);core.checked_ref(index['input_pack_ref']);core.checked_ref(index['runtime_ref'])
    return dict(schema_version=1,scope='finite_development_cpu19_ordering_comparison',passed=True,
        index_ref=index_ref,runtime_ref=index['runtime_ref'],input_pack_ref=index['input_pack_ref'],
        source_provider=source,cases=comparison['cases'],case_evidence=evidence,
        ordering=ordering['comparison'],ordering_evidence=ordering_evidence,full_corpus_complete=True,
        unsupported=[r['id'] for r in comparison['cases'] if r['status']!='passed'],
        diagnostic_only=True,execution_performed_by_comparison=False,
        complete_late_load_coverage=False,cpu_qualified=False,game_qualified=False,distribution_qualified=False)
