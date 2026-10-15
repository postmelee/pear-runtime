# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later AND MIT
"""Original owned CPU session on the explicitly admitted D36 development inputs.

The session/cleanup sequence is adapted from Pear tools/cpu/pear_run.py (MIT).
The diagnostic environment is explicitly the reviewed Stage4.1 configuration;
AVX refusal remains exit 77 and ordering retains all original finite oracles.
"""
from pathlib import Path
import os
import subprocess
import time
import uuid

from pear_runtime.assembly import core
from pear_runtime.assembly._common import encoded,read_relative
from pear_runtime.errors import Error,need
from pear_runtime.fixtures import supervision as supervisor
from pear_runtime.fixtures.admission import prefix_inventory
from pear_runtime.fixtures.direct import finish_reason
from pear_runtime.fixtures.inputs import fact,read,save,digest
from .cpu_context import CPUContext,CASES
from . import corpus,cpu_evidence as evidence


def _error(exc):return dict(type=type(exc).__name__,code=getattr(exc,'code',str(exc)))


def clone_prefix(context,prefix):
    """Clone the synthetic seed and replace only the two admitted module files."""
    template=context.seed/'run/prefix';inventory=context.base['seed_inventory']
    need(not prefix.exists() and not prefix.is_symlink(),'cpu_prefix_not_empty')
    need(prefix_inventory(template)==inventory,'cpu_seed_changed')
    tool=core.checked_ref(context.value['tool_refs']['copy'])
    subprocess.run([str(tool),'-cRp',str(template),str(prefix)],check=True,timeout=30)
    need(prefix_inventory(prefix)==inventory,'cpu_prefix_clone')
    allowed=set()
    for name,row in context.base['modules'].items():
        relative='drive_c/windows/system32/'+name;target=prefix/relative;source=core.checked_ref(row['selected_ref'])
        need(fact(target)['sha256']==row['seed_sha256'],'cpu_module_preimage')
        target.write_bytes(source.read_bytes())
        need(fact(target)['sha256']==row['selected_ref']['sha256'],'cpu_module_copy');allowed.add(relative)
    after=prefix_inventory(prefix)
    need([r for r in after if r['path'] not in allowed]==[r for r in inventory if r['path'] not in allowed],
         'cpu_module_copy_scope')
    need(prefix_inventory(template)==inventory,'cpu_seed_changed')
    return dict(seed_ref=context.base['seed_ref'],inventory_sha256=digest(encoded(inventory)),
                cold_prefix_initialization=False,staged_modules=context.base['modules'])


def owned_session(context,runtime,value,output,case_id,origin):
    work=output/'run';prefix=work/'prefix';fixture=value['fixtures'][case_id]
    result=dict(schema_version=1,scope='development_cpu_fixture_v1',kind='development_cpu_observation',
        fixture_id=case_id,fixture_sha256=fixture['sha256'],context_ref=context.ref,
        runtime_ref=context.base['runtime_ref'],runtime_sha256=context.base['runtime_ref']['sha256'],
        diagnostic_only=True,game_qualified=False,cpu_qualified=False,prefix_origin=origin,
        authorization_before_after_passed=False,producer_ref=fact(Path(__file__)),
        requested={**evidence.OPTIONS,'candidate':'d25-game','fixture':case_id,'budget':'standard120',
                   'log_budget':'standard2','samples':[],'observations':evidence.OBSERVATIONS},
        applied=dict(candidate='d25-game',deadline_seconds=120,stream_limit_bytes=evidence.STREAM_LIMIT,
            observation_environment=evidence.OBSERVATIONS,trace_environment=evidence.ENVIRONMENT['WINEDEBUG'],
            entry_environment={'PEAR_FEX_ENTRY_OBSERVE':'1'},link_environment={'PEAR_FEX_LINK_OBSERVE':'0'},
            query_environment={'PEAR_QUERY_OBSERVE':'0'},signal_environment={'PEAR_SIGNAL_RESUME_OBSERVE':'0'}))
    caught=None
    with supervisor.supervision(context.provider_root) as (life,helpers):
        helpers.base.STREAM_LIMIT=evidence.STREAM_LIMIT
        nonce=uuid.uuid4().hex;packet=supervisor.assessment_packet(value)
        session=helpers.api.APISession(work,runtime,packet,nonce,suite='api-abi',case_id='first-dispatch')
        env=supervisor.environment(work/'work',prefix,nonce,str(work/'home'));env.update(evidence.ENVIRONMENT)
        paths={k:runtime/v for k,v in value['entrypoints'].items()}
        read_fd=control=None;error=None;outcome='not_started';refusal=None
        start=time.monotonic();deadline=start+120;remaining=lambda cap:max(0,min(cap,deadline-time.monotonic()))
        launches=[]
        def launch(role,args,environment,**kwargs):
            child=session.launch(role,args,environment,**kwargs)
            launches.append(dict(role=role,argv=args,environment=environment,pid=child.pid));return child
        try:
            graphical=helpers.api.graphical_session()
            need(graphical=={'status':0,'available':True},'cpu_graphical_session');result['graphical_session']=graphical
            read_fd,control=os.pipe()
            sentinel=launch('sentinel',[str(paths['sentinel']),str(read_fd)],env,pass_fds=(read_fd,))
            os.close(read_fd);read_fd=None
            need(session.wait_for(lambda:b'\n' in session.streams[('sentinel','stdout')]['data'],remaining(5)),
                 'integration_sentinel_start')
            helpers.base.validate_helper(helpers.base.parse_lines(session,'sentinel')[0],'pear_sentinel_ready',sentinel)
            server=launch('server',[str(paths['server']),'-f','-p'],env,event_pipe=True)
            need(session.wait_for(lambda:any(r.get('event')=='server_ready' for r in session.events['server']) or server.exited,
                                  remaining(30)) and not server.exited,'integration_server_start')
            loader_env={**env,'PEAR_STAGE3_CONTROL':session.endpoint,'PEAR_WINE_ABI_FIXTURE':'1',
                        'PEAR_BOOTSTRAP_SERVER_PID':str(server.pid),
                        'WINEDLLOVERRIDES':'d3d11,dxgi,d3d10core,winemetal=b;mscoree='}
            executable=runtime/fixture['path']
            need(fact(executable)['sha256']==fixture['sha256'],'cpu_fixture_changed')
            session.output=work/'work'
            try:loader=launch('loader',[str(paths['bootstrap_helper']),'--exec-4k',str(paths['loader']),str(executable)],
                              loader_env,allowed_paths=[paths['bootstrap_helper'],paths['loader']])
            finally:session.output=work
            def finished():
                nonlocal refusal
                data=bytes(session.streams.get(('loader','stderr'),{}).get('data',b''))
                refusal=finish_reason(data,loader.pid,None)
                return loader.exited or refusal is not None or session.failure is not None
            completed=session.wait_for(finished,remaining(120))
            outcome='owner_refused' if refusal else 'exited' if completed else 'timeout'
        except BaseException as exc:
            caught=exc;error=_error(exc);outcome='error'
        finally:
            before,cleanup,sentinel_cleanup,logs,survived,cleanup_errors=life.cleanup_session(session,control,read_fd,work)
        result.update(outcome=outcome,error=error,stream_error=session.failure,events=session.events,logs=logs,
            cleanup=cleanup,sentinel_cleanup=sentinel_cleanup,sentinel_survived=survived,cleanup_errors=cleanup_errors,
            pre_cleanup=before,elapsed_ms=round((time.monotonic()-start)*1000),launches=launches,
            registrations=list(session.observer.registrations.values()),signal_observations=session.observer.signal_observations,
            processes={role:dict(identity=child.identity,exit_code=child.exit_code,reaped=child.reaped,
                                 allowed_paths=sorted(child.allowed_paths)) for role,child in session.children.items()},
            observed_owner_refusal=refusal)
        result['applied']['launches']=launches
        save(output/'case.json',result)
    if caught is not None:raise caught
    return result


def run(context,case_id,output):
    need(type(context) is CPUContext and callable(context.execution_interval),'cpu_execution_context')
    need(case_id in CASES,'cpu_case_selection')
    with context.execution_interval(output):
        storage=context.storage_admission(output);runtime,value=context.begin(case_id,output)
        output=Path(output);output.mkdir(mode=0o700);save(output/'storage.json',storage)
        control=dict(schema_version=1,scope='development_cpu_control_run',case_id=case_id,
            context_ref=context.ref,runtime_ref=context.base['runtime_ref'],operation_ref=context.base['operation_ref'],
            profile_ref=context.base['profile_ref'],input_pack_ref=context.value['input_pack_ref'],
            producer_manifest_ref=context.value['producer_manifest_ref'],status='started',error=None,
            secondary_errors=[],case_ref=None,before_ref=None,after_ref=None,diagnostic_only=True,
            runtime_qualified=False,cpu_qualified=False,game_qualified=False)
        save(output/'control.json',control);primary=None;interrupted=False
        try:
            context.preserve_sources(output)
            work=output/'run';work.mkdir(mode=0o700);origin=clone_prefix(context,work/'prefix')
            for path in (work/'work',work/'work/tmp',work/'home'):path.mkdir(mode=0o700)
            context.mark('prefix_and_source_preparation')
            context.current_authority(output/'before')
            control['before_ref']=evidence.authority(output,'before',context.base['runtime_ref'],context.base['operation_ref'])
            context.mark('authority_before')
            owned_session(context,runtime,value,output,case_id,origin)
            context.mark('owned_execution_and_cleanup');control['status']='executed'
        except BaseException as exc:
            primary=exc;control.update(status='failed',error=_error(exc))
            interrupted=isinstance(exc,(KeyboardInterrupt,SystemExit)) or getattr(exc,'code',None)=='assembly_worker_timeout'
        finally:
            def secondary(exc):
                nonlocal primary
                if primary is None:primary=exc;control.update(status='failed',error=_error(exc))
                else:primary.add_note('CPU finalization also failed: '+str(_error(exc)));control['secondary_errors'].append(_error(exc))
            if control['before_ref'] is not None and not interrupted:
                try:
                    context.current_authority(output/'after')
                    control['after_ref']=evidence.authority(output,'after',context.base['runtime_ref'],context.base['operation_ref'])
                    context.mark('authority_after')
                except BaseException as exc:secondary(exc)
            if interrupted:control['authority_after_not_started']='owned execution interrupted after cleanup'
            try:context.finish()
            except BaseException as exc:secondary(exc)
            try:
                case_path=output/'case.json'
                if case_path.is_file():
                    case=read(case_path)
                    case['authorization_before_after_passed']=control['before_ref'] is not None and control['after_ref'] is not None
                    save(case_path,case);control['case_ref']=fact(case_path)
            except BaseException as exc:secondary(exc)
            try:save(output/'control.json',control)
            except BaseException as exc:secondary(exc)
        if primary is not None:raise primary
        result=assess(context,output);save(output/'cpu-assessment.json',result)
        return result


def assess(context,output):
    need(type(context) is CPUContext and context._completed and context._validated_end and
         not context._active and Path(output)==context._output,'cpu_assessment_context')
    output=Path(output);control_ref=fact(output/'control.json');control=core.read_ref(control_ref)
    need(control['scope']=='development_cpu_control_run' and control['status']=='executed' and
         control['error'] is None and control['secondary_errors']==[] and control['case_id']==context._case and
         control['context_ref']==context.ref and control['runtime_ref']==context.base['runtime_ref'] and
         control['operation_ref']==context.base['operation_ref'] and control['profile_ref']==context.base['profile_ref'] and
         control['input_pack_ref']==context.value['input_pack_ref'] and
         control['producer_manifest_ref']==context.value['producer_manifest_ref'],'cpu_control_binding')
    case_ref=fact(output/'case.json');need(control['case_ref']==case_ref,'cpu_case_ref');case=core.read_ref(case_ref)
    fixture=next(r for r in context.pack['cases'] if r['id']==context._case)
    need(case['scope']=='development_cpu_fixture_v1' and case['kind']=='development_cpu_observation' and
         case['fixture_id']==fixture['id'] and case['fixture_sha256']==fixture['sha256'] and
         case['context_ref']==context.ref and case['diagnostic_only'] is True and
         case['cpu_qualified'] is False and case['game_qualified'] is False,'cpu_case_binding')
    for side in ('before','after'):
        need(control[side+'_ref']==evidence.authority(output,side,context.base['runtime_ref'],context.base['operation_ref']),
             'cpu_authority_ref')
    row,observed,raw=evidence.observed_row(output,case,fixture,context.base['runtime_ref'])
    if context._case=='ordering':
        root=context.pack['root'];reference=corpus.read(root/'ordering_reference/results.json')
        logs={stream:read_relative(root,'ordering_reference/'+stream) for stream in ('stdout','stderr')}
        comparison=corpus.compare_ordering_records(read_relative(root,'ordering_build/build.json'),reference,logs,
            row['events'],row['exit_code'],raw[('loader','stderr')]);status='passed'
    else:
        original=corpus.manifest();selected=next((r for r in original['cases'] if r['id']==context._case),None)
        actual=(corpus.case_result(selected,row,context.pack['built']['manifest_sha256'],provider=context.provider) if selected else
                corpus.boundary_result(next(r for r in original['boundaries'] if r['id']==context._case),row))
        expected=corpus.assess_records(original,context.pack['build_raw'],context.pack['reference'],'native',provider=context.provider)[context._case]
        # Bind exact Windows logs as well as the mathematical record.
        logs=evidence.reference_logs(context.pack)
        for reference in context.pack['reference']['cases']:
            for stream in ('stdout','stderr'):
                need(digest(logs[(reference['id'],stream)])==reference[stream+'_sha256'],'reference_log_changed')
            need([corpus.decode(x) for x in logs[(reference['id'],'stdout')].splitlines() if x.strip()]==reference['events'],
                 'reference_events_changed')
        if actual['status']=='unavailable':status='unsupported_not_exposed'
        else:need(expected['status']=='passed' and actual['values']==expected['values'],'native_mismatch');status='passed'
        comparison=dict(status=status,actual=actual,reference=expected)
    sources=context.finalize_assessment(output)
    for ref in (control_ref,case_ref,control['before_ref'],control['after_ref']):core.checked_ref(ref)
    return dict(scope='development_cpu_case_assessment',passed=True,case_id=context._case,status=status,
        context_ref=context.ref,runtime_ref=context.base['runtime_ref'],operation_ref=context.base['operation_ref'],
        control_ref=control_ref,case_ref=case_ref,input_pack_ref=context.value['input_pack_ref'],
        producer_manifest_ref=context.value['producer_manifest_ref'],producers_ref=sources,
        row=row,evidence=observed,comparison=comparison,diagnostic_only=True,
        full_corpus_complete=False,cpu_qualified=False,game_qualified=False)
