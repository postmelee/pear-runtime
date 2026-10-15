# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""One current owned game observation; inspection and prior controls are not grants."""
from __future__ import annotations

from contextlib import contextmanager, redirect_stdout, redirect_stderr
import os
import importlib
from pathlib import Path
import sys
import threading
import time
import uuid

from pear_runtime import build
from pear_runtime.errors import need
from pear_runtime.assembly import core
from pear_runtime.assembly._common import encoded
from pear_runtime.assembly.helpers import SourcePack, signing_helpers, PAYLOAD
from pear_runtime.assembly.driver import lease, deadline, BoundedLog, LogBudget
from . import admission, producers, game_prerequisites
from .context import capability_binding, inventory_shape
from .types import Selection
from .supervision import prefix_inventory
from .driver import interrupts

GAME_ENTRY_MODULES=producers.GAME_ENTRY_MODULES
DYNAMIC_PATHS=producers.DYNAMIC_PATHS+('provenance/fixture-game-seam.json',
    'pear:tools/development/game/import-provenance.json')
SCOPE=producers.GAME_SCOPE
GAME_SCOPE=SCOPE
GAME_DYNAMIC_PATHS=DYNAMIC_PATHS
REQUEST_FIELDS={'schema_version','scope','descriptor_ref','output_name','manual_policy','limits'}
WHOLE_TIMEOUT_SECONDS=5400
MANUAL_SECONDS=1800
_ACTIVE=None
_TOKEN=object()


def immutable_build_roots(value):
    """Exact recorded component roots and metadata parents, without rescanning builds."""
    assembly=value['development_assembly'];rows=assembly['builds']
    need(type(rows) is list and rows,'game_component_build_refs')
    roots=set()
    for ref in rows:
        built=core.read_ref(ref)
        need(type(built.get('schema_version')) is int and built['schema_version']==1 and
             built.get('scope')=='development_component_build' and built.get('status')=='passed' and
             type(built.get('roots')) is dict and built['roots'],'game_component_build_scope')
        roots.add(Path(ref['path']).parent)
        for row in built['roots'].values():
            need(type(row) is dict and row.get('kind') in ('git','input','toolchain','sdk','private','host') and
                 type(row.get('path')) is str,'game_component_root')
            path=Path(row['path'])
            need(path.is_absolute() and path.is_dir(),'game_component_root')
            roots.add(path.resolve(strict=True))
        for name in ('public_recipe','bindings_manifest','private_manifest'):
            if name in built and built[name] is not None:
                roots.add(core.checked_ref(built[name]).parent)
    for ref in assembly.get('review_refs',[]):roots.add(core.checked_ref(ref).parent)
    return roots


def admit_candidate(m):
    """Static candidate/seed/header/closure checks without host execution or a lease."""
    for key in ('runtime_ref','operation_ref','profile_ref','capabilities_ref','seed_ref'):core.checked_ref(m[key])
    runtime=Path(m['runtime_ref']['path']).parent;value=core.read_ref(m['runtime_ref'])
    core.completed_operation(m['runtime_ref'],value,m['operation_ref'])
    need(value.get('passed') is True and value.get('diagnostic_only') is True and
         all(value.get(k) is False for k in ('runtime_qualified','runtime_eligible','game_qualified',
                                            'execution_authorized_by_this_record')),'game_runtime_scope')
    need(value['development_assembly']['profile_ref']==m['profile_ref'],'game_runtime_profile')
    seed=Path(m['seed_root']);provider=Path(m['provider_root']);output=Path(m['output_root'])
    for root in (seed,provider,output):
        need(root.is_absolute() and root.is_dir() and root.resolve(strict=True)==root,'game_runtime_root_alias')
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output)
             for root in (seed,provider,runtime,Path(m['profile_ref']['path']).parent)),'game_runtime_output_overlap')
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output)
             for root in immutable_build_roots(value)),'game_output_build_input_overlap')
    helpers,reader=signing_helpers(SourcePack(provider));core.verify_closure(runtime,value,reader)
    selected=capability_binding(m['capabilities_ref'],value)
    need(m['seed_ref']['path']==str(seed/'case.json'),'game_seed_path')
    origin=core.read_ref(m['seed_ref'])
    need(origin['scope']=='translated_graphics' and origin['fixture_id']=='device' and
         origin['outcome']=='exited' and origin['error'] is None and origin['cleanup']['complete'] is True and
         origin['sentinel_survived'] is True and origin['cleanup_errors']==[],'game_synthetic_seed')
    inventory_shape(m['seed_inventory']);template=seed/'run/prefix'
    need(template.is_dir() and template.resolve(strict=True)==template and
         prefix_inventory(template)==m['seed_inventory'],'game_seed_changed')
    need(type(m['modules']) is dict and set(m['modules'])=={'ntdll.dll','xtajit64.dll'},'game_modules')
    for name,row in m['modules'].items():
        need(type(row) is dict and set(row)=={'seed_sha256','selected_ref'} and
             type(row['seed_sha256']) is str and len(row['seed_sha256'])==64 and
             all(c in '0123456789abcdef' for c in row['seed_sha256']),'game_module_shape')
        core.checked_ref(row['selected_ref'])
        need(build.fact(runtime/PAYLOAD/'lib/wine/aarch64-windows'/name)==row['selected_ref'] and
             build.fact(template/'drive_c/windows/system32'/name)['sha256']==row['seed_sha256'],'game_module_binding')
    inf=runtime/PAYLOAD/'share/wine/wine.inf'
    need((template/'.update-timestamp').read_text().strip()==str(int(inf.stat().st_mtime)),'game_prefix_update')
    return runtime,value,selected


def _symbol(captured,module,name):
    loaded=sys.modules.get(module)
    need(loaded is not None,'game_policy_not_loaded')
    path=getattr(loaded,'__file__',None)
    expected=captured.refs.get(('pear',module.replace('.','/')+'.py'))
    need(path is not None and expected is not None and
         str(Path(path).resolve(strict=True))==expected['path'] and build.fact(Path(path))==expected,
         'game_policy_source')
    symbol=getattr(loaded,name,None)
    need(symbol is not None and getattr(symbol,'__module__',None)==module,'game_policy_symbol')
    return symbol


def capture_context(context):
    # Reject structural substitutes before asking them to inspect or prepare inputs.
    cls=type(context);module=sys.modules.get('tools.development.game.context')
    need(module is not None and cls is getattr(module,'GameContext',None) and
         cls.__module__=='tools.development.game.context','game_context_type')
    captured=producers.capture(context.value['producer_manifest_ref'],context.provider_root,
        entry_modules=GAME_ENTRY_MODULES,dynamic_paths=DYNAMIC_PATHS,scope=SCOPE)
    need(cls is _symbol(captured,'tools.development.game.context','GameContext'),'game_context_source')
    need(type(context.candidate) is Selection and context.candidate.name=='d25-game' and
         context.candidate.runtime==Path(context.value['runtime_ref']['path']).parent,'game_context_candidate')
    core.checked_ref(context.ref)
    return captured


def request(path):
    path=Path(path)
    need(path.is_absolute() and path.resolve(strict=True)==path and not path.is_symlink(),'game_request_path')
    ref=build.fact(path);value=core.read_ref(ref)
    need(type(value) is dict and set(value)==REQUEST_FIELDS and type(value['schema_version']) is int and
         value['schema_version']==1 and value['scope']=='development_game_observation' and
         value['manual_policy']=='manual_feedback_v1','game_request_shape')
    name=value['output_name']
    need(type(name) is str and name and name not in ('.','..') and
         all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in name),'game_request_output')
    limits=value['limits']
    need(type(limits) is dict and set(limits)=={'whole_timeout_seconds','worker_log_bytes'} and
         type(limits['whole_timeout_seconds']) is int and limits['whole_timeout_seconds']==WHOLE_TIMEOUT_SECONDS and
         type(limits['worker_log_bytes']) is int and 1024<=limits['worker_log_bytes']<=16*1024**2,'game_request_limits')
    core.checked_ref(value['descriptor_ref']);core.checked_ref(ref)
    return value,ref


def review(path,context):
    value,ref=request(path);captured=capture_context(context)
    need(value['descriptor_ref']==context.ref and context.value['manual_policy']==value['manual_policy'],
         'game_request_context')
    output=context.fresh_output(Path(context.value['output_root'])/value['output_name'])
    operation=output.with_name(output.name+'.game-operation')
    need(not operation.exists() and not operation.is_symlink(),'game_operation_exists')
    inspected=context.inspect(output)
    game_prerequisites.admit(context.value)
    captured.recheck();core.checked_ref(ref)
    plan=dict(schema_version=1,scope='development_game_plan',request_ref=ref,descriptor_ref=context.ref,
        runtime_ref=context.value['runtime_ref'],assembly_operation_ref=context.value['operation_ref'],
        output=str(output),operation_output=str(operation),manual_policy=value['manual_policy'],
        limits=value['limits'],storage=inspected['storage'],current_authority_assessed=False,
        runtime_execution_performed=False,game_qualified=False)
    return value,ref,captured,plan


@contextmanager
def _current_lease():
    """Keep the existing lease owner and revoke its private guard before release."""
    with lease() as held:
        active=True;owner=(os.getpid(),os.getpgrp(),threading.get_ident())
        def require_live():
            need(active and owner==(os.getpid(),os.getpgrp(),threading.get_ident()),'game_lease_not_current')
        try:yield held,require_live
        finally:active=False


class GameOperation:
    """Current in-memory owner; only execute() creates an active instance under lease."""
    def __init__(self,token,context,ref,value,plan,captured,record,lease_guard):
        need(token is _TOKEN and _ACTIVE is None,'game_operation_constructor')
        self.context=context;self._lease_guard=lease_guard;self.request_ref=dict(ref);self.request_value=encoded(value)
        self.descriptor_bytes=encoded(context.value);self.plan=plan;self.captured=captured;self.record=record
        self.output=Path(plan['output']);self.operation_output=Path(plan['operation_output'])
        self.operation_id=record['operation_id'];self.owner=(os.getpid(),os.getpgrp(),threading.get_ident())
        self.not_after=record['not_after_monotonic_ns']
        need(type(self.not_after) is int and 0<self.not_after<2**63,'game_operation_deadline')
        self.active=False;self.entered=False;self.phase='preparation';self.authority_before=False
        self.runtime=None;self.runtime_value=None

    def assert_current(self,output,operation_id):
        need(type(self) is GameOperation and _ACTIVE is self and self.active and
             self.record['status']=='running' and self.record['lock']['released'] is False and
             self.owner==(os.getpid(),os.getpgrp(),threading.get_ident()) and os.getpid()==os.getpgrp() and
             Path(output)==self.output and operation_id==self.operation_id and time.monotonic_ns()<self.not_after,
             'game_operation_not_current')
        self._lease_guard()
        need(encoded(core.read_ref(self.request_ref))==self.request_value and
             encoded(self.context.value)==self.descriptor_bytes and
             core.read_ref(self.context.ref)==self.context.value,'game_operation_input_changed')
        need(self.record['plan']==self.plan and self.plan['output']==str(self.output) and
             self.plan['operation_output']==str(self.operation_output),'game_operation_binding')

    def _owned(self,output):
        self.assert_current(output,self.operation_id)
        need(self.phase=='owned_execution' and self.authority_before,'game_operation_authority_required')

    def check(self,phase,output):
        need(phase=='game','game_operation_phase');self._owned(output)
        return (dict(operation_id=self.operation_id,output=str(self.output)),
                dict(play_observation=dict(hold_seconds=MANUAL_SECONDS),manual_policy='manual_feedback_v1'))

    def grant(self,output,operation_id):
        self.assert_current(output,operation_id);self._owned(output)
        return dict(maximum_play_seconds=MANUAL_SECONDS,not_after_monotonic_ns=self.not_after)

    @contextmanager
    def execution_interval(self,output):
        self.assert_current(output,self.operation_id)
        need(not self.entered and self.phase=='preparation','game_execution_single_interval')
        self.entered=True;self.phase='authority_before';started=build.point()
        try:yield
        finally:
            self.phase='finalization'
            self.record['intervals'].append(build.span('current_authority_owned_execution_cleanup',started))

    def current_authority(self,runtime,value,output,reuse):
        self.assert_current(self.output,self.operation_id)
        expected=Path(self.context.value['runtime_ref']['path']).parent
        need(runtime==expected and value==core.read_ref(self.context.value['runtime_ref']) and
             Path(reuse)==Path(self.context.provider_root),'game_authority_context')
        output=Path(output)
        before=output==self.output/'before'
        need((before and self.phase=='authority_before' and not self.authority_before) or
             (output==self.output/'after' and self.phase=='owned_execution' and self.authority_before),
             'game_authority_phase')
        result=admission.current(self.context.value['runtime_ref'],self.context.value['operation_ref'],
            self.context.value['profile_ref'],self.context.provider_root,output)
        if before:self.authority_before=True;self.phase='owned_execution'
        else:self.phase='authority_after'
        self.assert_current(self.output,self.operation_id)
        return result

    def bind_factory(self,binder,companion_factory):
        self._owned(self.output);self.captured.recheck()
        need(binder is _symbol(self.captured,'tools.development.game.feedback','bind_factory'),
             'game_play_factory_binding')
        return binder(gate=self,companion_factory=companion_factory)

    def validate_adapter(self,adapter,companion_factory):
        self._owned(self.output)
        need(type(adapter) is _symbol(self.captured,'tools.development.game.feedback','FeedbackManualAdapter') and
             adapter.gate is self and adapter.companion_factory is companion_factory,'game_play_adapter_binding')


def result_admission(result,owner):
    """Require original harness oracles without converting guest outcomes into qualification."""
    from . import game_release
    output=owner.output;case_ref=build.fact(output/'case.json');case=core.read_ref(case_ref)
    need(type(result) is dict and result.get('game_qualified') is False and 'fixture_passed' not in result and
         result.get('game_context_ref')==owner.context.ref and result.get('runtime_ref')==owner.context.value['runtime_ref'] and
         result.get('assembly_operation_ref')==owner.context.value['operation_ref'] and result.get('case_ref')==case_ref and
         result.get('execution_operation')=={'path':str(owner.operation_output/'operation.json'),
                                             'operation_id':owner.operation_id},'game_result_scope')
    need(case.get('schema_version')==1 and type(case.get('schema_version')) is int and
         case.get('scope')=='development_direct_game_v1' and case.get('game_context_ref')==owner.context.ref and
         case.get('runtime_ref')==owner.context.value['runtime_ref'] and
         case.get('execution_operation')==result['execution_operation'] and case.get('game_qualified') is False,
         'game_result_case_binding')
    need(all(result.get(key) is True for key in ('cleanup_passed','authority_passed',
        'host_bootstrap_arm64_no_rosetta','runtime_unchanged')),'game_result_harness')
    need(case.get('error') is None and case.get('stream_error') is None and
         case.get('cleanup',{}).get('complete') is True and case.get('sentinel_cleanup',{}).get('complete') is True and
         case.get('sentinel_survived') is True and case.get('cleanup_errors')==[] and
         case.get('original_files_unchanged') is True and case.get('producer_dependencies_unchanged') is True and
         not any(case.get(key) for key in ('play_cleanup_error','sampler_cleanup_error','companion_evidence_error')),
         'game_result_cleanup')
    refs=[];companion=game_release._companions(case['companion_processes_ref'],output,owner.operation_id,
                                               owner.owner[0],refs,{}, {})
    need(all(row['present'] for row in companion['sessions'].values()),'game_result_companion_sessions')
    for row in companion['sessions'].values():
        for child in row['processes'].values():
            need(child['reaped'] is True and type(child['exit_code']) is int and child['fork_seen'] is False and
                 child['setup_error'] is None,'game_result_companion_cleanup')
    for name in ('companion-result.json','hud-result.json'):
        need(name in companion['record_refs'],'game_result_companion_receipt')
        record=core.read_ref(companion['record_refs'][name])
        need(record.get('cleanup',{}).get('complete') is True and not record.get('errors') and
             all(row.get('eof') is True and row.get('write_error') is None for row in record['logs']),
             'game_result_companion_cleanup')
    owner.assert_current(output,owner.operation_id)
    return case_ref


def observe_game(owner):
    """Preserve the selected original owner's finally observations on failed runs too."""
    module=importlib.import_module('pear_runtime.fixtures.game_observations')
    expected=owner.captured.refs[('runtime','pear_runtime/fixtures/game_observations.py')]
    need(build.fact(Path(module.__file__).resolve())==expected,'game_observer_source')
    owner.captured.recheck()
    result=module.observe(owner.output)
    if owner.output.is_dir():
        build.write_json(owner.output/'fex-observations.json',result)
        owner.record['fex_observations_ref']=build.fact(owner.output/'fex-observations.json')
    owner.record['fex_observation_status']=result['status']
    owner.captured.recheck()
    return result


def execute(path,*,context,play_factory):
    """Explicit future invocation only; all runtime processes use direct's original owner."""
    global _ACTIVE
    need(os.getpgrp()==os.getpid() and _ACTIVE is None,'game_worker_group_required')
    initial,initial_ref=request(path);started=build.point();record=None;operation=None;owner=None;error=None
    not_after=time.monotonic_ns()+WHOLE_TIMEOUT_SECONDS*10**9
    try:
        with interrupts(),deadline(initial['limits']['whole_timeout_seconds']),_current_lease() as (held,lease_guard):
            value,ref,captured,plan=review(path,context)
            need(value==initial and ref==initial_ref,'game_request_changed')
            need(play_factory is _symbol(captured,'tools.development.game.feedback','bind_factory'),
                 'game_play_factory_binding')
            operation=Path(plan['operation_output']);operation.mkdir(mode=0o700)
            record=dict(schema_version=1,scope='development_game_operation',operation_id=str(uuid.uuid4()),
                status='running',request_ref=ref,plan=plan,not_after_monotonic_ns=not_after,worker=dict(pid=os.getpid(),process_group=os.getpgrp(),
                interpreter_ref=build.fact(Path(sys.executable).resolve(strict=True)),interpreter_version=sys.version,
                argv=list(sys.argv)),lock={**held,'released':False},intervals=[],runtime_execution_attempted=False,
                runtime_execution_performed=False,game_qualified=False,independent_release_required=True)
            owner=GameOperation(_TOKEN,context,ref,value,plan,captured,record,lease_guard);owner.active=True;_ACTIVE=owner
            build.write_json(operation/'operation.json',record)
            record['predecessor_resources_ref']=game_prerequisites.observe_predecessors(owner)
            owner.assert_current(owner.output,owner.operation_id)
            record['storage']=context.storage_admission(owner.output)
            owner.runtime,owner.runtime_value=context.begin_game(owner.output,operation=owner)
            budget=LogBudget(value['limits']['worker_log_bytes'])
            with (operation/'stdout.log').open('xb') as stdout,(operation/'stderr.log').open('xb') as stderr:
                with redirect_stdout(BoundedLog(stdout,budget)),redirect_stderr(BoundedLog(stderr,budget)):
                    from . import direct
                    record['runtime_execution_attempted']=True
                    run_error=None
                    try:result=direct.run_game(context,owner.output,play_factory=play_factory)
                    except BaseException as primary:
                        run_error=primary
                        raise
                    finally:
                        try:observations=observe_game(owner)
                        except BaseException as observation_error:
                            record['fex_observation_error']=core.failure_details(observation_error)
                            if run_error is None:raise
                            run_error.add_note('FEX observation evidence also failed: '+getattr(observation_error,'code',type(observation_error).__name__))
                    need(observations['status']=='assessed','game_fex_observation_incomplete')
                    context.finalize_assessment(owner.output)
                    owner.assert_current(owner.output,owner.operation_id)
                    result_admission(result,owner)
                    record['result_ref']=build.fact(owner.output/'assessment.json')
            captured.recheck();record['status']='passed'
    except BaseException as failure:
        error=failure
        if record is not None:record.update(status='failed',error=core.failure_details(failure))
        raise
    finally:
        if owner is not None:owner.active=False;owner.phase='released'
        _ACTIVE=None
        if record is not None:
            evidence_failure=None
            def evidence_error(failure):
                nonlocal evidence_failure
                if evidence_failure is None:evidence_failure=failure
                record.update(status='failed',evidence_error=core.failure_details(failure))
                if error is not None:error.add_note('Game operation evidence also failed: '+getattr(failure,'code',type(failure).__name__))
            record['lock'].update(released=True,release_observed=build.point())
            record['timing']=build.span('game_worker_before_final_receipt',started)
            case=Path(record['plan']['output'])/'case.json'
            if case.is_file():
                try:
                    observed=build.load(case);record['case_ref']=build.fact(case)
                    record['runtime_execution_performed']=bool(observed.get('launches'))
                    record['cleanup']=observed.get('cleanup');record['sentinel_survived']=observed.get('sentinel_survived')
                    record['play_companions_ref']=observed.get('play_companions')
                    record['companion_processes_ref']=observed.get('companion_processes_ref')
                except BaseException as failure:evidence_error(failure);record['runtime_execution_performed']='unknown'
            elif record['runtime_execution_attempted']:record['runtime_execution_performed']='unknown'
            record['logs']={}
            for name in ('stdout','stderr'):
                log=operation/(name+'.log')
                if log.is_file():
                    try:record['logs'][name]=build.fact(log)
                    except BaseException as failure:evidence_error(failure)
            try:build.write_json(operation/'operation.json',record)
            except BaseException as failure:
                if error is None and evidence_failure is None:raise
                (error if error is not None else evidence_failure).add_note('Game final receipt write also failed: '+getattr(failure,'code',type(failure).__name__))
            if error is None and evidence_failure is not None:raise evidence_failure
    return dict(status='passed',operation_ref=build.fact(operation/'operation.json'),result_ref=record['result_ref'],
                runtime_execution_performed=record['runtime_execution_performed'],game_qualified=False,
                independent_release_required=True)
