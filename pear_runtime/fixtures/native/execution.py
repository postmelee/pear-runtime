# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Original native case execution and assessment behind exact current admission."""
from pathlib import Path
import copy
import re

from pear_runtime.assembly import core
from pear_runtime.assembly.helpers import PAYLOAD
from pear_runtime.errors import Error, need
from pear_runtime.fixtures.inputs import fact, save
from pear_runtime.fixtures.supervision import assessment_packet
from .binding import ROLES, DRIVER
from .context import NativeContext, API_CASES, CASES
from .provider import native_helpers, bootstrap_assessment, validate_suite_authorization, NATIVE_SEED_POLICY, menu_configuration


def authority(ref, context):
    value=core.read_ref(ref)
    need(value.get('passed') is True and value.get('runtime_sha256')==context.value['runtime_ref']['sha256'] and
         value.get('operation_ref')==context.value['operation_ref'],'native_current_authority')
    return value


def packet_for(context, value, authority_ref):
    authority(authority_ref,context)
    packet=assessment_packet(value)
    packet['entrypoints'].update({role:PAYLOAD+'/'+row[0] for role,row in ROLES.items()})
    packet['entrypoints']['window_driver_pe']=DRIVER
    if context._case=='api':
        packet['entrypoints']['api_pe']=context.variant['fixture_ref']['path']
        packet['native_api_variant']=context.variant
    packet['native_images']=[dict(row,source_path=row['path']) for row in value['native_images']]
    packet['native_fixture_policy']={'scope':'development_native_wine_controls',
        'runtime_ref':context.value['runtime_ref'],'operation_ref':context.value['operation_ref'],
        'authority_ref':authority_ref,'requirements':{'fixture_suite':'mac-driver',
            'guest_fixtures':{role:{'execution_permitted':False,
                'sha256':context.inputs['candidate_refs'][role]['sha256']} for role in ('x64_control','i386_control')}}}
    packet['native_fixture_policy']['requirements']['guest_fixtures']['lifetime_dll']={
        'machine':0xaa64,'execution_permitted':True,
        'sha256':context.inputs['candidate_refs']['lifetime_dll']['sha256']}
    validate_suite_authorization('mac-driver',packet)
    return packet


def _failure(exc):return {'type':type(exc).__name__,'code':getattr(exc,'code',str(exc))}


def _case_error(result):
    value=result.get('error')
    return value.get('code') if type(value) is dict else value


def run(context, case_id, output):
    need(type(context) is NativeContext and callable(context.execution_interval) and case_id in CASES,
         'native_execution_context')
    with context.execution_interval(output):
        budget=context.storage_admission(output);runtime,value=context.begin(case_id,output)
        output=Path(output);output.mkdir(mode=0o700);save(output/'storage.json',budget)
        record={'schema_version':1,'scope':'development_native_fixture_run','case_id':case_id,
            'context_ref':context.ref,'runtime_ref':context.value['runtime_ref'],
            'assembly_operation_ref':context.value['operation_ref'],'profile_ref':context.value['profile_ref'],
            'execution_operation':context.execution_operation,'producer_manifest_ref':context.value['producer_manifest_ref'],
            'binding_ref':context.value['binding_ref'],'status':'started','error':None,'secondary_errors':[],
            'before_ref':None,'after_ref':None,'case_ref':None,'static_controls':None,'prefix_origin':None,
            'prefix_policy':NATIVE_SEED_POLICY if case_id in API_CASES else 'fresh-empty-bootstrap-no-pe',
            'cold_prefix_initialization':False,
            'runtime_qualified':False,'game_qualified':False}
        save(output/'control.json',record);primary=None;interrupted=False
        try:
            context.preserve_sources(output)
            context.current_authority(output/'before');record['before_ref']=fact(output/'before/control.json')
            packet=packet_for(context,value,record['before_ref'])
            with native_helpers(context.provider_root,variant=context.variant if case_id=='api' else None,
                                seed=context.seed_adapter if case_id in API_CASES else None) as (life,helpers):
                record['static_controls']=helpers.api.target_controls(runtime,packet)
                config=context.api_cases if case_id in API_CASES else context.bootstrap_cases
                case=next(row for row in config['cases'] if row['id']==case_id)
                if case_id in API_CASES:
                    result=helpers.api.run_case(case,runtime,packet,output/case_id,config['bounds'])
                else:
                    result=helpers.base.run_case(case,runtime,packet['entrypoints'],output/case_id,config['bounds'])
                if case_id in API_CASES:
                    record['prefix_origin']=dict(helpers.seed_observation)
                # Original run_case preserves operation failure and cleanup.
                # A consumed one-shot whole deadline cannot start fresh authority.
                code=_case_error(result)
                if code in ('assembly_worker_timeout','runner_interrupted'):
                    interrupted=True;raise Error(code)
                if code is not None:raise Error(str(code))
                need(result.get('passed') is True,result.get('assessment_error') or 'native_case_failed')
                if case_id in API_CASES:
                    need(record['prefix_origin'].get('cold_prefix_initialization') is False,'native_seed_unobserved')
            record['status']='executed'
        except BaseException as exc:
            primary=exc;interrupted=interrupted or isinstance(exc,KeyboardInterrupt) or getattr(exc,'code',None)=='assembly_worker_timeout'
            record['status']='failed';record['error']=_failure(exc)
        finally:
            if not interrupted:
                try:
                    context.current_authority(output/'after');record['after_ref']=fact(output/'after/control.json')
                    authority(record['after_ref'],context)
                except BaseException as exc:
                    if primary is None:primary=exc;record['status']='failed';record['error']=_failure(exc)
                    else:record['secondary_errors'].append(_failure(exc))
            try:context.finish()
            except BaseException as exc:
                if primary is None:primary=exc;record['status']='failed';record['error']=_failure(exc)
                else:record['secondary_errors'].append(_failure(exc))
            path=output/case_id/'case.json'
            if path.is_file() and not path.is_symlink():record['case_ref']=fact(path)
            save(output/'control.json',record)
        if primary is not None:
            save(output/'native-assessment.json',{'passed':False,'error':record['error'],'game_qualified':False})
            raise primary
        try:
            result=assess(context,output)
            result['producer_snapshot_ref']=context.finalize_assessment(output)
        except BaseException as exc:
            save(output/'native-assessment.json',{'passed':False,'error':_failure(exc),'game_qualified':False})
            raise
        save(output/'native-assessment.json',result)
        return result


def assess(context, output):
    need(type(context) is NativeContext and context._completed and context._validated_end and not context._active and
         Path(output)==context._output,'native_assessment_interval')
    output=Path(output);record=core.read_ref(fact(output/'control.json'));case_id=context._case
    need(record['scope']=='development_native_fixture_run' and record['status']=='executed' and
         record['error'] is None and record['secondary_errors']==[] and record['case_id']==case_id and
         record['context_ref']==context.ref and record['runtime_ref']==context.value['runtime_ref'] and
         record['assembly_operation_ref']==context.value['operation_ref'] and
         record['profile_ref']==context.value['profile_ref'] and
         record['execution_operation']==context.execution_operation and
         record['producer_manifest_ref']==context.value['producer_manifest_ref'] and
         record['binding_ref']==context.value['binding_ref'],'native_assessment_binding')
    runtime,value=context._admit()
    if case_id in API_CASES:
        from pear_runtime.fixtures.inputs import digest
        from pear_runtime.assembly._common import encoded
        origin=record['prefix_origin']
        need(origin=={'seed_ref':context.base['seed_ref'],
             'inventory_sha256':digest(encoded(context.base['seed_inventory'])),
             'cold_prefix_initialization':False,'staged_modules':context.base['modules'],
             'policy':NATIVE_SEED_POLICY,
             'configuration':menu_configuration((context.seed/'run/prefix/system.reg').read_bytes())[1]},
             'native_seed_observation')
    else:need(record['prefix_origin'] is None,'native_bootstrap_seed_forbidden')
    need(record['cold_prefix_initialization'] is False and record['prefix_policy']==
         (NATIVE_SEED_POLICY if case_id in API_CASES else 'fresh-empty-bootstrap-no-pe'),
         'native_prefix_policy')
    for side in ('before','after'):
        need(record[side+'_ref']['path']==str(output/side/'control.json'),'native_authority_path')
        authority(record[side+'_ref'],context)
    packet=packet_for(context,value,record['after_ref'])
    need(record['case_ref']['path']==str(output/case_id/'case.json'),'native_case_path')
    path=core.checked_ref(record['case_ref']); raw=path.read_bytes()
    with native_helpers(context.provider_root,variant=context.variant if case_id=='api' else None) as (life,helpers):
        controls=helpers.api.target_controls(runtime,packet)
        need(controls==record['static_controls'],'native_static_controls_changed')
        config=context.api_cases if case_id in API_CASES else context.bootstrap_cases
        expected=next(row for row in config['cases'] if row['id']==case_id)
        result=(helpers.api.decode_case(raw,suite='mac-driver',case_id=case_id) if case_id in API_CASES
                else helpers.base.decode_json(raw))
        need(result.get('case')==expected and result.get('passed') is True,'native_case_configuration')
        need(type(result.get('nonce')) is str and re.fullmatch('[0-9a-f]{32}',result['nonce']), 'native_nonce')
        if case_id in API_CASES:
            prefix=output/case_id/'prefix';info=prefix.stat()
            need(not prefix.is_symlink() and result['prefix']['device']==info.st_dev and
                 result['prefix']['inode']==info.st_ino,'api_prefix_changed')
            helpers.api.validate_duration(result.get('elapsed_ms'),expected['timeout_ms'],config['bounds'])
            logs=helpers.api.verify_logs(output,case_id,result,suite='mac-driver')
            observed=helpers.api.assess_case(result,logs,runtime,packet,case_root=output/case_id)
        else:
            bootstrap_assessment(life,helpers,context.provider_root)(output,case_id,result,expected,runtime,packet)
            observed={'passed':True,'expected':expected['expected'],'outcome':result['outcome'],
                      'native_process_count':3,'pe_executed':False}
    return {'schema_version':1,'scope':'development_native_fixture_assessment','case_id':case_id,'passed':True,
        'context_ref':context.ref,'runtime_ref':context.value['runtime_ref'],
        'assembly_operation_ref':context.value['operation_ref'],'execution_operation':context.execution_operation,
        'case_ref':record['case_ref'],'before_ref':record['before_ref'],'after_ref':record['after_ref'],
        'observations':observed,'static_controls':controls,'input_evidence':copy.deepcopy(context.input_evidence),
        'prefix_policy':record['prefix_policy'],'cold_prefix_initialization':False,
        'prefix_origin':record['prefix_origin'],'pe_executed':case_id in API_CASES,
        'runtime_qualified':False,'game_qualified':False}
