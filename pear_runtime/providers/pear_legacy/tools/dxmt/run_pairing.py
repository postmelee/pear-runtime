#!/usr/bin/env python3
"""Run and replay one owned ordinary ARM64 Wine/Metal pairing fixture.

Actual source-built/signature admission is supplied by pairing_runtime. This
finite source-matched route never admits a hybrid DLL, translator or game.
"""
from __future__ import annotations
import argparse
import ast
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import signal
import sys
import time
import uuid
from types import SimpleNamespace

from common import (REPO, Error, decode_json, digest, encoded, fields, need,
                    output_directory, owned_directory, read_relative, relative,
                    sha256, write_new)

WINE_HELPERS = ('common', 'prepare', 'toolchain', 'modules', 'abi_review',
                'dynamic_evidence', 'exception_evidence', 'run_fixtures', 'api_runner')
METAL_ENV = {'MTL_DEBUG_LAYER': '1', 'MTL_DEBUG_LAYER_ERROR_MODE': 'assert',
             'MTL_DEBUG_LAYER_WARNING_MODE': 'nslog', 'MTL_SHADER_VALIDATION': '1',
             'MTL_SHADER_VALIDATION_FAIL_MODE': 'zerofill',
             'MTL_SHADER_VALIDATION_REPORT_TO_STDERR': '1'}
BOUNDS = {'grace_ms': 3000, 'terminate_ms': 2000, 'kill_ms': 5000, 'drain_ms': 1000}
TIMEOUT_MS = 180000
CASES = [
    ('getter_version',2),('getter_size',3),('getter_features',4),('getter_null',1),('getter_valid',0),
    ('null_device',7),('invalid_window',5),('no_client',6),('unknown_lease',10),('foreign_owner',11),
    ('acquire_a',0),('acquire_b',0),('query_live',0),('layer_callback',0),('layer_exception',13),
    ('layer_reentry',0),('release_b',0),('double_release_b',10),('dxmt_acquire',0),('dxmt_get_props',0),
    ('dxmt_set_props',0),('dxmt_next_drawable',0),('dxmt_colorspace',0),('dxmt_edr',0),('dxmt_display',0),
    ('dxmt_release',0),('resize_live',0),('replacement_stale',10),('release_invalid',0),
    ('replacement_acquire',0),('detach_stale',10),('detach_release',0),('destroy_acquire',0),
    ('destroy_stale',10),('destroy_missing',5),('destroy_release',0),('cleanup',0),('dxmt_dlclose',0),('lifetime',0)]
NATIVE_FIELDS = ('case_id','status','expected_status','facts','lease_count','attachment_count','main_thread',
                 'x18_mode','delegate_state','created_views','deallocated_views','created_layers',
                 'deallocated_layers','created_proxies','deallocated_proxies')
CASE_FIELDS = ('schema_version','record_kind','case','nonce','prefix','outcome','error','stream_error',
    'elapsed_ms','base_environment','loader_environment','graphical_session','events','logs','cleanup',
    'sentinel_cleanup','sentinel_survived','registrations','pre_cleanup','signal_observations',
    'processes','launches','cleanup_errors','ordinary_arm64_pe_execution_performed','passed',
    'assessment_error','hybrid_execution_performed','translated_guest_execution_performed',
    'game_qualified','runtime_eligible')
PE_FIELDS = ('primary_step','primary_error','control_status','bridge_status','cleanup_error',
             'cleanup_flags','completed_phases')


def local(path, alias, raw=None):
    """Compile captured Python bytes under a fixed isolated module identity."""
    spec=importlib.util.spec_from_file_location(alias,path)
    need(spec is not None and spec.loader is not None,'pair_run_helper')
    module=importlib.util.module_from_spec(spec)
    sys.modules[alias]=module
    try:
        if raw is None: raw=read_relative(Path(path).parent,Path(path).name)
        exec(compile(raw,str(path),'exec'),vars(module))
    except BaseException:
        sys.modules.pop(alias,None)
        raise
    return module


def producers(repo=REPO):
    names=['tools/dxmt/run_pairing.py','tools/dxmt/pairing_check.py','tools/dxmt/pairing_runtime.py']
    names += ['tools/wine/'+name+'.py' for name in WINE_HELPERS]
    return {name:digest(read_relative(repo,name)) for name in sorted(names)}


@contextmanager
def wine_helpers(repo=REPO, expected=None):
    """Load captured unchanged Wine bytes into a restored import namespace.

    These are the reviewed pure readers/supervisor, not source-build scripts.
    Capturing before compilation binds the bytes actually loaded to their proof.
    """
    captured={name:read_relative(repo,'tools/wine/'+name+'.py') for name in WINE_HELPERS}
    if expected is not None:
        need(all(expected.get('tools/wine/'+name+'.py')==digest(raw)
                 for name,raw in captured.items()),'pair_run_helper_changed')
    previous={name:sys.modules.get(name) for name in WINE_HELPERS}
    try:
        for name in WINE_HELPERS:
            local(Path(repo)/'tools/wine'/(name+'.py'),name,captured[name])
        api=sys.modules['api_runner']; base=sys.modules['run_fixtures']
        # Reuse the complete original function with one source-owned marker in
        # an isolated globals copy; no repository/global EVENT set is changed.
        tree=ast.parse(captured['api_runner'])
        nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='assess_native_events']
        need(len(nodes)==1 and not nodes[0].decorator_list,'pair_native_assessor_source')
        namespace=dict(vars(api));namespace['EVENTS']=api.EVENTS | {'metal_pairing_images'}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'tools/wine/api_runner.py','exec'),namespace)
        yield SimpleNamespace(api=api,base=base,dynamic=sys.modules['dynamic_evidence'],
                              Error=sys.modules['common'].Error,
                              assess_native=namespace['assess_native_events'])
    finally:
        for name,module in previous.items():
            if module is None:sys.modules.pop(name,None)
            else:sys.modules[name]=module


def integer(value,low=0,high=2**64-1):
    return type(value)is int and low<=value<=high


def native_rows(raw):
    need(type(raw)is bytes and len(raw)<=262144,'pair_native_log_bound')
    rows,diagnostics=[],bytearray()
    for line in raw.splitlines(keepends=True):
        if line.startswith(b'{"record_kind":"pear_metal_pairing"'):
            need(line.endswith(b'\n') and len(line)<=3072,'pair_native_row_bound')
            value=decode_json(line,3072)
            fields(value,['record_kind','version','case',*NATIVE_FIELDS])
            need(value['record_kind']=='pear_metal_pairing' and type(value['version'])is int and value['version']==1
                 and type(value['case'])is str and all(integer(value[key],-2**31 if key in ['status','expected_status'] else 0,
                 2**31-1 if key in ['status','expected_status'] else 2**64-1)
                 for key in NATIVE_FIELDS),'pair_native_row_fields')
            rows.append(value)
        else:
            need(not (line.lstrip().startswith(b'{') and b'pear_metal_pairing' in line),
                 'pair_native_unrecognized_row')
            diagnostics.extend(line)
    need(len(rows)==len(CASES),'pair_native_case_count')
    leases={'acquire_a':1,'acquire_b':2,'query_live':2,'layer_callback':2,'layer_exception':2,'layer_reentry':2,
            'release_b':1,'double_release_b':1,'dxmt_acquire':2,'dxmt_get_props':2,'dxmt_set_props':2,
            'dxmt_next_drawable':2,'dxmt_colorspace':2,'dxmt_edr':2,'dxmt_display':2,'dxmt_release':1,
            'resize_live':1,'replacement_stale':1,'replacement_acquire':1,'detach_stale':1,
            'destroy_acquire':1,'destroy_stale':1,'destroy_missing':1}
    previous=[0]*6
    for index,(row,(name,status))in enumerate(zip(rows,CASES),1):
        expected_leases=leases.get(name,0)
        need(row['case_id']==index and row['case']==name and row['status']==row['expected_status']==status
             and row['facts']==1 and row['lease_count']==expected_leases
             and row['attachment_count']==int(expected_leases>0),'pair_native_case_failed')
        need(row['main_thread']==(1 if index>=14 else 0) and row['x18_mode']==0
             and row['delegate_state']==(1 if index>=14 else 0),'pair_native_main_mode')
        observed=[row[key] for key in ['created_views','deallocated_views','created_layers',
                    'deallocated_layers','created_proxies','deallocated_proxies']]
        views=0 if index<14 else (1 if index<30 else (2 if index<33 else 3))
        proxy=int(index>=20)
        need(observed[0]==observed[2]==views and observed[4]==proxy
             and all(value>=old for value,old in zip(observed,previous))
             and all(observed[i+1]<=observed[i] for i in [0,2,4]),'pair_lifetime_observation')
        previous=observed
    need(previous==[3,3,3,3,1,1],'pair_physical_lifetime_unknown')
    return {'case_count':len(rows),'physical_lifetime':'observed_balanced',
            'created_views':3,'deallocated_views':3,'created_layers':3,'deallocated_layers':3,
            'created_proxies':1,'deallocated_proxies':1,'final_lease_count':0,'final_attachment_count':0},bytes(diagnostics)


def pe_rows(raw,helper,loader):
    lines=raw.splitlines(keepends=True)
    need(len(lines)==2 and all(line.endswith(b'\n') and len(line)<=3072 for line in lines), 'pair_pe_output_count')
    helper.base.validate_helper(decode_json(lines[0],3072),'pear_bootstrap_helper',loader)
    value=decode_json(lines[1],3072)
    fields(value,['record_kind','version',*PE_FIELDS])
    need(value['record_kind']=='pear_metal_pairing_pe' and type(value['version'])is int and value['version']==1
         and all(integer(value[key],0,2**32-1)for key in PE_FIELDS),'pair_pe_terminal_fields')
    need(all(value[key]==0 for key in PE_FIELDS if key not in ['cleanup_flags','completed_phases'])
         and value['cleanup_flags']==7 and value['completed_phases']==6,'pair_pe_terminal_failed')
    return {'completed_phases':6,'primary_error':0,'cleanup_error':0,'cleanup_flags':7}


def environment(work,prefix,nonce):
    need(type(nonce)is str and len(nonce)==32 and all(c in '0123456789abcdef'for c in nonce),'pair_nonce')
    value={'PATH':'/usr/bin:/bin','TMPDIR':str(work/'tmp'),'LANG':'C','LC_ALL':'C','WINEPREFIX':str(prefix),
           'WINEDEBUG':'-all','PEAR_BOOTSTRAP_NONCE':nonce,'PEAR_BOOTSTRAP_GENERATION':'0',**METAL_ENV}
    if 'HOME'in os.environ:value['HOME']=os.environ['HOME']
    return value


def assessment_packet(value):
    rows=[row for row in value['native_images']if row['origin']['role']=='baseline-native'
          and row['origin']['path'].endswith('/ntdll.so')]
    need(len(rows)==1,'pair_runtime_ntdll')
    return {'entrypoints':{'loader':value['entrypoints']['loader'],'server':value['entrypoints']['server'],
            'api_launch':value['entrypoints']['bootstrap_helper'],'ntdll':rows[0]['path']},
            'native_images':value['native_images'],'arena_capacity':value['arena_capacity'],
            'code_publication_policy':'page-wx'}


def verify_logs(root,result):
    observed={};total=0
    for row in result['logs']:
        fields(row,['role','channel','path','sha256','bytes','observed_bytes','eof','write_error'])
        key=(row['role'],row['channel'])
        need(key not in observed and row['path']==row['role']+'.'+row['channel']+'.log'
             and row['channel']in ['stdout','stderr','events'],'pair_log_set')
        limit=2097152 if row['channel']=='events'else 262144
        raw=read_relative(root,row['path'],limit)
        need(type(row['bytes'])is int and type(row['observed_bytes'])is int
             and row['bytes']==row['observed_bytes']==len(raw)
             and row['eof']is True and row['write_error']is None and digest(raw)==row['sha256'],'pair_log_changed')
        if row['channel']=='events':
            need(not raw or raw.endswith(b'\n'),'pair_event_truncation');total+=len(raw)
        observed[key]=raw
    need(total<=32*1024**2,'pair_event_total')
    wanted={(role,channel)for role in ['loader','server','sentinel']for channel in ['stdout','stderr']}
    wanted|={(role,'events')for role in result['events']}
    need(set(observed)==wanted,'pair_log_coverage')
    return observed


def launch_recipes(runtime,value,env,loader_env,pipe_fd):
    need(integer(pipe_fd,3,2**20),'pair_sentinel_pipe_fd')
    paths={key:str(runtime.joinpath(*relative(path)))for key,path in value['entrypoints'].items()}
    return {
        'sentinel':([paths['sentinel'],str(pipe_fd)],env),
        'server':([paths['server'],'-f','-p'],env),
        'loader':([paths['bootstrap_helper'],'--exec-4k',paths['loader'],paths['fixture_pe']],loader_env),
    }


def validate_launches(result,runtime,value):
    rows=result['launches']
    need(type(rows)is list and len(rows)==3,'pair_launch_coverage')
    fields(rows[0],['role','argv','environment','pid','started'])
    argv=rows[0]['argv']
    need(type(argv)is list and len(argv)==2 and type(argv[1])is str and argv[1].isascii()
         and argv[1].isdecimal() and str(int(argv[1]))==argv[1],'pair_sentinel_pipe_fd')
    recipes=launch_recipes(runtime,value,result['base_environment'],result['loader_environment'],int(argv[1]))
    for row,role in zip(rows,['sentinel','server','loader']):
        fields(row,['role','argv','environment','pid','started'])
        need(row['role']==role and row['started']is True and type(row['pid'])is int
             and row['pid']==result['processes'][role]['identity']['pid']
             and encoded([row['argv'],row['environment']])==encoded(recipes[role]),'pair_launch_changed')


def passive_dynamic_observations(result,packet,helper):
    """Reuse the exact passive source process reader, with no dynamic-code test.

    The original top-level dispatcher accepts its historical case names only.
    This adapter keeps the unchanged process proof and explicitly disallows
    translated/dynamic execution, signal fixtures and prior window fixtures.
    """
    need(not any(row['event']in helper.api.STAGE4_EVENTS|helper.api.STAGE5_EVENTS
         for rows in result['events'].values()for row in rows),'pair_unselected_native_fixture')
    capacity=packet['arena_capacity'];supported='dynamic_limits'in capacity;observations=[]
    for role,rows in result['events'].items():
        selected=helper.dynamic.dynamic_rows(rows)
        executes=any(row['event']=='stage3_pe_continue'for row in rows)
        if not supported or not executes:
            need(not selected,'pair_unexpected_dynamic_events')
            continue
        need(role!='server','pair_dynamic_server_execution')
        reservations=[row for row in rows if row['event']=='arena_reserve']
        need(len(reservations)==1,'pair_dynamic_arena_reservation')
        facts=helper.dynamic._process(rows,capacity,reservations[0],False)
        observations.append({'role':role,**facts})
    need(not supported or any(row['role']=='loader'for row in observations),'pair_dynamic_budget_missing')
    return {'dynamic_supported':supported,'scope':'passive_source_budget_and_protection',
            'processes':observations,'dynamic_execution_test_performed':False}


def assess_case(result,raw,runtime,value,helper):
    fields(result,CASE_FIELDS,'dxmt_pairing_case')
    need(encoded(result['case'])==encoded({'id':'metal','timeout_ms':TIMEOUT_MS,'expected_exit':0})
         and result['passed']is False and result['assessment_error']is None and result['cleanup_errors']==[]
         and result['ordinary_arm64_pe_execution_performed']is True
         and all(result[key]is False for key in ['hybrid_execution_performed',
         'translated_guest_execution_performed','game_qualified','runtime_eligible']),'pair_case_scope')
    need(result['error']is None and result['stream_error']is None and result['outcome']=='exited'
         and type(result['processes']['loader']['exit_code'])is int
         and result['processes']['loader']['exit_code']==0,'pair_run_failed')
    need(encoded(result['graphical_session'])==encoded({'status':0,'available':True}),'pair_graphical_session')
    need(set(result['processes'])=={'loader','server','sentinel'},'pair_process_coverage')
    identities=[row.get('identity')for row in result['processes'].values()]
    need(all(type(item)is dict and set(item)=={'pid','ppid','start_sec','start_usec'}
         and all(type(number)is int for number in item.values()) and item['pid']>1 and item['ppid']>1
         and item['start_sec']>0 and 0<=item['start_usec']<1000000 for item in identities)
         and len({item['pid']for item in identities})==3 and len({item['ppid']for item in identities})==1,
         'pair_direct_identity')
    validate_launches(result,runtime,value)
    paths={role:str((runtime/value['entrypoints'][role]).resolve())for role in ['loader','server','sentinel']}
    for role,process in result['processes'].items():
        allowed=sorted([paths[role],str((runtime/value['entrypoints']['bootstrap_helper']).resolve())]
                       if role=='loader'else[paths[role]])
        fields(process,['identity','allowed_paths','exit_code','reaped'])
        need(process['allowed_paths']==allowed and process['reaped']is True
             and type(process['exit_code'])is int,'pair_process_paths')
    for name,roles in [('cleanup',{'loader','server'}),('sentinel_cleanup',{'sentinel'})]:
        row=result[name]
        need(row['complete']is True and row['errors']==[] and row['observation_gap']is False
             and set(row['reaped'])==roles and all(item is True for item in row['reaped'].values()),'pair_cleanup_incomplete')
        need(all(item['role']in roles and type(item['signal'])is int
             and item['signal']in [int(signal.SIGINT),int(signal.SIGTERM),int(signal.SIGKILL)]for item in row['signals']),
             'pair_cleanup_signal_scope')
    need(result['sentinel_survived']is True and result['sentinel_cleanup']['signals']==[]
         and type(result['processes']['sentinel']['exit_code'])is int
         and result['processes']['sentinel']['exit_code']==0,'pair_sentinel_lost')
    sentinel=[decode_json(line)for line in raw[('sentinel','stdout')].splitlines()]
    need(len(sentinel)==2 and sentinel[1]=={'version':1,'record_kind':'pear_sentinel_done','signal':0,'command':81},
         'pair_sentinel_records')
    helper.base.validate_helper(sentinel[0],'pear_sentinel_ready',SimpleNamespace(identity=result['processes']['sentinel']['identity']))
    for role,rows in result['events'].items():
        need([decode_json(line,32768)for line in raw[(role,'events')].splitlines()]==rows,'pair_event_log_changed')
    server_code=result['processes']['server']['exit_code']
    need(server_code==0 or server_code in [-int(signal.SIGINT),-int(signal.SIGTERM),-int(signal.SIGKILL)]
         and any(item['role']=='server'and item['signal']==-server_code for item in result['cleanup']['signals']),
         'pair_server_native_failure')
    packet=assessment_packet(value)
    pe_count=helper.assess_native(result,runtime,packet)
    need(pe_count>=2,'pair_wineboot_unobserved')
    markers=[(role,index,row)for role,rows in result['events'].items()for index,row in enumerate(rows)
             if row['event']=='metal_pairing_images']
    need(len(markers)==1 and markers[0][0]=='loader','pair_metal_snapshot_count')
    _,index,marker=markers[0]
    helper.base.native_snapshot(marker,4096)
    need(marker['prefix_error']==0 and marker['prefix_dev']==result['prefix']['device']
         and marker['prefix_ino']==result['prefix']['inode'],'pair_metal_snapshot_prefix')
    rows=result['events']['loader'];images=[];at=index+1
    while at<len(rows)and rows[at]['event']=='image':images.append(rows[at]);at+=1
    need(images and at<len(rows)and rows[at]['event']=='images_end'and rows[at]['count']==len(images),
         'pair_metal_snapshot_incomplete')
    for key in ['winemac_native','winemetal_native']:
        expected=str((runtime/value['entrypoints'][key]).resolve())
        need(sum(str(Path(row['path']).resolve())==expected for row in images)==1,'pair_metal_native_image_missing')
    need(any(row['event']=='stage3_guest_exit'and type(row.get('exit_code'))is int
         and row['exit_code']==0 for row in rows),'pair_guest_exit_missing')
    arena=helper.api.assess_arena_events(result,packet,[])
    dynamic=passive_dynamic_observations(result,packet,helper)
    helper.api.assess_descendant_exits(result)
    native,diagnostics=native_rows(raw[('loader','stderr')])
    terminal=pe_rows(raw[('loader','stdout')],helper,SimpleNamespace(identity=result['processes']['loader']['identity']))
    return {**native,'pe_terminal':terminal,'ordinary_arm64_pe_execution_performed':True,
            'registered_pe_process_count':pe_count,'arena_observations':arena,'dynamic_observations':dynamic,
            'native_pairing_observed':True,'diagnostics':{'sha256':digest(diagnostics),'size_bytes':len(diagnostics),
            'review':'unperformed','scope':'captured_nonfixture_loader_stderr'},
            'hybrid_execution_performed':False,'translated_guest_execution_performed':False,
            'game_qualified':False,'runtime_eligible':False,'distribution_qualified':False}


def failure_detail(exc,default):
    return {'code':getattr(exc,'code',default),'exception_type':type(exc).__name__,
            'errno':exc.errno if isinstance(exc,OSError)else None}


def finish_capture(session,output,errors):
    """Preserve available stream bytes if the reviewed finalizer itself fails."""
    try:return session.finish_logs(BOUNDS['drain_ms'])
    except (Exception,KeyboardInterrupt)as exc:
        errors.append({'operation':'finish_logs',**failure_detail(exc,'pair_log_finalization')})
    rows=[]
    for (role,channel),item in session.streams.items():
        raw=bytes(item['data']);name=role+'.'+channel+'.log';write_error=None
        try:
            target=output/name
            if target.exists()or target.is_symlink():
                need(read_relative(output,name)==raw,'pair_partial_log_changed')
            else:
                with target.open('xb')as stream:stream.write(raw)
        except (Exception,KeyboardInterrupt)as exc:
            write_error=getattr(exc,'code','pair_failure_log_write')
            errors.append({'operation':'write_log',**failure_detail(exc,write_error)})
        rows.append({'role':role,'channel':channel,'path':name,'sha256':digest(raw),'bytes':len(raw),
            'observed_bytes':item['total_bytes'],'eof':item['eof'],'write_error':write_error})
    return rows


def cleanup_session(session,control,read_fd,output):
    """Attempt all owned cleanup operations without replacing a primary error."""
    errors=[];survived=False
    def perform(operation,call,default=None):
        try:return call()
        except (Exception,KeyboardInterrupt)as exc:
            errors.append({'operation':operation,**failure_detail(exc,'pair_cleanup_operation')})
            return default
    if read_fd is not None:perform('close_read_fd',lambda:os.close(read_fd))
    perform('pre_cleanup_refresh',session.observer.refresh)
    pre_cleanup={'at_ns':time.monotonic_ns(),'processes':{row['role']:{'exited':row['exited'],
        'exit_code':row['exit_code'],'exit_status':row['exit_status']}
        for row in session.observer.registrations.values()}}
    incomplete={'signals':[],'errors':[{'role':'observer','code':'pair_cleanup_operation'}],
                'observation_gap':True,'reaped':{},'complete':False}
    cleanup=perform('owned_group_cleanup',lambda:session.cleanup(('loader','server'),BOUNDS))
    if cleanup is None:
        # A raised loader cleanup must not suppress the reserved server cleanup.
        server=perform('server_fallback_cleanup',lambda:session.cleanup(('server',),BOUNDS),incomplete)
        cleanup={**incomplete,'signals':server['signals'],'errors':incomplete['errors']+server['errors'],
                 'reaped':server['reaped']}
    if 'sentinel'in session.children:
        child=session.children['sentinel']
        def sentinel_finish():
            session.observer.refresh()
            alive=not child.exited and session.observer.identity(child.pid)==child.identity
            if alive:
                need(os.write(control,b'Q')==1,'pair_sentinel_stop_write')
                end=time.monotonic()+3
                while not child.exited and time.monotonic()<end:session.pump()
            return alive
        survived=perform('sentinel_finish',sentinel_finish,False)
    if control is not None:perform('close_control_fd',lambda:os.close(control))
    sentinel_cleanup=perform('sentinel_cleanup',lambda:session.cleanup(('sentinel',),BOUNDS),incomplete)
    logs=finish_capture(session,output,errors)
    return pre_cleanup,cleanup,sentinel_cleanup,logs,survived,errors


def run_case(runtime,value,output,helper):
    for path in [output/'prefix',output/'work',output/'work/tmp']:path.mkdir(mode=0o700)
    prefix=output/'prefix';prefix_info=helper.base.prefix_identity(prefix)
    nonce=uuid.uuid4().hex;packet=assessment_packet(value)
    session=helper.api.APISession(output,runtime,packet,nonce,suite='api-abi',case_id='metal')
    env=environment(output/'work',prefix,nonce)
    paths={key:runtime.joinpath(*relative(path))for key,path in value['entrypoints'].items()}
    read_fd,control=None,None;start=time.monotonic();deadline=start+TIMEOUT_MS/1000
    remaining=lambda cap:max(0,min(cap,deadline-time.monotonic()))
    error,outcome=None,'not_started';loader_env=None;graphical=None;launches=[]
    def launch(role,argv,selected_env,**kwargs):
        row={'role':role,'argv':argv,'environment':selected_env,'pid':None,'started':None}
        launches.append(row)
        child=session.launch(role,argv,selected_env,**kwargs)
        row.update({'pid':child.pid,'started':True})
        return child
    try:
        read_fd,control=os.pipe()
        graphical=helper.api.graphical_session();need(graphical=={'status':0,'available':True},'pair_graphical_session')
        sentinel=launch('sentinel',[str(paths['sentinel']),str(read_fd)],env,pass_fds=(read_fd,))
        os.close(read_fd);read_fd=None
        need(session.wait_for(lambda:b'\n'in session.streams[('sentinel','stdout')]['data'],remaining(5)),'pair_sentinel_start')
        helper.base.validate_helper(helper.base.parse_lines(session,'sentinel')[0],'pear_sentinel_ready',sentinel)
        server=launch('server',[str(paths['server']),'-f','-p'],env,event_pipe=True)
        need(session.wait_for(lambda:any(row.get('event')=='server_ready'for row in session.events['server'])
             or server.exited,remaining(30))and not server.exited,'pair_server_start')
        loader_env={**env,'PEAR_STAGE3_CONTROL':session.endpoint,'PEAR_WINE_ABI_FIXTURE':'1',
                    'PEAR_BOOTSTRAP_SERVER_PID':str(server.pid),'WINEDLLOVERRIDES':'mscoree=',
                    'PEAR_DXMT_PAIRING_FIXTURE':'1','PEAR_DXMT_PAIRING_UNIXLIB':str(paths['winemetal_native'])}
        session.output=output/'work'
        try:
            loader=launch('loader',[str(paths['bootstrap_helper']),'--exec-4k',str(paths['loader']),str(paths['fixture_pe'])],
                          loader_env,allowed_paths=[paths['bootstrap_helper'],paths['loader']])
        finally:session.output=output
        outcome='exited'if session.wait_for(lambda:loader.exited,remaining(TIMEOUT_MS/1000))else'timeout'
    except KeyboardInterrupt:error,outcome='pair_run_interrupted','interrupted'
    except Exception as exc:error,outcome=getattr(exc,'code','pair_run_operation_failed'),'error'
    finally:
        pre_cleanup,cleanup,sentinel_cleanup,logs,survived,cleanup_errors=cleanup_session(
            session,control,read_fd,output)
    result={'schema_version':1,'record_kind':'dxmt_pairing_case','case':{'id':'metal','timeout_ms':TIMEOUT_MS,'expected_exit':0},
            'nonce':nonce,'prefix':prefix_info,'outcome':outcome,'error':error,'stream_error':session.failure,
            'elapsed_ms':round((time.monotonic()-start)*1000),'base_environment':env,'loader_environment':loader_env,
            'graphical_session':graphical,'events':session.events,'logs':logs,'cleanup':cleanup,'sentinel_cleanup':sentinel_cleanup,
            'sentinel_survived':survived,'registrations':list(session.observer.registrations.values()),'pre_cleanup':pre_cleanup,
            'signal_observations':session.observer.signal_observations,'launches':launches,'cleanup_errors':cleanup_errors,
            'processes':{role:{'identity':child.identity,'allowed_paths':sorted(child.allowed_paths),
            'exit_code':child.exit_code,'reaped':child.reaped}for role,child in session.children.items()},
            'ordinary_arm64_pe_execution_performed':(True if any(row.get('event')in
            ['stage3_pe_continue','stage3_guest_exit']for rows in session.events.values()for row in rows)else
            (None if any(row['role']=='loader'for row in launches)else False)),
            'passed':False,'assessment_error':None,'hybrid_execution_performed':False,'translated_guest_execution_performed':False,
            'game_qualified':False,'runtime_eligible':False}
    write_new(output/'case.json',result)
    try:assessment=assess_case(result,verify_logs(output,result),runtime,value,helper)
    except Exception as exc:
        write_new(output/'assessment.json',{'passed':False,'error':getattr(exc,'code','pair_assessment_failed')})
        # Preserve the actual operation failure; assessment refusal is secondary.
        raise Error(error or getattr(exc,'code','pair_assessment_failed'))from exc
    write_new(output/'assessment.json',{'passed':True,'error':None,'observations':assessment})
    return result,assessment


def runtime_values(root,repo=REPO):
    raw=read_relative(repo,'tools/dxmt/pairing_runtime.py')
    helper=local(Path(repo)/'tools/dxmt/pairing_runtime.py','_pear_dxmt_runtime_admission',raw)
    value=helper.verify_runtime(root,repo=repo)
    need(value['code_publication_policy']=='page-wx'and value['runtime_eligible']is False
         and value['game_qualified']is False,'pair_runtime_scope')
    return value


def run(runtime,output,repo=REPO):
    runtime=owned_directory(runtime,repo);runtime_value=runtime_values(runtime,repo)
    root=output_directory(output,repo)
    receipts={'runtime_ref':{'path':str(runtime),'sha256':digest(read_relative(runtime,'runtime.json'))},
              'producers':{},'bounds':BOUNDS,'timeout_ms':TIMEOUT_MS,'metal_environment':METAL_ENV}
    phase='preparation'
    try:
        receipts['producers']=producers(repo)
        for name,sha in receipts['producers'].items():
            path=root/'producers'/name;path.parent.mkdir(parents=True,exist_ok=True)
            raw=read_relative(repo,name);need(digest(raw)==sha,'pair_run_producer_changed')
            with path.open('xb')as stream:stream.write(raw)
        phase='execution'
        with wine_helpers(repo,receipts['producers'])as helper:
            result,assessment=run_case(runtime,runtime_value,root,helper)
        phase='post_execution_replay'
        need(runtime_values(runtime,repo)==runtime_value and receipts['producers']==producers(repo),
             'pair_run_inputs_changed')
        value={'schema_version':1,'record_kind':'dxmt_pairing_run','scope':'finite_native_metal_pairing',**receipts,
               'case_ref':{'path':'case.json','sha256':digest(read_relative(root,'case.json'))},
               'assessment_ref':{'path':'assessment.json','sha256':digest(read_relative(root,'assessment.json'))},
               'native_pairing_observed':True,'ordinary_arm64_pe_execution_performed':True,'diagnostics_review':'unperformed',
               'passed':True,'hybrid_execution_performed':False,'translated_guest_execution_performed':False,
               'game_qualified':False,'runtime_eligible':False,'distribution_qualified':False}
        write_new(root/'run.json',value)
        return value
    except (Exception,KeyboardInterrupt)as exc:
        write_new(root/'failed.json',{'schema_version':1,'record_kind':'dxmt_pairing_run_failure',**receipts,
            'phase':phase,**failure_detail(exc,'pair_run_failed'),'passed':False,'runtime_eligible':False})
        raise Error(getattr(exc,'code','pair_run_interrupted'if isinstance(exc,KeyboardInterrupt)else'pair_run_failed'))from exc


def verify_run(root,repo=REPO):
    root=owned_directory(root,repo);need(not(root/'failed.json').exists(),'pair_failed_run')
    record=decode_json(read_relative(root,'run.json'))
    fields(record,['schema_version','record_kind','scope','runtime_ref','producers','bounds','timeout_ms','metal_environment',
        'case_ref','assessment_ref','native_pairing_observed','ordinary_arm64_pe_execution_performed','diagnostics_review','passed',
        'hybrid_execution_performed','translated_guest_execution_performed','game_qualified','runtime_eligible','distribution_qualified'],
        'dxmt_pairing_run')
    need(record['scope']=='finite_native_metal_pairing'and record['passed']is True and record['native_pairing_observed']is True
         and record['ordinary_arm64_pe_execution_performed']is True and record['diagnostics_review']=='unperformed'
         and all(record[name]is False for name in ['hybrid_execution_performed','translated_guest_execution_performed',
         'game_qualified','runtime_eligible','distribution_qualified']),'pair_run_scope')
    need(encoded(record['producers'])==encoded(producers(repo))and encoded(record['bounds'])==encoded(BOUNDS)
         and type(record['timeout_ms'])is int and record['timeout_ms']==TIMEOUT_MS
         and record['metal_environment']==METAL_ENV,'pair_run_inputs_changed')
    for name,sha in record['producers'].items():need(digest(read_relative(root,'producers/'+name))==sha,'pair_run_producer_snapshot')
    fields(record['runtime_ref'],['path','sha256'])
    runtime=owned_directory(record['runtime_ref']['path'],repo)
    need(digest(read_relative(runtime,'runtime.json'))==record['runtime_ref']['sha256'],'pair_run_runtime_changed')
    value=runtime_values(runtime,repo)
    for key,path in [('case_ref','case.json'),('assessment_ref','assessment.json')]:
        fields(record[key],['path','sha256'])
        need(record[key]['path']==path and digest(read_relative(root,path))==record[key]['sha256'],'pair_run_receipt_changed')
    result=decode_json(read_relative(root,'case.json',16*1024**2),16*1024**2,max_nodes=1000000)
    need(result['case']=={'id':'metal','timeout_ms':TIMEOUT_MS,'expected_exit':0},'pair_run_case_scope')
    from common import real_directory
    info=real_directory(root/'prefix').stat()
    fields(result['prefix'],['device','inode','namespace'])
    expected_namespace=str(Path('/private/tmp')/('.wine-'+str(os.getuid()))/f'server-{info.st_dev:x}-{info.st_ino:x}')
    need(result['prefix']['namespace']==expected_namespace and
         type(result['prefix']['device'])is int and type(result['prefix']['inode'])is int and result['prefix']['device']==info.st_dev and result['prefix']['inode']==info.st_ino,
         'pair_run_prefix_changed')
    env=environment(root/'work',root/'prefix',result['nonce'])
    need(result['base_environment']==env,'pair_run_environment_changed')
    endpoint=result['loader_environment']['PEAR_STAGE3_CONTROL']
    endpoint_path=Path(endpoint)
    need(endpoint_path.parent.parent==Path('/private/tmp')and '..'not in endpoint_path.parts
         and endpoint_path.name=='control'and endpoint_path.parent.name.startswith('pear-stage3-'),
         'pair_run_control_endpoint')
    expected={**env,'PEAR_STAGE3_CONTROL':endpoint,'PEAR_WINE_ABI_FIXTURE':'1',
              'PEAR_BOOTSTRAP_SERVER_PID':str(result['processes']['server']['identity']['pid']),
              'WINEDLLOVERRIDES':'mscoree=','PEAR_DXMT_PAIRING_FIXTURE':'1',
              'PEAR_DXMT_PAIRING_UNIXLIB':str(runtime/value['entrypoints']['winemetal_native'])}
    need(result['loader_environment']==expected,'pair_run_loader_environment_changed')
    with wine_helpers(repo,record['producers'])as helper:
        try:
            helper.api.validate_duration(result['elapsed_ms'],TIMEOUT_MS,BOUNDS)
            actual=assess_case(result,verify_logs(root,result),runtime,value,helper)
        except helper.Error as exc:raise Error(exc.code)from exc
    need(encoded(decode_json(read_relative(root,'assessment.json')))==encoded(
         {'passed':True,'error':None,'observations':actual}),
         'pair_run_assessment_changed')
    return actual


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',required=True);parser.add_argument('--output',required=True)
    parser.add_argument('--require-empty',required=True,action='store_true')
    args=parser.parse_args(argv)
    try:
        run(args.runtime,args.output)
        print(encoded({'native_pairing_observed':True,'ordinary_arm64_pe_execution_performed':True,
            'diagnostics_review':'unperformed','hybrid_execution_performed':False,'runtime_eligible':False}).decode(),end='')
        return 0
    except (Error,OSError,KeyError,ValueError,TypeError)as exc:
        print(encoded({'passed':False,'runtime_eligible':False,'error':getattr(exc,'code','pair_run_failed')}).decode(),end='',file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
