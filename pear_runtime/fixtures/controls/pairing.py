# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later AND MIT
"""Original 39-case v1 and 23-case v2 pairing oracles, without a launcher.

The v2 table and controls retain their original MIT permissions. The v1 legacy
Pear source retains its repository license. See fixture-controls-import.json.
Native architecture, launch/ownership and live authorization are separate gates.
"""
import re
from pear_runtime.assembly._common import decode_json, record
from pear_runtime.errors import need

def fields(value, names, kind=None):
    need(isinstance(value, dict) and set(value) == set(names), 'record_fields')
    if kind:
        record(value, kind)

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

PE_FIELDS = ('primary_step','primary_error','control_status','bridge_status','cleanup_error',
             'cleanup_flags','completed_phases')

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

SURFACE_CASES=[('getter_present',0),('version',2),('size',3),('features',4),('null_output',1),
       ('valid_table',0),('invalid_window',5),('null_device',7),('wrong_context',11),
       ('allocation_rollback',8),('allocation_no_client',6),('registration_rollback',8),
       ('registration_no_client',6),('create_missing',0),('share_owned',0),
       ('release_first',0),('remaining_live',0),('release_last',0),('recreate_missing',0),('detached_stale',10),('detached_release',0),('final_no_client',6),
       ('foreign_surface',11)]

def controls(stderr):
    records=[]
    for line in stderr.splitlines():
        if not line.startswith(b'PEAR_SURFACE_CONTROL'):continue
        m=re.fullmatch(rb'PEAR_SURFACE_CONTROL name=(\w+) status=(\d+) expected=(\d+) facts=(\d+)',line)
        need(m is not None,'surface_control_malformed')
        name=m[1].decode();status,expected,facts=map(int,m.groups()[1:]);records.append((name,status,expected,facts))
    need([r[0] for r in records]==[r[0] for r in SURFACE_CASES],'surface_control_set')
    need(all((status,expected,facts)==(want,want,1) for (_,status,expected,facts),(_,want) in zip(records,SURFACE_CASES)),
         'surface_control_failed')
    return dict(passed=True,case_count=len(records),cases=[dict(name=n,status=s) for n,s,e,f in records])
