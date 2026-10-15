# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact pure Wine owner/bitmap/PE metadata oracles on explicit synthetic inputs.

These retain original record schemas, not an executable compatibility launcher.
Current build, assembly, supervision and admission remain the runtime APIs.
"""
from pathlib import Path
from collections import Counter
import re
import struct
from pear_runtime.assembly._common import encoded, decode_json, read_relative
from pear_runtime.errors import Error, need
from pear_runtime.fixtures.inputs import digest as digest_bytes
from pear_runtime.fixtures.supervision import environment, loader_environment, supervision, STREAM_LIMIT
from pear_runtime.fixtures.controls.execution import _translated_logs as verify_logs
from . import bitmap as bitmap_policy, resume as atomic_checks, pe as builder

def fields(value, names, kind=None):
    need(type(value) is dict and set(value) == set(names), 'memory_wine_run_fields')
    if kind:
        need(type(value['schema_version']) is int and value['schema_version'] == 1
             and value['record_kind'] == kind, 'memory_wine_run_kind')


def same(left,right,code):
    need(encoded(left) == encoded(right),code)


def integer(value,low=0,high=2**53-1):
    return type(value) is int and low <= value <= high


def json_lines(raw,limit=4096):
    need(type(raw) is bytes and 0<len(raw)<=STREAM_LIMIT and raw.endswith(b'\n'),'memory_wine_stdout_bound')
    lines=raw.splitlines(keepends=True)
    need(len(lines)<=limit and all(line.endswith(b'\n') and len(line)<=32768 for line in lines),
         'memory_wine_stdout_shape')
    return [decode_json(line,32768) for line in lines]


def suite_contract():
    """Closed finite original fixture cases, independently checked in Wine scope.

    Reuse decision: retain the source fixture and its reviewed control counts,
    but do not project fabricated native-admission rows into memory_run's parser.
    """
    counts={'reserve_extent':103,'retire_extent':103,'begin_two_page_write':39,'publish_two_pages':39,
        'enter_owned_leaf':73,'exit_to_native_gate':73,'begin_cross_page_instruction_pair':1,
        'publish_cross_page_instruction_pair':1,'enter_before_source_continuation':1,
        'pin_saved_source_resume':1,'direct_owned_handoff_to_native':1,'poll_existing_owned_handoff':1,
        'admit_finite_saved_resume':127,'discard_owned_saved_resume':127,'release_original_pin_epoch':1,
        'begin_unpublished_abort_control':1,'abort_unpublished_window':1,
        'register_actual_native_executor':1,'query_current_token':103,'mixed_extent_query_unavailable':112,
        'unregister_actual_native_executor':1}
    refusals={'version_mismatch':2,'record_size_mismatch':1,'unknown_opcode':1,'unknown_flags':1,
        'reserved_word':1,'reserved_word64':1,'foreign_owner':6,'stale_generation':6,'foreign_allocation':6,
        'offset_alias':6,'extent_alias':6,'unselected_role':1,'native_fixture_cannot_select_arm64ec_role':3,
        'wrapped_write_range':1,'source_guard_write':1,'empty_write':1,'ordinary_exit_cannot_drop_saved_resume':1,
        'nested_handoff_refused':1,'poll_requires_original_pin_epoch':1,'poll_requires_exact_resume_offset':1,
        'poll_requires_existing_continuation':1,'unregister_cannot_drop_saved_resume':1,
        'retirement_keeps_saved_generation':3,'continuation_capacity_preserves_old_pins':4,
        'new_epoch_cannot_release_original_pin':1,'duplicate_retirement':6,'shared_capacity_exhausted':4,
        'fragmented_free_bytes_refused':4,'dispatcher_capacity_exhausted':4}
    counts.update(dict.fromkeys(refusals,1))
    opcodes=dict.fromkeys(counts,6)
    opcodes.update({'register_actual_native_executor':7,'reserve_extent':1,'begin_two_page_write':2,
        'publish_two_pages':3,'enter_owned_leaf':8,'exit_to_native_gate':9,'begin_cross_page_instruction_pair':2,
        'publish_cross_page_instruction_pair':3,'enter_before_source_continuation':8,'pin_saved_source_resume':10,
        'direct_owned_handoff_to_native':13,'poll_existing_owned_handoff':13,'admit_finite_saved_resume':10,
        'discard_owned_saved_resume':11,'release_original_pin_epoch':11,'begin_unpublished_abort_control':2,
        'abort_unpublished_window':4,'retire_extent':5,'unregister_actual_native_executor':12,'unknown_opcode':16,
        'native_fixture_cannot_select_arm64ec_role':7,'wrapped_write_range':2,'source_guard_write':2,'empty_write':2,
        'ordinary_exit_cannot_drop_saved_resume':9,'nested_handoff_refused':13,'poll_requires_original_pin_epoch':13,
        'poll_requires_exact_resume_offset':13,'poll_requires_existing_continuation':13,
        'unregister_cannot_drop_saved_resume':12,'retirement_keeps_saved_generation':5,
        'continuation_capacity_preserves_old_pins':10,'new_epoch_cannot_release_original_pin':11,
        'duplicate_retirement':5,'shared_capacity_exhausted':1,'fragmented_free_bytes_refused':1,
        'dispatcher_capacity_exhausted':1})
    atomic_counts, atomic_refusals, atomic_opcodes = atomic_checks.controls('wine_owner')
    counts.update(atomic_counts); refusals.update(atomic_refusals); opcodes.update(atomic_opcodes)
    return counts,refusals,opcodes


def bootstrap_observation(row,child,helper):
    fields(row,('version','record_kind','pid','ppid','start_sec','start_usec','cpu_type',
        'translation_value','query_errno','user_page','vm_page','kernel_page','kernel_error'))
    need(integer(row['version'],1,1) and row['record_kind']=='pear_bootstrap_helper'
         and all(type(row[k]) is int and row[k]==v for k,v in child.identity.items())
         and integer(row['user_page']) and row['user_page'] in (4096,16384),'memory_wine_bootstrap_identity')
    helper.base.native_snapshot(row,row['user_page'])


def owner_output(raw,child,helper):
    rows=json_lines(raw);need(len(rows)>6,'memory_wine_fixture_count')
    bootstrap_observation(rows[0],child,helper)
    for row,(control,opcode) in zip(rows[1:4],[('register_readiness_native_executor',7),
        ('query_readiness_native_owner',6),('unregister_readiness_native_executor',12)]):
        wanted={'version':1,'record_kind':'pear_fex_memory_wine','event':'readiness_call','control':control,
                'opcode':opcode,'returned_status':0,'status':0,'native_error_domain':0,'native_error_code':0}
        same(row,wanted,'memory_wine_readiness')
    calls=rows[4:-2];counted,refusals,opcodes=suite_contract();counts=Counter()
    keys={'version','record_kind','scope','sequence','event','control','opcode','returned_status','status',
        'requested_state','operation_offset','operation_size','allocation_id','generation','extent_offset',
        'extent_size','write_epoch','executor_id','continuation_id','executor_state','lifecycle','protection',
        'capabilities','native_error_domain','native_error_code'}
    for sequence,row in enumerate(calls,1):
        fields(row,keys)
        need(row['record_kind']=='pear_fex_memory_fixture' and row['scope']=='wine_owner'
             and row['event']=='owner_call' and integer(row['version'],1,1)
             and integer(row['sequence'],sequence,sequence),'memory_wine_call_order')
        need(type(row['control']) is str and row['control'] in counted,'memory_wine_control')
        numbers=keys-{'record_kind','scope','event','control','operation_offset','operation_size'}
        need(all(integer(row[k],-2**31 if k=='native_error_code' else 0,
             2**31-1 if k=='native_error_code' else 2**53-1) for k in numbers),'memory_wine_call_type')
        need(all(type(row[k]) is str and re.fullmatch('[0-9a-f]{16}',row[k]) for k in
             ('operation_offset','operation_size')),'memory_wine_range_encoding')
        status=3 if row['control']=='mixed_extent_query_unavailable' else refusals.get(row['control'],0)
        need(row['status']==row['returned_status']==status and row['opcode']==opcodes[row['control']]
             and row['requested_state'] in range(6) and row['executor_state'] in range(6)
             and row['lifecycle'] in range(6) and row['protection'] in range(3)
             and row['capabilities'] & ~7 == 0 and row['native_error_domain'] in range(4)
             and (row['native_error_domain'] or row['native_error_code']==0)
             and (status or row['native_error_domain']==row['native_error_code']==0),'memory_wine_call_status')
        if status:
            need(all(row[k]==0 for k in ('allocation_id','generation','extent_offset','extent_size','write_epoch',
                 'executor_id','continuation_id','executor_state','lifecycle','protection','capabilities')),
                 'memory_wine_refusal_facts')
        counts[row['control']]+=1
    need(counts==counted,'memory_wine_control_counts')
    atomic_checks.validate(calls, need, scope='wine_owner')
    terminal={'version':1,'record_kind':'pear_fex_memory_fixture','scope':'wine_owner',
        'sequence':len(calls)+1,'event':'suite_complete','passed':True,'checked_ec':False,
        'owner_calls':len(calls),'refusals':sum(row['status']!=0 for row in calls),'allocations':103,
        'retirements':103,'publications':40,'owned_code_calls':73,'protection_observations':83,
        'patch_rounds':32,'fragmentation_controls':1,'continuation_controls':2,
        'fex_initialization':False,'translated_guest_execution':False,'game_execution':False}
    same(rows[-2],terminal,'memory_wine_suite_terminal')
    finish=rows[-1]
    fields(finish,('version','record_kind','event','native_arm64_pe_execution','virtual_query_observations',
        'checked_ec','ec_registration_exercised','wine_view_registration','fex_initialization',
        'translated_guest_execution','game_execution','exit_code'))
    wanted={'version':1,'record_kind':'pear_fex_memory_wine','event':'finish','native_arm64_pe_execution':True,
        'checked_ec':False,'ec_registration_exercised':False,'wine_view_registration':True,
        'fex_initialization':False,'translated_guest_execution':False,'game_execution':False,'exit_code':0}
    same({k:v for k,v in finish.items() if k!='virtual_query_observations'},wanted,'memory_wine_finish')
    need(integer(finish['virtual_query_observations'],83,100000),'memory_wine_virtual_query_count')
    shared=sum(row['control']=='reserve_extent' and row['status']==0 and row['extent_size']>=16777216
               for row in calls)
    need(shared==38,'memory_wine_shared_reservation_count')
    return {'readiness_calls':3,**{k:terminal[k] for k in ('owner_calls','refusals','allocations','retirements',
        'publications','owned_code_calls','protection_observations','patch_rounds','fragmentation_controls',
        'continuation_controls')},'virtual_query_observations':finish['virtual_query_observations'],
        'shared_reservation_count':shared,'wine_view_registration_observed':True,'checked_ec':False,
        'arm64ec_role_qualified':False,'fex_initialization':False}


def bitmap_output(raw,expected):
    need(type(raw) is bytes and len(raw)<=STREAM_LIMIT and integer(expected,1,128),'memory_wine_bitmap_bound')
    try:
        pairs,diagnostics=bitmap_policy.parse_stream(raw,expected)
    except bitmap_policy.Refused as exc:
        raise Error('memory_wine_bitmap_diagnostic_'+str(exc)) from exc
    for pair in pairs:
        row=pair['bitmap']
        need(all(row[k] is True for k in ('set_observed','clear_observed','restoration_observed',
             'none_before','none_after','actual_peb_bitmap','restoration_attempted'))
             and row['hybrid_classification'] is False and integer(row['error_domain'],0,0)
             and integer(row['error_code'],0,0),'memory_wine_bitmap_failed')
    return {'self_tests':len(pairs),'actual_peb_bitmap_observed':True,'set_read_clear_read_observed':True,
        'none_before_and_after_observed':True,'source_view_and_bitmap_restoration_observed':True,
        'diagnostic_self_tests':len(pairs),
        'diagnostic_rows_sha256':digest_bytes(encoded([pair['diagnostic'] for pair in pairs])),
        'hybrid_classification':False,'arm64ec_role_qualified':False}, diagnostics


def apiset_defaults(data):
    """Read Wine's actual ARM64 PE .apiset v6 table; never infer from filenames."""
    need(type(data) is bytes and 64<=len(data)<=64*1024**2,'memory_wine_apiset_bytes')
    def uint(fmt,at):
        need(0<=at and at+struct.calcsize('<'+fmt)<=len(data),'memory_wine_apiset_pe_bound')
        return struct.unpack_from('<'+fmt,data,at)[0]
    need(data[:2]==b'MZ','memory_wine_apiset_pe_header')
    at=uint('I',60);opt=at+24;count=uint('H',at+6);size=uint('H',at+20)
    need(at>=64 and data[at:at+4]==b'PE\0\0' and uint('H',at+4)==0xaa64
         and uint('H',opt)==0x20b and size>=240 and 1<=count<=96,'memory_wine_apiset_pe_header')
    sections=[]
    for i in range(count):
        p=opt+size+i*40;need(p+40<=len(data),'memory_wine_apiset_section_bound')
        if data[p:p+8].rstrip(b'\0')==b'.apiset':
            virtual=uint('I',p+8);span=uint('I',p+16);offset=uint('I',p+20)
            need(28<=virtual<=span and offset+span<=len(data),'memory_wine_apiset_section_bound')
            sections.append(data[offset:offset+virtual])
    need(len(sections)==1,'memory_wine_apiset_section')
    blob=sections[0]
    version,length,flags,entries,entry_offset,hash_offset,factor=struct.unpack_from('<7I',blob)
    need(version==6 and flags==0 and 28<=length<=len(blob) and 0<entries<=4096
         and entry_offset==28 and entry_offset+entries*24<=length
         and hash_offset+entries*8<=length and factor>0,'memory_wine_apiset_header')
    def words(at,count):
        need(0<=at and at+count*4<=length,'memory_wine_apiset_table_bound')
        return struct.unpack_from('<'+str(count)+'I',blob,at)
    def text(at,span):
        need(span>0 and span%2==0 and at>=28 and at+span<=length,'memory_wine_apiset_string_bound')
        try: value=blob[at:at+span].decode('utf-16-le')
        except UnicodeError: raise Error('memory_wine_apiset_string') from None
        need(re.fullmatch('[a-z0-9._-]+',value) is not None,'memory_wine_apiset_string')
        return value
    mapping={};expected_hash=[]
    for i in range(entries):
        flag,nameoff,namelen,hashed,valoff,valcount=words(entry_offset+i*24,6)
        need(flag==1 and hashed>0 and hashed%2==0 and hashed<=namelen and 0<valcount<=64,
             'memory_wine_apiset_entry')
        name=text(nameoff,namelen);need(name not in mapping,'memory_wine_apiset_duplicate')
        targets=[]
        for j in range(valcount):
            vf,selectoroff,selectorlen,targetoff,targetlen=words(valoff+j*20,5)
            need(vf==0 and bool(selectoroff)==bool(selectorlen) and bool(targetoff)==bool(targetlen),
                 'memory_wine_apiset_value')
            selector=text(selectoroff,selectorlen) if selectorlen else None
            target=text(targetoff,targetlen) if targetlen else None
            targets.append((selector,target))
        defaults=[target for selector,target in targets if selector is None]
        need(len(defaults)<=1,'memory_wine_apiset_default_duplicate')
        mapping[name+'.dll']=defaults[0] if defaults else None
        h=0
        for c in name[:hashed//2]:h=(h*factor+ord(c))&0xffffffff
        expected_hash.append((h,i))
    hashes=[words(hash_offset+i*8,2) for i in range(entries)]
    need(sorted(hashes)==sorted(expected_hash) and all(hashes[i][0]<=hashes[i+1][0] for i in range(entries-1)),
         'memory_wine_apiset_hash_index')
    return mapping


class BaselinePEMetadata:
    """Bounded baseline metadata only; no delayed loader or generic admission."""
    def __init__(self,data):
        need(type(data) is bytes and 64<=len(data)<=64*1024**2,'memory_wine_crt_pe_bytes')
        self.data=data
        at=self.number('I',60);self.opt=at+24
        count=self.number('H',at+6);size=self.number('H',at+20)
        need(at>=64 and data[:2]==b'MZ' and data[at:at+4]==b'PE\0\0'
             and self.number('H',at+4)==0xaa64 and self.number('H',self.opt)==0x20b
             and self.number('H',at+22)&0x2000 and self.number('I',self.opt+108)==16
             and size>=240 and 1<=count<=96,'memory_wine_crt_baseline_arm64_dll')
        self.base=self.number('Q',self.opt+24);self.image_size=self.number('I',self.opt+56);self.sections=[]
        for i in range(count):
            p=self.opt+size+i*40
            span,rva,raw_size,raw,flags=[self.number('I',p+n) for n in (8,12,16,20,36)]
            need(raw+raw_size<=len(data) and rva+span<=2**32,'memory_wine_crt_pe_section')
            self.sections.append((rva,min(span,raw_size),raw,flags))
    def number(self,fmt,at):
        need(type(at) is int and 0<=at and at+struct.calcsize('<'+fmt)<=len(self.data),'memory_wine_crt_pe_bound')
        return struct.unpack_from('<'+fmt,self.data,at)[0]
    def mapped(self,rva,size):
        need(type(rva) is int and type(size) is int and rva>0 and size>0 and rva+size<=self.image_size,'memory_wine_crt_rva')
        found=[(raw+rva-base,flags) for base,span,raw,flags in self.sections
               if rva>=base and rva-base+size<=span]
        need(len(found)==1,'memory_wine_crt_rva');return found[0]
    def word(self,rva):return self.number('Q',self.mapped(rva,8)[0])
    def string(self,rva,limit=512):
        at,_=self.mapped(rva,1);end=self.data.find(b'\0',at,min(len(self.data),at+limit))
        need(end>at,'memory_wine_crt_string');self.mapped(rva,end-at+1)
        try:value=self.data[at:end].decode('ascii')
        except UnicodeError:raise Error('memory_wine_crt_string') from None
        need(all(33<=ord(c)<=126 for c in value),'memory_wine_crt_string');return value
    def directory(self,index):return self.number('I',self.opt+112+index*8),self.number('I',self.opt+116+index*8)
    def selected_export(self,name):
        rva,size=self.directory(0);need(rva and rva+size<=2**32 and 40<=size<=1024**2,'memory_wine_crt_export_directory')
        self.mapped(rva,size);p,_=self.mapped(rva,40)
        base=self.number('I',p+16);count=self.number('I',p+20);names=self.number('I',p+24)
        need(0<names<=count<=65536,'memory_wine_crt_export_counts')
        addresses,_=self.mapped(self.number('I',p+28),count*4)
        table,_=self.mapped(self.number('I',p+32),names*4)
        ordinals,_=self.mapped(self.number('I',p+36),names*2)
        selected=[];seen=set()
        for i in range(names):
            actual=self.string(self.number('I',table+4*i))
            need(actual not in seen,'memory_wine_crt_export_duplicate');seen.add(actual)
            index=self.number('H',ordinals+2*i);need(index<count,'memory_wine_crt_export_ordinal')
            if actual!=name:continue
            target=self.number('I',addresses+4*index);need(target,'memory_wine_crt_export_zero')
            if rva<=target<rva+size:
                forward=self.string(target);need(target+len(forward)+1<=rva+size,'memory_wine_crt_forwarder_bound')
                selected.append({'name':name,'ordinal':base+index,'target_kind':'forwarder','forwarder':forward})
            else:
                _,flags=self.mapped(target,4)
                need(target%4==0 and flags&0x20000000,'memory_wine_crt_export_non_executable')
                selected.append({'name':name,'ordinal':base+index,'target_kind':'executable_source_export','forwarder':None})
        need(len(selected)==1,'memory_wine_crt_selected_export_missing');return selected[0]


def ucrt_delay_table(raw):
    """Only the pinned source's two DLLs/three named RVA delay descriptors."""
    pe=BaselinePEMetadata(raw);rva,size=pe.directory(13)
    need(rva%8==0 and size==96 and pe.base>0 and pe.base+pe.image_size<2**64
         and 0<pe.image_size<2**32,'memory_wine_ucrt_delay_directory')
    at,_=pe.mapped(rva,size);wanted=[('advapi32.dll',['SystemFunction036']),
                                  ('user32.dll',['GetActiveWindow','MessageBoxIndirectW'])]
    observations=[];ranges=[(rva,size)]
    def exclusive(start,span):
        pe.mapped(start,span)
        need(all(start+span<=b or b+s<=start for b,s in ranges),'memory_wine_ucrt_delay_slot_alias')
        ranges.append((start,span))
    for i,(module,symbols) in enumerate(wanted):
        attrs,name,handle,iat,int_,bound,unload,timestamp=struct.unpack_from('<8I',raw,at+i*32)
        need(attrs==1 and bound==unload==timestamp==0 and pe.string(name,128)==module,
             'memory_wine_ucrt_delay_descriptor')
        need(handle%8==iat%8==int_%8==0 and pe.word(handle)==0
             and pe.mapped(handle,8)[1]&0x80000000 and pe.mapped(iat,8*(len(symbols)+1))[1]&0x80000000,
             'memory_wine_ucrt_delay_mutable_slots')
        exclusive(name,len(module)+1)
        found=[]
        for j,symbol in enumerate(symbols):
            entry=pe.word(int_+8*j)
            need(0<entry<2**32 and entry%2==0,'memory_wine_ucrt_delay_named_thunk')
            hint=pe.number('H',pe.mapped(entry,2)[0]);actual=pe.string(entry+2)
            need(actual==symbol and hint==0,'memory_wine_ucrt_delay_symbol')
            exclusive(entry,2+len(symbol)+1)
            target=pe.word(iat+8*j)
            need(pe.base>0 and pe.base<=target<pe.base+2**32,'memory_wine_ucrt_delay_thunk_va')
            code=target-pe.base
            need(code%4==0 and code+4<=pe.image_size and pe.mapped(code,4)[1]&0x20000000,'memory_wine_ucrt_delay_thunk_non_executable')
            found.append(symbol)
        need(pe.word(int_+8*len(symbols))==0 and pe.word(iat+8*len(symbols))==0,
             'memory_wine_ucrt_delay_thunk_terminator')
        for start,span in [(handle,8),(iat,8*(len(symbols)+1)),(int_,8*(len(symbols)+1))]:
            exclusive(start,span)
        observations.append({'module':module,'symbols':found,'attributes':attrs,
            'module_handle_zero':True,'int_terminated':True,'iat_terminated':True,
            'initial_iat_executable_thunks_observed':True,'bound_unload_timestamp_zero':True})
    need(raw[at+64:at+96]==b'\0'*32,'memory_wine_ucrt_delay_descriptor_terminator')
    return {'descriptor_count':2,'named_thunk_count':3,'table_bytes':96,
        'table_sha256':digest_bytes(raw[at:at+size]),'imports':observations,'execution':False}


def ucrt_delay_closure(runtime,value,by_name,payload):
    """Selected baseline UCRT imports/export route; other dependencies unperformed."""
    table=ucrt_delay_table(payload(by_name['ucrtbase.dll']))
    built_root=Path(value['build_ref']['path']);source_rows=[]
    specs={
      'dlls/ucrtbase/Makefile.in':['DELAYIMPORTS = advapi32 user32'],
      'dlls/advapi32/advapi32.spec':['@ stdcall SystemFunction036(ptr long) cryptbase.SystemFunction036'],
      'dlls/user32/user32.spec':['@ stdcall GetActiveWindow()','@ stdcall MessageBoxIndirectW(ptr)'],
      'dlls/cryptbase/cryptbase.spec':['@ stdcall SystemFunction036(ptr long)'],
      'include/ntsecapi.h':['#define RtlGenRandom                    SystemFunction036']}
    for path,lines in specs.items():
        raw=read_relative(built_root,'source/'+path,2*1024**2)
        for line in lines:need(raw.splitlines().count(line.encode())==1,'memory_wine_ucrt_delay_source_spec')
        if path=='dlls/ucrtbase/Makefile.in':
            need([line.strip() for line in raw.splitlines() if line.strip().startswith(b'DELAYIMPORTS')]
                 ==[b'DELAYIMPORTS = advapi32 user32'],'memory_wine_ucrt_delay_source_spec')
        source_rows.append({'path':path,'sha256':digest_bytes(raw)})
    # Byte-bind the inspected fallback/generator source without claiming its
    # functions executed or all their transitive dependencies were resolved.
    for path in ('dlls/msvcrt/misc.c','dlls/msvcrt/exit.c','dlls/cryptbase/cryptbase_main.c',
                 'dlls/user32/input.c','dlls/user32/msgbox.c','tools/winebuild/import.c','dlls/ntdll/loader.c'):
        raw=read_relative(built_root,'source/'+path,2*1024**2)
        source_rows.append({'path':path,'sha256':digest_bytes(raw)})
    providers=[];exports=[]
    for module,names in [('advapi32.dll',['SystemFunction036']),('cryptbase.dll',['SystemFunction036']),
                         ('user32.dll',['GetActiveWindow','MessageBoxIndirectW'])]:
        need(module in by_name,'memory_wine_ucrt_delay_provider_missing');row=by_name[module]
        need(row.get('machine')==0xaa64 and row.get('classification')=='ordinary_arm64_image'
             and row.get('load_admission')=='unperformed' and row.get('execution_performed') is False,
             'memory_wine_ucrt_delay_provider_selection')
        raw=payload(row);pe=BaselinePEMetadata(raw)
        selected=[pe.selected_export(name) for name in names]
        for export in selected:
            need(export['forwarder']==('cryptbase.SystemFunction036' if module=='advapi32.dll' else None),
                 'memory_wine_ucrt_delay_forwarder_target')
        providers.append({'name':module,'path':row['path'],'sha256':row['sha256'],'size_bytes':row['size_bytes'],
            'other_delay_directory_present':pe.directory(13)!=(0,0),
            'other_eager_delay_symbol_resolution':'unperformed'})
        exports.append({'module':module,'selected_exports':selected})
    return {'scope':'source_selected_ucrt_delay_module_and_export_bytes','table':table,
        'providers':providers,'selected_exports':exports,'source_files':source_rows,
        'all_provider_dependency_and_symbol_resolution':'unperformed','execution':False}


def crt_closure(runtime,value):
    """Finite fixture's imported module/default-APIset provider byte closure.

    This does not claim all PE named/ordinal/forwarder symbols are resolved;
    actual ordinary execution is a separate gate. The full verified overlay is
    mandatory and its source-built KernelBase/NTDLL providers stay byte-bound.
    """
    rows=value['pe_images'];need(type(rows) is list and rows,'memory_wine_crt_pe_inventory')
    by_name={}
    for row in rows:
        name=Path(row['path']).name.lower()
        if '/aarch64-windows/' in row['path']:
            need(name not in by_name,'memory_wine_crt_duplicate_image');by_name[name]=row
    required=('apisetschema.dll','ucrtbase.dll','kernel32.dll','kernelbase.dll','ntdll.dll')
    need(all(name in by_name for name in required),'memory_wine_crt_missing_provider')
    def payload(row):
        raw=read_relative(runtime,row['path'],64*1024**2)
        need(digest_bytes(raw)==row['sha256'] and len(raw)==row['size_bytes'],'memory_wine_crt_image_changed')
        return raw
    fixture=next((r for r in rows if r['path']==value['entrypoints']['fixture_pe']),None)
    need(fixture is not None and fixture.get('machine')==0xaa64
         and fixture.get('classification')=='ordinary_arm64_image'
         and fixture.get('load_admission')=='unperformed' and fixture.get('execution_performed') is False,
         'memory_wine_crt_fixture_image')
    imports=builder.pe_facts(payload(fixture),False)['imports']
    need(imports and 'kernel32.dll' in imports and all(name=='kernel32.dll' or
         re.fullmatch('api-ms-win-crt-[a-z0-9-]+-l1-1-0.dll',name) for name in imports),
         'memory_wine_crt_fixture_imports')
    apisets=apiset_defaults(payload(by_name['apisetschema.dll']))
    mappings=[]
    for name in imports:
        target=name if name=='kernel32.dll' else apisets.get(name)
        need(target==('kernel32.dll' if name=='kernel32.dll' else 'ucrtbase.dll'),
             'memory_wine_crt_default_target')
        mappings.append({'import':name,'default_provider':target})
    built_root=Path(value['build_ref']['path'])
    source=read_relative(built_root,'source/dlls/apisetschema/apisetschema.spec',2*1024**2)
    for row in mappings:
        if row['import']!='kernel32.dll':
            line=('apiset '+row['import'][:-4]+' = '+row['default_provider']).encode()
            need(source.splitlines().count(line)==1,'memory_wine_crt_source_mapping')
    providers=[];delay=None
    for name in required:
        row=by_name[name]
        need(row.get('machine')==0xaa64 and row.get('classification')=='ordinary_arm64_image'
             and row.get('load_admission')=='unperformed' and row.get('execution_performed') is False,
             'memory_wine_crt_provider_selection')
        raw=payload(row)
        if name=='ucrtbase.dll' and BaselinePEMetadata(raw).directory(13)!=(0,0):
            delay=ucrt_delay_closure(runtime,value,by_name,payload)
        else:
            facts=builder.pe_facts(raw,True)
            need(facts['machine']==0xaa64 and facts['delay_imports'] is False,'memory_wine_crt_provider_architecture')
        providers.append({'name':name,'path':row['path'],'sha256':row['sha256'],'size_bytes':row['size_bytes']})
    return {'scope':'finite_fixture_import_module_and_default_apiset_provider_bytes',
        'imports':mappings,'providers':providers,'source_api_spec_sha256':digest_bytes(source),
        'ucrt_delay_import_closure':delay,
        'complete_named_ordinal_forwarder_symbol_resolution':'unperformed','execution':False}


def failure_detail(exc,default='memory_wine_run_failed'):
    value={'code':getattr(exc,'code',default),'exception_type':type(exc).__name__}
    if isinstance(exc,OSError):value['native_error']={'domain':'errno','code':exc.errno}
    elif isinstance(getattr(exc,'native_error',None),dict):value['native_error']=dict(exc.native_error)
    for field in ('observed_primary','observed_source_failures','failure_record_error'):
        if hasattr(exc,field):value[field]=getattr(exc,field)
    return value


def source_failures(stdout,stderr):
    """Keep actual unexpected source errors distinct from assessment/cleanup.

    A malformed log is preserved raw and reported as parse-unavailable; no
    invented owner failure, success, native errno or allocation identity appears.
    """
    result={'observations':[],'parse_error':None,
        'bitmap_diagnostics':bitmap_policy.observe_failed_prefix(stderr)}
    try:
        counted,refusals,_=suite_contract()
        for row in json_lines(stdout):
            if row.get('event') in ('failed_control','failure'):
                result['observations'].append(row)
            elif row.get('event') in ('readiness_call','owner_call'):
                wanted=3 if row.get('control')=='mixed_extent_query_unavailable' else refusals.get(row.get('control'),0)
                if row.get('status')!=wanted:result['observations'].append(row)
            elif row.get('event')=='suite_complete' and row.get('passed') is not True:
                result['observations'].append(row)
            elif row.get('event')=='finish' and row.get('exit_code')!=0:
                result['observations'].append(row)
    except Exception as exc:result['parse_error']=failure_detail(exc,'memory_wine_failure_parse_unavailable')
    try:
        for line in stderr.splitlines():
            if line.startswith(b'PEAR_FEX_BITMAP '):
                row=decode_json(line[len(b'PEAR_FEX_BITMAP '):],2048)
                if row.get('error_domain') or row.get('error_code') or row.get('restoration_observed') is not True:
                    result['observations'].append({'record_kind':'pear_fex_bitmap_failure',**row})
            elif line.startswith(b'{') and b'pear_fex_memory_launch_failure' in line:
                result['observations'].append(decode_json(line,32768))
    except Exception as exc:
        detail=failure_detail(exc,'memory_wine_stderr_parse_unavailable')
        if result['parse_error'] is None:result['parse_error']=detail
        else:result['secondary_parse_error']=detail
    return result


def require_no_source_failure(value):
    """Assessment only: complete source/raw-stream qualification happens first.

    The prefix observation object never qualifies a count or runtime. Its
    parser refusal blocks the assessment without changing the primary error.
    """
    fields(value,('observations','parse_error','bitmap_diagnostics'))
    diagnostic=value['bitmap_diagnostics']
    fields(diagnostic,('scope','completed_count_qualified','observations','parse_error'))
    need(value['observations']==[] and value['parse_error'] is None
         and diagnostic['scope']=='partial_bitmap_diagnostics'
         and diagnostic['completed_count_qualified'] is False
         and type(diagnostic['observations']) is list
         and diagnostic['parse_error'] is None,'memory_wine_source_failed')


def validate_ready(row, child, nonce):
    import re
    need(isinstance(row, dict) and type(row.get('version')) is int and row['version'] == 1
         and row.get('record_kind') == 'pear_fex_memory_admission' and row.get('event') == 'ready',
         'memory_admission_record')
    need(isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce) is not None,
         'memory_admission_nonce')
    expected = {'pid': child.identity['pid'], 'parent_pid': child.identity['ppid'],
                'start_seconds': child.identity['start_sec'], 'start_microseconds': child.identity['start_usec'],
                'nonce': nonce, 'user_page': 4096, 'vm_page': 4096, 'kernel_page': 16384,
                'translation_result': 0, 'translation_errno': 0, 'translation_value': 0,
                'translation_size': 4, 'user_page_errno': 0, 'kernel_page_result': 0,
                'host_port_release_result': 0, 'cpu_type': 0x100000c, 'jit_supported': 1,
                'geometry_accepted': True, 'restricted_operations_started': False,
                'checked_ec': False, 'wine_view_registration': False}
    need(set(row) == {'version', 'record_kind', 'event'} | set(expected), 'memory_admission_fields')
    need(all(type(row.get(key)) is type(value) and row[key] == value for key, value in expected.items()),
         'memory_admission_geometry_or_identity')


def validate_result(rows, name):
    import re
    from collections import Counter
    need(name in ('pear-fex-memory', 'pear-fex-cooperative'), 'memory_fixture_name')
    need(isinstance(rows, list) and 3 <= len(rows) <= 4096 and all(isinstance(r, dict) for r in rows),
         'memory_fixture_rows')
    header = {'version', 'record_kind'}
    fixture_keys = header | {'scope', 'sequence', 'event', 'control', 'opcode', 'returned_status', 'status',
        'requested_state', 'operation_offset', 'operation_size', 'allocation_id', 'generation', 'extent_offset',
        'extent_size', 'write_epoch', 'executor_id', 'continuation_id', 'executor_state', 'lifecycle', 'protection',
        'capabilities', 'native_error_domain', 'native_error_code'}
    cooperative_keys = header | {'sequence', 'event', 'actor', 'control', 'opcode', 'returned_status', 'status',
        'executor_id', 'continuation_id', 'executor_state', 'write_epoch', 'native_error_domain', 'native_error_code'}
    helper_keys = header | {'pid', 'ppid', 'start_sec', 'start_usec', 'cpu_type', 'translation_value',
        'query_errno', 'user_page', 'vm_page', 'kernel_page', 'kernel_error'}
    native_count_keys = {'owner_calls', 'refusals', 'allocations', 'retirements', 'publications', 'owned_code_calls',
        'protection_observations', 'patch_rounds', 'fragmentation_controls', 'continuation_controls'}
    coop_count_keys = {'owned_workers', 'workers_joined', 'schedules', 'timeout_controls', 'writes', 'handoffs',
        'owned_leaf_calls', 'wire_poll_calls', 'condition_cleanup', 'mutex_cleanup', 'trace_cleanup'}
    scope_false = {'checked_ec', 'fex_initialization', 'translated_guest_execution', 'game_execution'}
    native_complete_keys = header | {'scope', 'sequence', 'event', 'passed'} | native_count_keys | scope_false
    coop_complete_keys = header | {'sequence', 'event', 'passed', 'wine_view_registration'} | coop_count_keys | scope_false
    admission_init_keys = header | {'event', 'status', 'native_error_domain', 'native_error_code',
        'checked_ec', 'wine_view_registration'}
    admission_finish_keys = header | {'event', 'observed_regions', 'native_owned_code_execution',
        'native_arm64_pe_execution', 'wine_view_registration', 'exit_code'} | scope_false
    sequence = Counter()
    calls = []
    helpers, admissions, initializations, suites, finishes, completions = [], [], [], [], [], []
    thread_events = {'thread_create': [], 'thread_join': []}
    for row in rows:
        need(type(row.get('version')) is int and row['version'] == 1, 'memory_fixture_record_header')
        kind, event = row.get('record_kind'), row.get('event')
        need(event not in ('failed_control', 'failure', 'join_incomplete'), 'memory_fixture_control_failed')
        if kind == 'pear_bootstrap_helper':
            need(set(row) == helper_keys, 'memory_fixture_helper_fields')
            need(all(type(row[k]) is int for k in helper_keys - header), 'memory_fixture_helper_types')
            need(row['pid'] > 0 and row['ppid'] > 0 and row['start_sec'] > 0 and 0 <= row['start_usec'] < 1000000
                 and row['cpu_type'] == 0x100000c and row['translation_value'] == row['query_errno'] == row['kernel_error'] == 0
                 and row['user_page'] == row['vm_page'] and row['user_page'] in (4096, 16384)
                 and row['kernel_page'] == 16384, 'memory_fixture_helper_observation')
            helpers.append(row)
        elif kind == 'pear_fex_memory_admission':
            if event == 'ready': admissions.append(row)
            elif event == 'initialize':
                need(set(row) == admission_init_keys and type(row['status']) is int and row['status'] == 0
                     and type(row['native_error_domain']) is int and row['native_error_domain'] == 0
                     and type(row['native_error_code']) is int and row['native_error_code'] == 0,
                     'memory_fixture_initialize')
                initializations.append(row)
            elif event == 'finish':
                need(set(row) == admission_finish_keys and type(row['exit_code']) is int and row['exit_code'] == 0
                     and row['native_owned_code_execution'] is True and row['native_arm64_pe_execution'] is False
                     and type(row['observed_regions']) is int and row['observed_regions'] > 0,
                     'memory_fixture_finish')
                finishes.append(row)
            else: need(False, 'memory_fixture_admission_event')
        elif kind in ('pear_fex_memory_fixture', 'pear_fex_memory_cooperative'):
            need(type(row.get('sequence')) is int and row['sequence'] == sequence[kind] + 1,
                 'memory_fixture_sequence')
            sequence[kind] += 1
            if kind == 'pear_fex_memory_fixture':
                need(row.get('scope') == 'native_owner', 'memory_fixture_scope')
            if event == 'owner_call':
                need(set(row) == (fixture_keys if kind == 'pear_fex_memory_fixture' else cooperative_keys),
                     'memory_fixture_call_fields')
                integer_fields = (set(row) - header - {'event', 'scope', 'control', 'operation_offset', 'operation_size'})
                need(all(type(row[k]) is int for k in integer_fields), 'memory_fixture_call_types')
                need(isinstance(row['control'], str) and re.fullmatch('[a-z][a-z0-9_]{0,95}', row['control']) is not None,
                     'memory_fixture_control_name')
                need(row['status'] == row['returned_status'] and row['status'] in range(9)
                     and row['native_error_domain'] in range(4) and -(1 << 31) <= row['native_error_code'] < (1 << 31)
                     and (row['native_error_domain'] or not row['native_error_code'])
                     and (row['status'] or not (row['native_error_domain'] or row['native_error_code'])),
                     'memory_fixture_call_status')
                need(row['opcode'] in range(1, 16) and row['executor_state'] in range(6)
                     and all(0 <= row[k] <= 2**53-1 for k in integer_fields - {'native_error_code'}),
                     'memory_fixture_call_values')
                facts = {'executor_id', 'continuation_id', 'executor_state', 'write_epoch'}
                if kind == 'pear_fex_memory_fixture':
                    need(row['requested_state'] in range(6) and row['lifecycle'] in range(6)
                         and row['protection'] in range(3) and not row['capabilities'] & ~7,
                         'memory_fixture_call_enums')
                    need(all(isinstance(row[k], str) and re.fullmatch('[0-9a-f]{16}', row[k]) is not None
                             for k in ('operation_offset', 'operation_size')), 'memory_fixture_operation_range')
                    facts |= {'allocation_id', 'generation', 'extent_offset', 'extent_size', 'lifecycle', 'protection', 'capabilities'}
                else:
                    need(row['actor'] in range(4), 'memory_fixture_actor')
                if row['status']: need(all(row[k] == 0 for k in facts), 'memory_fixture_refusal_facts')
                calls.append(row)
            elif kind == 'pear_fex_memory_fixture' and event == 'suite_complete':
                need(set(row) == native_complete_keys and row['passed'] is True, 'memory_fixture_suite_terminal')
                suites.append(row)
            elif kind == 'pear_fex_memory_cooperative' and event in thread_events:
                need(set(row) == header | {'sequence', 'event', 'actor', 'native_error_code'}
                     and type(row['actor']) is int and row['actor'] in range(4)
                     and type(row['native_error_code']) is int and row['native_error_code'] == 0,
                     'memory_cooperative_thread_event')
                thread_events[event].append(row)
            elif kind == 'pear_fex_memory_cooperative' and event == 'complete':
                need(set(row) == coop_complete_keys and row['passed'] is True, 'memory_cooperative_terminal')
                completions.append(row)
            else: need(False, 'memory_fixture_event')
        else: need(False, 'memory_fixture_record_kind')
        for key in ('checked_ec', 'wine_view_registration', 'fex_initialization', 'translated_guest_execution', 'game_execution'):
            if key in row: need(row[key] is False, 'memory_fixture_overclaim')
    need(len(helpers) == len(admissions) == 1 and rows[0] is helpers[0] and rows[1] is admissions[0],
         'memory_fixture_admission_order')
    helper = helpers[0]
    child = type('RecordedIdentity', (), {'identity': {'pid': helper['pid'], 'ppid': helper['ppid'],
        'start_sec': helper['start_sec'], 'start_usec': helper['start_usec']}})()
    validate_ready(admissions[0], child, admissions[0].get('nonce'))
    fixture_calls = [r for r in calls if r['record_kind'] == 'pear_fex_memory_fixture']
    cooperative_calls = [r for r in calls if r['record_kind'] == 'pear_fex_memory_cooperative']
    controls = Counter(r['control'] for r in fixture_calls)
    if name == 'pear-fex-memory':
        need(not cooperative_calls and not completions and len(initializations) == len(suites) == len(finishes) == 1
             and rows[2] is initializations[0] and rows[-2] is suites[0] and rows[-1] is finishes[0],
             'memory_fixture_terminal_order')
        terminal = suites[0]
        expected = {'owner_calls': len(calls), 'refusals': sum(r['status'] != 0 for r in calls),
            'allocations': 103, 'retirements': 103, 'publications': 40, 'owned_code_calls': 73,
            'protection_observations': 83, 'patch_rounds': 32, 'fragmentation_controls': 1, 'continuation_controls': 2}
        need(all(type(terminal.get(k)) is int and terminal[k] == v for k, v in expected.items()),
             'memory_fixture_suite_counts')
        counted = {'reserve_extent': 103, 'retire_extent': 103, 'begin_two_page_write': 39, 'publish_two_pages': 39,
            'enter_owned_leaf': 73, 'exit_to_native_gate': 73, 'begin_cross_page_instruction_pair': 1,
            'publish_cross_page_instruction_pair': 1, 'pin_saved_source_resume': 1,
            'admit_finite_saved_resume': 127, 'discard_owned_saved_resume': 127,
            'release_original_pin_epoch': 1, 'continuation_capacity_preserves_old_pins': 1,
            'begin_unpublished_abort_control': 1, 'abort_unpublished_window': 1}
        counted.update({'register_actual_native_executor': 1, 'query_current_token': 103,
            'mixed_extent_query_unavailable': 112, 'enter_before_source_continuation': 1,
            'direct_owned_handoff_to_native': 1, 'poll_existing_owned_handoff': 1, 'unregister_actual_native_executor': 1})
        refusal_status = {'version_mismatch': 2, 'record_size_mismatch': 1, 'unknown_opcode': 1,
            'unknown_flags': 1, 'reserved_word': 1, 'reserved_word64': 1, 'foreign_owner': 6,
            'stale_generation': 6, 'foreign_allocation': 6, 'offset_alias': 6, 'extent_alias': 6,
            'unselected_role': 1, 'native_fixture_cannot_select_arm64ec_role': 3, 'wrapped_write_range': 1,
            'source_guard_write': 1, 'empty_write': 1, 'ordinary_exit_cannot_drop_saved_resume': 1,
            'nested_handoff_refused': 1, 'poll_requires_original_pin_epoch': 1, 'poll_requires_exact_resume_offset': 1,
            'poll_requires_existing_continuation': 1, 'unregister_cannot_drop_saved_resume': 1,
            'retirement_keeps_saved_generation': 3, 'continuation_capacity_preserves_old_pins': 4,
            'new_epoch_cannot_release_original_pin': 1, 'duplicate_retirement': 6,
            'shared_capacity_exhausted': 4, 'fragmented_free_bytes_refused': 4, 'dispatcher_capacity_exhausted': 4}
        counted.update({control: 1 for control in refusal_status})
        atomic_counts, atomic_refusals, atomic_opcodes = atomic_checks.controls('native_owner')
        counted.update(atomic_counts)
        refusal_status.update(atomic_refusals)
        need(controls == counted, 'memory_fixture_control_counts')
        opcode_by_control = dict.fromkeys(counted, 6)
        opcode_by_control.update({'register_actual_native_executor': 7, 'reserve_extent': 1,
            'begin_two_page_write': 2, 'publish_two_pages': 3, 'enter_owned_leaf': 8,
            'exit_to_native_gate': 9, 'begin_cross_page_instruction_pair': 2,
            'publish_cross_page_instruction_pair': 3, 'enter_before_source_continuation': 8,
            'pin_saved_source_resume': 10, 'direct_owned_handoff_to_native': 13,
            'admit_finite_saved_resume': 10, 'discard_owned_saved_resume': 11,
            'release_original_pin_epoch': 11, 'begin_unpublished_abort_control': 2,
            'abort_unpublished_window': 4, 'retire_extent': 5,
            'unregister_actual_native_executor': 12, 'unknown_opcode': 15,
            'native_fixture_cannot_select_arm64ec_role': 7, 'wrapped_write_range': 2,
            'source_guard_write': 2, 'empty_write': 2, 'ordinary_exit_cannot_drop_saved_resume': 9,
            'nested_handoff_refused': 13, 'poll_existing_owned_handoff': 13, 'poll_requires_original_pin_epoch': 13,
            'poll_requires_exact_resume_offset': 13, 'poll_requires_existing_continuation': 13,
            'unregister_cannot_drop_saved_resume': 12,
            'retirement_keeps_saved_generation': 5, 'continuation_capacity_preserves_old_pins': 10,
            'new_epoch_cannot_release_original_pin': 11, 'duplicate_retirement': 5,
            'shared_capacity_exhausted': 1, 'fragmented_free_bytes_refused': 1,
            'dispatcher_capacity_exhausted': 1})
        opcode_by_control.update(atomic_opcodes)
        atomic_checks.validate(fixture_calls, need, scope='native_owner')
        for row in fixture_calls:
            expected_status = 3 if row['control'] == 'mixed_extent_query_unavailable' else refusal_status.get(row['control'], 0)
            need(row['status'] == expected_status and row['opcode'] == opcode_by_control[row['control']],
                 'memory_fixture_control_status_or_opcode')
        need(sum(r['opcode'] == 10 and r['status'] == 0 for r in calls) == 128,
             'memory_fixture_source_pin_admission')
    else:
        need(not suites and not finishes and not initializations and len(completions) == 1
             and rows[-1] is completions[0], 'memory_cooperative_terminal_order')
        terminal = completions[0]
        expected = {'owned_workers': 4, 'workers_joined': 4, 'schedules': 32, 'timeout_controls': 2,
            'writes': 30, 'handoffs': 96, 'owned_leaf_calls': 96, 'condition_cleanup': 0, 'mutex_cleanup': 0, 'trace_cleanup': 0}
        need(all(type(terminal.get(k)) is int and terminal[k] == v for k, v in expected.items()),
             'memory_cooperative_counts')
        need(all(len(items) == 4 and {r['actor'] for r in items} == set(range(4)) for items in thread_events.values()),
             'memory_cooperative_worker_ownership')
        coop_controls = Counter(r['control'] for r in cooperative_calls)
        need(type(terminal['wire_poll_calls']) is int and 96 <= terminal['wire_poll_calls'] <= 3072
             and terminal['wire_poll_calls'] == coop_controls['poll_existing_source_descriptor'],
             'memory_cooperative_wire_poll_count')
        expected_controls = {'register_owned_worker': 4, 'unregister_owned_worker': 4,
            'enter_source_leaf': 96, 'handoff_to_compiled_native_gate': 96,
            'discard_saved_resume_original_epoch': 96, 'active_participant_timeout': 1,
            'native_pin_without_park_timeout': 1, 'cooperative_writer_admission': 30,
            'publish_after_native_park_ack': 30, 'poll_existing_source_descriptor': terminal['wire_poll_calls']}
        need(coop_controls == expected_controls, 'memory_cooperative_control_counts')
        for r in cooperative_calls:
            timed = r['control'] in ('active_participant_timeout', 'native_pin_without_park_timeout')
            need(r['status'] == (5 if timed else 0), 'memory_cooperative_control_status')
        operation = {'register_owned_worker': (7, 1), 'unregister_owned_worker': (12, 5),
            'enter_source_leaf': (8, 2), 'handoff_to_compiled_native_gate': (13, 3),
            'discard_saved_resume_original_epoch': (11, 1), 'active_participant_timeout': (2, 0),
            'native_pin_without_park_timeout': (2, 0), 'cooperative_writer_admission': (2, 1),
            'publish_after_native_park_ack': (3, 1), 'poll_existing_source_descriptor': (13, 3)}
        for row in cooperative_calls:
            opcode, state = operation[row['control']]
            need(row['opcode'] == opcode and row['executor_state'] == state, 'memory_cooperative_state_transition')
            if row['control'] in ('enter_source_leaf', 'handoff_to_compiled_native_gate', 'discard_saved_resume_original_epoch', 'poll_existing_source_descriptor'):
                need(row['actor'] in (0, 1, 2), 'memory_cooperative_reader_role')
            elif row['control'] not in ('register_owned_worker', 'unregister_owned_worker'):
                need(row['actor'] == 3, 'memory_cooperative_writer_role')
        need(all(sum(r['actor'] == actor and r['control'] == control for r in cooperative_calls) == 32
                 for actor in (0, 1, 2) for control in ('enter_source_leaf', 'handoff_to_compiled_native_gate',
                                                       'discard_saved_resume_original_epoch')),
             'memory_cooperative_reader_schedules')
        need(controls == {'setup_register': 1, 'reserve_extent': 1, 'query_current_token': 1,
            'begin_two_page_write': 1, 'publish_two_pages': 1, 'setup_unregister': 1,
            'cleanup_register_after_worker_join': 1, 'mixed_extent_query_unavailable': 1,
            'retire_extent': 1, 'cleanup_unregister_after_retirement': 1}, 'memory_cooperative_setup_cleanup')
        setup_operations = {'setup_register': 7, 'reserve_extent': 1, 'query_current_token': 6,
            'begin_two_page_write': 2, 'publish_two_pages': 3, 'setup_unregister': 12,
            'cleanup_register_after_worker_join': 7, 'mixed_extent_query_unavailable': 6,
            'retire_extent': 5, 'cleanup_unregister_after_retirement': 12}
        need(all(r['opcode'] == setup_operations[r['control']] and
                 r['status'] == (3 if r['control'] == 'mixed_extent_query_unavailable' else 0)
                 for r in fixture_calls), 'memory_cooperative_setup_cleanup_result')
    return {'owner_calls': len(calls), 'controlled_refusals': sum(r['status'] != 0 for r in calls), 'terminal': terminal}
