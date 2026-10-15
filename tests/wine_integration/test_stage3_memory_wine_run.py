# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Original pure transcript/provider/metadata controls; no old CLI or receipts.

Canonical runtime supervision provides the immutable source-only helper pack.
The retained pure readers consume only synthetic bytes created by these tests.
"""
from copy import deepcopy
import errno
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from pear_runtime.assembly._common import encoded
from pear_runtime.errors import Error
from pear_runtime.fixtures.inputs import digest as digest_bytes
from tests.wine_integration.oracles import memory as runner
from tests.wine_integration.test_memory_wine_bitmap import row as diagnostic_row
from tests.wine_integration.oracles.synthetic_memory import native_rows, CHILD
REUSE = Path(__file__).resolve().parents[2]/'pear_runtime/providers/pear_legacy'


def wine_rows():
    """Synthetic structural source counts only, without a native owner/proof."""
    native=native_rows();calls=deepcopy(native[3:-2])
    shared=0
    for row in calls:
        row['scope']='wine_owner'
        if row['control']=='unknown_opcode':row['opcode']=16
        if row['control']=='atomic_wrong_role':row['status']=row['returned_status']=3
        if row['control']=='reserve_extent':
            row['extent_size']=16777216 if shared<38 else 16384;shared+=1
    terminal=deepcopy(native[-2]);terminal['scope']='wine_owner'
    readiness=[dict(version=1,record_kind='pear_fex_memory_wine',event='readiness_call',control=control,
         opcode=opcode,returned_status=0,status=0,native_error_domain=0,native_error_code=0)
         for control,opcode in [('register_readiness_native_executor',7),('query_readiness_native_owner',6),
                                ('unregister_readiness_native_executor',12)]]
    finish=dict(version=1,record_kind='pear_fex_memory_wine',event='finish',native_arm64_pe_execution=True,
        virtual_query_observations=156,checked_ec=False,ec_registration_exercised=False,wine_view_registration=True,
        fex_initialization=False,translated_guest_execution=False,game_execution=False,exit_code=0)
    return [native[0],*readiness,*calls,terminal,finish]


def line(row):return (json.dumps(row,separators=(',',':'))+'\n').encode()


def transcript(rows):return b''.join(line(row) for row in rows)


def bitmap_row():
    return {'set_observed':True,'clear_observed':True,'restoration_observed':True,'none_before':True,'none_after':True,
        'actual_peb_bitmap':True,'restoration_attempted':True,'hybrid_classification':False,'error_domain':0,'error_code':0}


def bitmap_log(rows):
    records=[]
    for row in rows:
        diagnostic=diagnostic_row()
        diagnostic.update(native_error_domain=row.get('error_domain',0),native_error_code=row.get('error_code',0))
        records.extend((runner.bitmap_policy.PREFIX+line(diagnostic),b'PEAR_FEX_BITMAP '+line(row)))
    return b''.join(records)


def pe(section=b'.rdata',blob=b'\0'*32,dll=True):
    """Metadata only: no executable instructions or target process."""
    value=bytearray(512+len(blob));value[:2]=b'MZ';struct.pack_into('<I',value,60,64);value[64:68]=b'PE\0\0'
    struct.pack_into('<HH',value,68,0xaa64,1);struct.pack_into('<HH',value,84,240,0x2000 if dll else 0)
    struct.pack_into('<H',value,88,0x20b);struct.pack_into('<I',value,88+108,16)
    value[328:336]=section.ljust(8,b'\0');struct.pack_into('<4I',value,336,len(blob),4096,len(blob),512)
    struct.pack_into('<I',value,364,0x40000040);value[512:]=blob
    return bytes(value)


def apiset_blob(target='ucrtbase.dll',duplicate_default=False):
    name='api-ms-win-crt-runtime-l1-1-0';nb=name.encode('utf-16-le');tb=target.encode('utf-16-le')
    count=2 if duplicate_default else 1;strings=28+24+20*count;hashed=len(name)-2
    tail=strings+len(nb)+len(tb);hashpos=(tail+3)&~3;size=hashpos+8
    blob=bytearray(size);struct.pack_into('<7I',blob,0,6,size,0,1,28,hashpos,31)
    struct.pack_into('<6I',blob,28,1,strings,len(nb),hashed*2,52,count)
    for i in range(count):struct.pack_into('<5I',blob,52+20*i,0,0,0,strings+len(nb),len(tb))
    blob[strings:strings+len(nb)]=nb;blob[strings+len(nb):tail]=tb
    h=0
    for c in name[:hashed]:h=(h*31+ord(c))&0xffffffff
    struct.pack_into('<2I',blob,hashpos,h,0)
    return bytes(blob)


class WineMemoryOutputControls(unittest.TestCase):
    def setUp(self):
        self.context=runner.supervision(REUSE);self.life,self.helper=self.context.__enter__()
        self.addCleanup(self.context.__exit__,None,None,None)

    def test_synthetic_wine_scope_has_distinct_readiness_and_view_observations(self):
        result=runner.owner_output(transcript(wine_rows()),CHILD,self.helper)
        self.assertEqual((result['owner_calls'],result['refusals'],result['readiness_calls']),(964,153,3))
        self.assertEqual(result['shared_reservation_count'],38)
        self.assertTrue(result['wine_view_registration_observed']);self.assertFalse(result['checked_ec'])
        self.assertFalse(result['fex_initialization']);self.assertFalse(result['arm64ec_role_qualified'])

    def test_missing_reordered_extra_or_boolean_readiness_is_refused(self):
        changes=[lambda r:r.pop(1),lambda r:r.__setitem__(slice(1,3),r[1:3][::-1]),
                 lambda r:r[2].update(owner_pid=17),lambda r:r[1].update(status=False)]
        for change in changes:
            rows=wine_rows();change(rows)
            with self.subTest(change=change),self.assertRaises(Error):runner.owner_output(transcript(rows),CHILD,self.helper)

    def test_call_gaps_wrong_scope_opcode_status_capability_and_refusal_facts_are_refused(self):
        for key,value in [('sequence',2),('scope','native_owner'),('opcode',6),('returned_status',False),
                          ('capabilities',8),('extent_size',True)]:
            rows=wine_rows();rows[4][key]=value
            with self.subTest(key=key),self.assertRaises(Error):runner.owner_output(transcript(rows),CHILD,self.helper)
        rows=wine_rows();next(r for r in rows if r.get('control')=='foreign_owner')['executor_id']=91
        with self.assertRaisesRegex(Error,'refusal_facts'):runner.owner_output(transcript(rows),CHILD,self.helper)

    def test_missing_control_truncation_wrong_terminal_and_unqualified_scope_never_pass(self):
        mutations=[lambda r:r.pop(7),lambda r:r[-2].update(allocations=102),lambda r:r[-1].update(wine_view_registration=False),
                   lambda r:r[-1].update(ec_registration_exercised=True),lambda r:r[-1].update(fex_initialization=True),
                   lambda r:r[-1].update(virtual_query_observations=True),lambda r:r[-1].update(exit_code=7)]
        for mutation in mutations:
            rows=wine_rows();mutation(rows)
            with self.subTest(mutation=mutation),self.assertRaises(Error):runner.owner_output(transcript(rows),CHILD,self.helper)
        with self.assertRaises(Error):runner.owner_output(transcript(wine_rows())[:-1],CHILD,self.helper)

    def test_wrong_native_identity_and_translated_helper_refused_before_suite(self):
        for key,value in [('pid',18),('translation_value',1),('kernel_page',4096),('vm_page',4096)]:
            rows=wine_rows();rows[0][key]=value
            with self.subTest(key=key),self.assertRaises((Error,self.helper.Error)):runner.owner_output(transcript(rows),CHILD,self.helper)

    def test_bootstrap_snapshot_is_distinct_from_actual_wine_admission(self):
        rows=wine_rows();rows[0]['user_page']=rows[0]['vm_page']=4096
        result=runner.owner_output(transcript(rows),CHILD,self.helper)
        self.assertEqual(result['owner_calls'],964)
        rows[0]['version']=True
        with self.assertRaises(Error):runner.owner_output(transcript(rows),CHILD,self.helper)




class WineBitmapControls(unittest.TestCase):
    def test_each_actual_field_count_and_diagnostics_bytes_are_kept_separate(self):
        raw=bitmap_log([bitmap_row(),bitmap_row()])+b'captured nonfixture diagnostic\n'
        result,extra=runner.bitmap_output(raw,2)
        self.assertEqual(result['self_tests'],2);self.assertEqual(extra,b'captured nonfixture diagnostic\n')
        self.assertFalse(result['hybrid_classification']);self.assertFalse(result['arm64ec_role_qualified'])

    def test_missing_extra_unrecognized_rollback_or_fake_success_cannot_pass(self):
        for key,value in [('set_observed',False),('actual_peb_bitmap',False),('restoration_observed',False),
            ('none_after',False),('restoration_attempted',False),('error_domain',1),('error_code',5),
            ('hybrid_classification',True),('error_code',False),('extra',True)]:
            row=bitmap_row();row[key]=value
            with self.subTest(key=key),self.assertRaises(Error):runner.bitmap_output(bitmap_log([row]),1)
        for raw,count in [(bitmap_log([bitmap_row()]),2),(bitmap_log([bitmap_row()]*2),1),
                          (b'  PEAR_FEX_BITMAP {}\n',1),(bitmap_log([bitmap_row()])[:-1],1)]:
            with self.subTest(raw=raw[:20]),self.assertRaises(Error):runner.bitmap_output(raw,count)

    def test_source_native_error_and_restoration_failure_retained_without_success(self):
        rows=wine_rows();rows[1].update(status=7,returned_status=7,native_error_domain=3,native_error_code=5)
        bitmap=bitmap_row();bitmap.update(error_domain=2,error_code=-1073741811,restoration_observed=False)
        value=runner.source_failures(transcript(rows),bitmap_log([bitmap]))
        self.assertIsNone(value['parse_error']);self.assertEqual(len(value['observations']),2)
        self.assertEqual(value['observations'][0]['native_error_code'],5)
        self.assertEqual(value['observations'][1]['error_code'],-1073741811)
        self.assertFalse(value['observations'][1]['restoration_observed'])

    def test_failure_parse_error_never_invents_native_errno(self):
        value=runner.source_failures(b'{broken\n',b'')
        self.assertEqual(value['observations'],[]);self.assertIsNotNone(value['parse_error'])
        self.assertNotIn('native_error',value['parse_error'])

    def test_diagnostic_refusal_keeps_original_primary_and_completed_count_unqualified(self):
        primary=bitmap_row();primary.update(restoration_observed=False,error_domain=3,error_code=7)
        raw=bitmap_log([primary])+runner.bitmap_policy.PREFIX+b'{}\n'
        value=runner.source_failures(transcript(wine_rows()[:4]),raw)
        self.assertIsNone(value['parse_error'])
        self.assertEqual(value['observations'][0]['error_code'],7)
        prefix=value['bitmap_diagnostics']
        self.assertEqual(len(prefix['observations']),1)
        self.assertFalse(prefix['completed_count_qualified'])
        self.assertEqual(prefix['observations'][0]['bitmap']['error_code'],7)
        self.assertIsNotNone(prefix['parse_error'])
        with self.assertRaises(Error):runner.require_no_source_failure(value)

    def test_completed_source_requires_diagnostic_pair_without_accepting_warning_allowance(self):
        raw=bitmap_log([bitmap_row()])
        self.assertFalse(runner.source_failures(transcript(wine_rows()[:4]),raw)['bitmap_diagnostics']['completed_count_qualified'])
        value=runner.source_failures(transcript(wine_rows()[:4]),raw)
        runner.require_no_source_failure(value)
        value['bitmap_diagnostics']['completed_count_qualified']=True
        with self.assertRaises(Error):runner.require_no_source_failure(value)
        primary=b'PEAR_FEX_BITMAP '+line(bitmap_row())
        with self.assertRaises(Error):runner.bitmap_output(primary,1)
        with self.assertRaises(Error):runner.bitmap_output(raw+b'warning PEAR_FEX_BITMAP {}\n',1)


    def test_malformed_stdout_cannot_suppress_original_stderr_native_failure(self):
        primary=bitmap_row();primary.update(restoration_observed=False,error_domain=3,error_code=7)
        value=runner.source_failures(b'{broken\n',bitmap_log([primary]))
        self.assertIsNotNone(value['parse_error'])
        self.assertEqual(value['observations'][0]['error_code'],7)
        self.assertEqual(value['bitmap_diagnostics']['observations'][0]['bitmap']['error_code'],7)
        self.assertFalse(value['bitmap_diagnostics']['completed_count_qualified'])
        with self.assertRaises(Error):runner.require_no_source_failure(value)


class WineCRTControls(unittest.TestCase):
    def test_actual_v6_default_and_hash_index_are_read_from_metadata_bytes(self):
        result=runner.apiset_defaults(pe(b'.apiset',apiset_blob()))
        self.assertEqual(result,{'api-ms-win-crt-runtime-l1-1-0.dll':'ucrtbase.dll'})
        self.assertEqual(runner.apiset_defaults(pe(b'.apiset',apiset_blob('foreign.dll'))),
                         {'api-ms-win-crt-runtime-l1-1-0.dll':'foreign.dll'})

    def test_bad_machine_namespace_hash_target_range_and_duplicate_default_refused(self):
        for mutation in ('machine','version','hash','target_bounds','duplicate'):
            data=bytearray(pe(b'.apiset',apiset_blob(duplicate_default=mutation=='duplicate')))
            if mutation=='machine':struct.pack_into('<H',data,68,0x8664)
            elif mutation=='version':struct.pack_into('<I',data,512,5)
            elif mutation=='hash':data[-8]^=1
            elif mutation=='target_bounds':struct.pack_into('<I',data,512+52+12,0xffffffff)
            with self.subTest(mutation=mutation),self.assertRaises(Error):runner.apiset_defaults(bytes(data))

    def test_provider_missing_and_api_set_default_cannot_be_inferred_from_name(self):
        with self.assertRaisesRegex(Error,'missing_provider'):
            runner.crt_closure(Path('/unused'),{'pe_images':[{'path':'aarch64-windows/kernel32.dll'}]})


class WineCRTProviderControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.build=self.root/'build';self.build.mkdir()
        self.api='api-ms-win-crt-runtime-l1-1-0.dll';self.schema=pe(b'.apiset',apiset_blob())
        names=['kernel32.dll',self.api];blob=bytearray(60);at=60
        for i,name in enumerate(names):
            struct.pack_into('<5I',blob,i*20,0,0,0,4096+at,0)
            chunk=name.encode()+b'\0';blob.extend(chunk);at+=len(chunk)
        fixture=bytearray(pe(blob=bytes(blob),dll=False));struct.pack_into('<2I',fixture,88+120,4096,60)
        self.rows=[]
        for name,raw in [('fixture.exe',bytes(fixture)),('apisetschema.dll',self.schema),
            ('ucrtbase.dll',pe()),('kernel32.dll',pe()),('kernelbase.dll',pe()),('ntdll.dll',pe())]:
            path='lib/wine/aarch64-windows/'+name
            target=self.root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
            self.rows.append({'path':path,'sha256':digest_bytes(raw),'size_bytes':len(raw),'machine':0xaa64,
                'classification':'ordinary_arm64_image','load_admission':'unperformed','execution_performed':False})
        self.value={'pe_images':self.rows,'build_ref':{'path':str(self.build)},
                    'entrypoints':{'fixture_pe':self.rows[0]['path']}}
        self.source=self.build/'source/dlls/apisetschema/apisetschema.spec';self.source.parent.mkdir(parents=True)
        self.source.write_bytes(b'apiset api-ms-win-crt-runtime-l1-1-0 = ucrtbase.dll\n')

    def test_synthetic_real_pe_namespace_bytes_and_matching_source_bind_ucrt_provider(self):
        value=runner.crt_closure(self.root,self.value)
        self.assertEqual(value['imports'],[{'import':self.api,'default_provider':'ucrtbase.dll'},
                                          {'import':'kernel32.dll','default_provider':'kernel32.dll'}])
        self.assertEqual({row['name'] for row in value['providers']},
                         {'apisetschema.dll','ucrtbase.dll','kernel32.dll','kernelbase.dll','ntdll.dll'})
        self.assertFalse(value['execution']);self.assertEqual(value['complete_named_ordinal_forwarder_symbol_resolution'],'unperformed')

    def test_wrong_default_source_byte_or_foreign_fixture_selection_is_refused(self):
        for mutation in ['default','source','byte','selection']:
            value=deepcopy(self.value)
            if mutation=='default':
                raw=pe(b'.apiset',apiset_blob('foreign.dll'));row=value['pe_images'][1]
                (self.root/row['path']).write_bytes(raw);row.update(sha256=digest_bytes(raw),size_bytes=len(raw))
            elif mutation=='source':self.source.write_bytes(b'apiset api-ms-win-crt-runtime-l1-1-0 = foreign.dll\n')
            elif mutation=='byte':(self.root/value['pe_images'][2]['path']).write_bytes(b'changed')
            else:value['pe_images'][0].update(machine=0x8664,classification='retained_wrong_architecture_fixture',load_admission='refused')
            with self.subTest(mutation=mutation),self.assertRaises(Error):runner.crt_closure(self.root,value)
            (self.root/self.rows[1]['path']).write_bytes(self.schema)
            (self.root/self.rows[2]['path']).write_bytes(pe())
            self.source.write_bytes(b'apiset api-ms-win-crt-runtime-l1-1-0 = ucrtbase.dll\n')


def delay_metadata(exports=None, forwarder=None):
    """Synthetic tables only. RX bytes are zero; no image is loaded or called."""
    data=bytearray(512+4096+256);data[:2]=b'MZ';struct.pack_into('<I',data,60,64)
    data[64:68]=b'PE\0\0';struct.pack_into('<HH',data,68,0xaa64,2)
    struct.pack_into('<HH',data,84,240,0x2000);struct.pack_into('<H',data,88,0x20b)
    struct.pack_into('<Q',data,112,0x180000000);struct.pack_into('<I',data,144,12288)
    struct.pack_into('<I',data,196,16)
    for pos,name,rva,size,raw,flags in [(328,b'.data',4096,4096,512,0xc0000040),
                                       (368,b'.text',8192,256,4608,0x60000020)]:
        data[pos:pos+8]=name.ljust(8,b'\0');struct.pack_into('<4I',data,pos+8,size,rva,size,raw)
        struct.pack_into('<I',data,pos+36,flags)
    def string(offset,value):
        raw=value.encode()+b'\0';data[512+offset:512+offset+len(raw)]=raw;return 4096+offset
    if exports is not None:
        struct.pack_into('<2I',data,200,4096,1024)
        struct.pack_into('<IIIIII',data,512+16,1,len(exports),len(exports),4096+64,4096+128,4096+192)
        cursor=256
        for i,name in enumerate(exports):
            target=8192+4*i
            if forwarder is not None and i==0:target=string(768,forwarder)
            struct.pack_into('<I',data,512+64+4*i,target)
            struct.pack_into('<I',data,512+128+4*i,string(cursor,name));cursor+=len(name)+1
            struct.pack_into('<H',data,512+192+2*i,i)
    else:
        struct.pack_into('<2I',data,304,4096,96)
        module_offsets=(1000,1020);name_offset=1100
        for i,(module,symbols,handle,iat,int_) in enumerate([
            ('advapi32.dll',['SystemFunction036'],128,160,208),
            ('user32.dll',['GetActiveWindow','MessageBoxIndirectW'],136,176,224)]):
            struct.pack_into('<8I',data,512+32*i,1,string(module_offsets[i],module),
                4096+handle,4096+iat,4096+int_,0,0,0)
            for j,symbol in enumerate(symbols):
                name_offset=(name_offset+1)&~1;struct.pack_into('<H',data,512+name_offset,0)
                string(name_offset+2,symbol)
                struct.pack_into('<Q',data,512+int_+8*j,4096+name_offset)
                struct.pack_into('<Q',data,512+iat+8*j,0x180000000+8192+(i*2+j)*4)
                name_offset+=len(symbol)+3
    return bytes(data)


class WineUCRTDelayMetadataControls(unittest.TestCase):
    def test_two_dll_three_named_rva_descriptors_require_individual_terminators(self):
        value=runner.ucrt_delay_table(delay_metadata())
        self.assertEqual((value['descriptor_count'],value['named_thunk_count'],value['table_bytes']),(2,3,96))
        self.assertEqual([r['module'] for r in value['imports']],['advapi32.dll','user32.dll'])
        self.assertFalse(value['execution'])
        for row in value['imports']:
            self.assertTrue(row['module_handle_zero']);self.assertTrue(row['int_terminated'])
            self.assertTrue(row['iat_terminated']);self.assertTrue(row['initial_iat_executable_thunks_observed'])

    def test_foreign_descriptor_mode_bound_unload_timestamp_and_size_refused(self):
        for pos,fmt,value in [(512,'I',0),(512,'I',2),(512+20,'I',4096),(512+24,'I',4096),
                               (512+28,'I',1),(308,'I',64),(308,'I',128),(304,'I',4097),
                               (68,'H',0x8664),(86,'H',0),(144,'I',4096)]:
            raw=bytearray(delay_metadata());struct.pack_into('<'+fmt,raw,pos,value)
            with self.subTest(pos=pos,value=value),self.assertRaises(Error):runner.ucrt_delay_table(bytes(raw))

    def test_int_ordinal_hint_wrong_name_and_terminator_refused(self):
        for pos,fmt,value in [(512+208,'Q',1<<63),(512+208,'Q',0),(512+208,'Q',1<<32),
                               (512+208,'Q',4097),(512+1100,'H',1),(512+216,'Q',1),
                               (512+240,'Q',1),(512+168,'Q',1),(512+192,'Q',1)]:
            raw=bytearray(delay_metadata());struct.pack_into('<'+fmt,raw,pos,value)
            with self.subTest(pos=pos,value=value),self.assertRaises(Error):runner.ucrt_delay_table(bytes(raw))
        raw=bytearray(delay_metadata());raw[512+1102]=ord('X')
        with self.assertRaisesRegex(Error,'delay_symbol'):runner.ucrt_delay_table(bytes(raw))

    def test_iat_not_image_va_not_executable_outside_image_and_unaligned_refused(self):
        for pos,fmt,value in [(512+160,'Q',8192),(512+160,'Q',0x180000000+4096),
                               (512+160,'Q',0x180000000+16384),(512+160,'Q',0x180000000+8193),
                               (144,'I',8192),(404,'I',0x40000020)]:
            raw=bytearray(delay_metadata());struct.pack_into('<'+fmt,raw,pos,value)
            with self.subTest(pos=pos,value=value),self.assertRaises(Error):runner.ucrt_delay_table(bytes(raw))

    def test_mutable_handle_table_alias_extra_descriptor_and_unbounded_string_refused(self):
        for pos,fmt,value in [(512+128,'Q',1),(364,'I',0x40000040),(512+8,'I',4096+64),
                               (512+40,'I',4096+128),(512+16,'I',4096+160),
                               (512+64,'I',1),(512+4,'I',0xffffffff)]:
            raw=bytearray(delay_metadata());struct.pack_into('<'+fmt,raw,pos,value)
            with self.subTest(pos=pos,value=value),self.assertRaises(Error):runner.ucrt_delay_table(bytes(raw))
        with self.assertRaises(Error):runner.ucrt_delay_table(delay_metadata()[:550])

    def test_selected_export_forwarder_and_direct_targets_have_separate_facts(self):
        value=runner.BaselinePEMetadata(delay_metadata(['SystemFunction036'],'cryptbase.SystemFunction036'))
        self.assertEqual(value.selected_export('SystemFunction036'),{'name':'SystemFunction036','ordinal':1,
            'target_kind':'forwarder','forwarder':'cryptbase.SystemFunction036'})
        value=runner.BaselinePEMetadata(delay_metadata(['GetActiveWindow','MessageBoxIndirectW']))
        self.assertEqual(value.selected_export('MessageBoxIndirectW')['target_kind'],'executable_source_export')

    def test_missing_duplicate_bad_ordinal_zero_target_and_nonexecute_exports_refused(self):
        with self.assertRaises(Error):runner.BaselinePEMetadata(delay_metadata(['Missing'])).selected_export('SystemFunction036')
        with self.assertRaises(Error):runner.BaselinePEMetadata(delay_metadata(['SystemFunction036']*2)).selected_export('SystemFunction036')
        for pos,fmt,value in [(512+192,'H',1),(512+64,'I',0),(512+64,'I',4096+1500),
                               (512+64,'I',8193),(404,'I',0x40000020),(204,'I',2**32-1)]:
            raw=bytearray(delay_metadata(['SystemFunction036']));struct.pack_into('<'+fmt,raw,pos,value)
            with self.subTest(pos=pos,value=value),self.assertRaises(Error):
                runner.BaselinePEMetadata(bytes(raw)).selected_export('SystemFunction036')


class WineUCRTDelayClosureControls(WineCRTProviderControls):
    # Inherited provider controls still cover the old zero-delay reader path.
    def setUp(self):
        super().setUp();self.update('ucrtbase.dll',delay_metadata())
        self.add_provider('advapi32.dll',delay_metadata(['SystemFunction036'],'cryptbase.SystemFunction036'))
        self.add_provider('cryptbase.dll',delay_metadata(['SystemFunction036']))
        self.add_provider('user32.dll',delay_metadata(['GetActiveWindow','MessageBoxIndirectW']))
        self.specs={
            'dlls/ucrtbase/Makefile.in':b'DELAYIMPORTS = advapi32 user32\n',
            'dlls/advapi32/advapi32.spec':b'@ stdcall SystemFunction036(ptr long) cryptbase.SystemFunction036\n',
            'dlls/user32/user32.spec':b'@ stdcall GetActiveWindow()\n@ stdcall MessageBoxIndirectW(ptr)\n',
            'dlls/cryptbase/cryptbase.spec':b'@ stdcall SystemFunction036(ptr long)\n',
            'include/ntsecapi.h':b'#define RtlGenRandom                    SystemFunction036\n'}
        for name in ('dlls/msvcrt/misc.c','dlls/msvcrt/exit.c','dlls/cryptbase/cryptbase_main.c',
                     'dlls/user32/input.c','dlls/user32/msgbox.c','tools/winebuild/import.c','dlls/ntdll/loader.c'):
            self.specs[name]=b'/* Synthetic source bytes; no runtime functions. */\n'
        for name,raw in self.specs.items():
            target=self.build/'source'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)

    def update(self,name,raw):
        row=next(row for row in self.rows if Path(row['path']).name==name)
        (self.root/row['path']).write_bytes(raw);row.update(sha256=digest_bytes(raw),size_bytes=len(raw))

    def add_provider(self,name,raw):
        path='lib/wine/aarch64-windows/'+name;(self.root/path).write_bytes(raw)
        self.rows.append({'path':path,'sha256':digest_bytes(raw),'size_bytes':len(raw),'machine':0xaa64,
            'classification':'ordinary_arm64_image','load_admission':'unperformed','execution_performed':False})

    def test_exact_source_routes_and_current_provider_bytes_bound_without_execution_claim(self):
        value=runner.crt_closure(self.root,self.value);delay=value['ucrt_delay_import_closure']
        self.assertEqual(delay['table']['named_thunk_count'],3)
        self.assertEqual(len(delay['providers']),3);self.assertEqual(len(delay['source_files']),12)
        self.assertEqual(sum(len(row['selected_exports']) for row in delay['selected_exports']),4)
        self.assertFalse(delay['execution']);self.assertFalse(value['execution'])
        self.assertEqual(delay['all_provider_dependency_and_symbol_resolution'],'unperformed')
        self.assertEqual(value['complete_named_ordinal_forwarder_symbol_resolution'],'unperformed')

    def test_missing_changed_foreign_and_unselected_provider_cannot_pass(self):
        for change in ('missing','byte','foreign','load','execution'):
            value=deepcopy(self.value);row=value['pe_images'][-1]
            if change=='missing':value['pe_images'].pop()
            elif change=='byte':(self.root/row['path']).write_bytes(b'altered')
            elif change=='foreign':row['machine']=0x8664
            elif change=='load':row['load_admission']='refused'
            else:row['execution_performed']=True
            with self.subTest(change=change),self.assertRaises(Error):runner.crt_closure(self.root,value)
            self.update('user32.dll',delay_metadata(['GetActiveWindow','MessageBoxIndirectW']))

    def test_missing_changed_conflicting_source_contract_cannot_pass(self):
        target=self.build/'source/dlls/ucrtbase/Makefile.in';original=target.read_bytes()
        for raw in (b'DELAYIMPORTS = advapi32 foreign\n', original+b'DELAYIMPORTS = foreign\n', original*2):
            target.write_bytes(raw)
            with self.subTest(raw=raw),self.assertRaises(Error):runner.crt_closure(self.root,self.value)
        target.unlink()
        with self.assertRaises((Error,OSError)):runner.crt_closure(self.root,self.value)
        target.write_bytes(original)
        target=self.build/'source/dlls/advapi32/advapi32.spec';target.write_bytes(b'@ stdcall SystemFunction036(ptr long) foreign.SystemFunction036\n')
        with self.assertRaises(Error):runner.crt_closure(self.root,self.value)

    def test_changed_forwarder_missing_direct_export_and_unrelated_delay_remain_separate(self):
        self.update('advapi32.dll',delay_metadata(['SystemFunction036'],'foreign.SystemFunction036'))
        with self.assertRaisesRegex(Error,'forwarder_target'):runner.crt_closure(self.root,self.value)
        self.update('advapi32.dll',delay_metadata(['SystemFunction036'],'cryptbase.SystemFunction036'))
        self.update('cryptbase.dll',delay_metadata(['Missing']))
        with self.assertRaises(Error):runner.crt_closure(self.root,self.value)
        self.update('cryptbase.dll',delay_metadata(['SystemFunction036']))
        raw=bytearray(delay_metadata(['GetActiveWindow','MessageBoxIndirectW']))
        struct.pack_into('<2I',raw,304,4096+1500,32);self.update('user32.dll',bytes(raw))
        value=runner.crt_closure(self.root,self.value)['ucrt_delay_import_closure']
        row=next(row for row in value['providers'] if row['name']=='user32.dll')
        self.assertTrue(row['other_delay_directory_present'])
        self.assertEqual(row['other_eager_delay_symbol_resolution'],'unperformed')
        self.assertFalse(value['execution'])


class WineRunRecordControls(unittest.TestCase):
    def test_inherited_home_is_not_repurposed_and_injections_not_in_environment(self):
        env=runner.environment(Path('/owned/work'),Path('/owned/prefix'),'a'*32,'/normal/home')
        self.assertEqual(env['HOME'],'/normal/home');self.assertNotIn('DYLD_INSERT_LIBRARIES',env)
        self.assertNotIn('FEX_ROOTFS',env);self.assertNotIn('PEAR_FEX_MEMORY_OWNER_PID',env)
        self.assertNotIn('HOME',runner.environment(Path('/work'),Path('/prefix'),'a'*32,None))
        with self.assertRaises(Error):runner.environment(Path('/work'),Path('/prefix'),'a'*31,None)

    def test_exact_nonce_control_endpoint_no_hostpid_or_graphics_environment(self):
        base=runner.environment(Path('/work'),Path('/prefix'),'a'*32,None)
        value=runner.loader_environment(base,'/private/tmp/pear-stage3-owned/control',17,'a'*32)
        self.assertEqual(value['PEAR_FEX_BITMAP_DIAGNOSTICS'],'1')
        self.assertEqual(value['PEAR_FEX_MEMORY_FIXTURE_NONCE'],'a'*32)
        self.assertNotIn('PEAR_FEX_MEMORY_OWNER_PID',value)
        self.assertFalse(any(key.startswith('MTL_') for key in value))
        for endpoint in ['/tmp/pear-stage3-owned/control','/private/tmp/other/control','/private/tmp/pear-stage3-x/../control']:
            with self.assertRaises(Error):runner.loader_environment(base,endpoint,17,'a'*32)

    def test_changed_unclosed_or_partial_log_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);logs=[]
            for role in ['loader','server','sentinel']:
                for channel in ['stdout','stderr']:
                    path=role+'.'+channel+'.log';(root/path).write_bytes(b'bytes')
                    logs.append({'role':role,'channel':channel,'path':path,'sha256':digest_bytes(b'bytes'),
                        'bytes':5,'observed_bytes':5,'eof':True,'write_error':None})
            value={'logs':logs,'events':{}};self.assertEqual(len(runner.verify_logs(root,value)),6)
            for mutation in ('extra','eof','size','hash','duplicate','path','changed'):
                candidate=deepcopy(value)
                if mutation=='extra':candidate['logs'][0]['private_grant']=True
                elif mutation=='eof':candidate['logs'][0]['eof']=False
                elif mutation=='size':candidate['logs'][0]['bytes']=True
                elif mutation=='hash':candidate['logs'][0]['sha256']='0'*64
                elif mutation=='duplicate':candidate['logs'].append(candidate['logs'][0])
                elif mutation=='path':candidate['logs'][0]['path']='../outside'
                else:(root/'loader.stdout.log').write_bytes(b'changed')
                with self.subTest(mutation=mutation),self.assertRaises(Error):runner.verify_logs(root,candidate)







    def test_genuine_error_detail_does_not_invent_exit_or_replace_original_domain(self):
        value=runner.failure_detail(OSError(errno.ENOSPC,'full'))
        self.assertEqual(value['native_error'],{'domain':'errno','code':errno.ENOSPC})
        self.assertNotIn('exit_code',value);self.assertNotIn('native_error',runner.failure_detail(Error('refused')))


if __name__=='__main__':unittest.main()
