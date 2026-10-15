# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact retained fixture source/build bindings, separate from current authority."""
from pathlib import Path
import struct

from pear_runtime.assembly import core
from pear_runtime.assembly.helpers import PAYLOAD, SourcePack, signing_helpers
from pear_runtime.assembly._common import read_relative
from pear_runtime.errors import need
from pear_runtime.fixtures.inputs import fact, digest

# role: installed relative path, original command id, contributing fixture units
ROLES = {
 'api_pe': ('libexec/pear-stage3/api-arm64.exe', 'fixture-api-arm64', ('api_pe.c',)),
 'abi_pe': ('libexec/pear-stage3/abi-arm64.exe', 'fixture-abi-arm64', ('abi_pe.c','abi_gateway.S')),
 'stage4_pe': ('libexec/pear-stage4/stage4-arm64.exe', 'fixture-stage4-arm64',
              ('threads_pe.c','memory_pe.c','exceptions_pe.c','threads_gateway.S')),
 'window_pe': ('libexec/pear-stage5/window-arm64.exe', 'fixture-window-arm64', ('window_pe.c',)),
 'lifetime_dll': ('libexec/pear-stage3/lifetime-arm64.dll', 'fixture-lifetime-dll', ('lifetime_pe.c',)),
 'missing_name_dll': ('libexec/pear-stage3/missing-name-arm64.dll', 'fixture-missing-name-dll', ('missing_import_pe.c',)),
 'missing_ordinal_dll': ('libexec/pear-stage3/missing-ordinal-arm64.dll', 'fixture-missing-ordinal-dll', ('missing_import_pe.c',)),
 'x64_control': ('libexec/pear-stage3/api-x64.exe', 'fixture-api-x64', ('api_pe.c',)),
 'i386_control': ('libexec/pear-stage3/api-i386.exe', 'fixture-api-i386', ('api_pe.c',)),
 'api_launch': ('libexec/pear-stage3/api-launch', 'fixture-api-launch', ('api_launch.c',)),
 'bootstrap_helper': ('libexec/pear-stage2/bootstrap-native', 'fixture-bootstrap', ('bootstrap_native.c',)),
 'sentinel': ('libexec/pear-stage2/sentinel', 'fixture-sentinel', ('sentinel.c',)),
}
MACH_ROLES = {'api_launch','bootstrap_helper','sentinel'}
NATIVE_SOURCES = {'abi_native.c':'dlls/ntdll/unix/pear_abi_fixture.c',
                  'signal_native.c':'dlls/ntdll/unix/pear_signal_fixture.c',
                  'window_native.m':'dlls/winemac.drv/pear_window_fixture.m'}
DRIVER = PAYLOAD+'/lib/wine/aarch64-windows/winemac.drv'
FIELDS = {'schema_version','scope','build_ref','installed_manifest_ref','fixture_manifest_ref',
          'wine_source_ref','source_refs','installed_refs','candidate_refs'}


def pe_timestamps(raw):
    """Bounded PE32/PE32+ timestamp locations; no executable normalization."""
    need(type(raw) is bytes and 64 <= len(raw) <= 64*1024**2 and raw[:2] == b'MZ', 'native_pe_header')
    def n(fmt, at):
        size=struct.calcsize('<'+fmt)
        need(0 <= at <= len(raw)-size, 'native_pe_bounds')
        return struct.unpack_from('<'+fmt,raw,at)[0]
    pe=n('I',60); need(raw[pe:pe+4] == b'PE\0\0', 'native_pe_signature')
    count,size=n('H',pe+6),n('H',pe+20); opt=pe+24; magic=n('H',opt)
    need(1 <= count <= 96 and magic in (0x10b,0x20b), 'native_pe_optional')
    dirs=112 if magic==0x20b else 96
    need(size >= dirs+16*8 and n('I',opt+dirs-4)==16, 'native_pe_directories')
    header=n('I',opt+60); table=opt+size
    need(table+count*40 <= header <= len(raw), 'native_pe_sections')
    sections=[]
    for i in range(count):
        at=table+i*40; virtual,rva,length,start=struct.unpack_from('<4I',raw,at+8)
        need(start+length <= len(raw), 'native_pe_section_bounds')
        sections.append((rva,virtual,length,start))
    def offset(rva,size):
        hits=[rva] if rva+size<=header else []
        hits += [start+rva-base for base,virtual,length,start in sections
                 if 0 <= rva-base and rva-base+size <= min(virtual,length)]
        need(len(hits)==1,'native_pe_mapping'); return hits[0]
    rva,length=struct.unpack_from('<II',raw,opt+dirs+6*8)
    need(length%28==0 and length<=28*1024,'native_pe_debug_size')
    offsets=[pe+8]+[offset(rva+i,28)+4 for i in range(0,length,28)]
    return n('H',pe+4),offsets


def compare_pe(original, candidate, machine):
    old, offsets=pe_timestamps(original); new, current=pe_timestamps(candidate)
    need(old==new==machine and current==offsets and len(original)==len(candidate), 'native_pe_geometry')
    a,b=bytearray(original),bytearray(candidate)
    for at in offsets: a[at:at+4]=b'\0'*4; b[at:at+4]=b'\0'*4
    need(a==b, 'native_pe_non_timestamp_changed')
    return {'whole_payload_equal_except_timestamps':True,'timestamp_offsets':offsets,
            'different_byte_count':sum(a!=b for a,b in zip(original,candidate))}


def _row(rows, name):
    selected=[row for row in rows if row['path']==name]
    need(len(selected)==1,'native_source_inventory_entry');return selected[0]


def verify(ref, runtime, packet, provider):
    value=core.read_ref(ref)
    need(set(value)==FIELDS and type(value['schema_version']) is int and value['schema_version']==1 and
         value['scope']=='native_wine_fixture_inputs','native_binding_shape')
    built=core.read_ref(value['build_ref']); install=Path(built['install_root'])
    need(built.get('passed') is True and built.get('scope')=='wine_component' and
         built.get('fixture_suite')=='mac-driver','native_fixture_build')
    manifest_ref=value['installed_manifest_ref']; inventory=core.read_ref(manifest_ref)
    need(Path(manifest_ref['path'])==Path(value['build_ref']['path']).parent/built['artifacts_manifest']['path'] and
         manifest_ref['sha256']==built['artifacts_manifest']['sha256'],'native_install_manifest_join')
    fixture=core.read_ref(value['fixture_manifest_ref']); source=core.read_ref(value['wine_source_ref'])
    source_path=core.checked_ref(value['wine_source_ref']); wine=source_path.parent.parent
    need(source_path==wine/'pear/source-manifest.json' and source['component']=='pear-wine' and
         Path(value['fixture_manifest_ref']['path'])==wine/'pear/fixture-source-manifest.json' and
         fixture['canonical_owner']=='pear-wine','native_source_owner')
    need(type(value['source_refs']) is dict and set(value['source_refs'])==set(built['fixture_hashes']),
         'native_fixture_source_set')
    for name,row in value['source_refs'].items():
        path=core.checked_ref(row)
        dest=NATIVE_SOURCES.get(name,'pear/tests/fixtures/'+name)
        owner=_row(source['selected_files'] if name in NATIVE_SOURCES else fixture['files'],dest)
        need(path==wine/dest and row['sha256']==built['fixture_hashes'][name]==owner['sha256'] and
             row['size_bytes']==owner['size_bytes'],'native_fixture_source_join')
    need(set(value['installed_refs'])==set(ROLES) and set(value['candidate_refs'])==set(ROLES),
         'native_fixture_artifact_set')
    _,reader=signing_helpers(SourcePack(provider)); comparisons={}
    for role,(relative,ident,units) in ROLES.items():
        old=value['installed_refs'][role]; new=value['candidate_refs'][role]
        oldpath=core.checked_ref(old); newpath=core.checked_ref(new)
        row=_row(inventory['files'],relative)
        need(oldpath==install/relative and newpath==runtime/PAYLOAD/relative and
             old['sha256']==row['sha256'] and old['size_bytes']==row['size_bytes'],'native_fixture_install_join')
        commands=[c for c in built['commands'] if c['id']==ident]
        need(len(commands)==1,'native_fixture_compile_command'); command=commands[0]
        need(type(command['exit_code']) is int and command['exit_code']==0 and
             all(command.get(key) is False for key in ('interrupted','output_limit','timed_out')),
             'native_fixture_compile_failed')
        argv=command['argv']; need(argv.count('-o')==1 and argv[argv.index('-o')+1]==str(oldpath),
                                  'native_fixture_compile_output')
        actual_paths=[Path(x) for x in argv if x.endswith(('.c','.S'))]
        origin=Path(value['build_ref']['path']).parents[3]/'tests/wine/fixtures'
        need(actual_paths==[origin/n for n in units], 'native_fixture_compile_source_paths')
        actual=[x.name for x in actual_paths]
        need(tuple(actual)==units and all(built['fixture_hashes'][n]==value['source_refs'][n]['sha256'] for n in units),
             'native_fixture_compile_sources')
        if role in MACH_ROLES:
            reader.verify_code_origin(oldpath,newpath)
            native=_row(packet['native_images'],str(newpath.relative_to(runtime)))
            need(native['sha256']==new['sha256'],'native_fixture_signed_image')
            comparisons[role]={'verified':True,'scope':'macho_signature_fields_only'}
        else:
            machine=0x8664 if role=='x64_control' else (0x14c if role=='i386_control' else 0xaa64)
            comparisons[role]=compare_pe(oldpath.read_bytes(),newpath.read_bytes(),machine)
    # This PE is an admitted retained lower layer, not rebuilt by graphics6.
    # Its historical source-to-PE build origin remains explicitly unknown.
    origin_ref=packet['development_assembly']['input_runtime']; core.read_ref(origin_ref)
    ledger=[row for row in packet['source_ledger'] if row['runtime_path']==DRIVER]
    need(len(ledger)==1,'native_driver_origin')
    old=core.checked_ref(ledger[0]['origin']); current=runtime/DRIVER
    need(old==Path(origin_ref['path']).parent/DRIVER and fact(current)['sha256']==ledger[0]['origin']['sha256'] and
         fact(current)['size_bytes']==ledger[0]['origin']['size_bytes'],'native_retained_driver_changed')
    return value, {'fixtures':comparisons,'window_driver':{'artifact_ref':fact(current),
        'input_runtime_ref':origin_ref,'origin_ref':ledger[0]['origin'],
        'source_to_pe_build_origin':'unknown','claim':'exact_retained_lower_layer'}}
