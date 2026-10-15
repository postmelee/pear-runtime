#!/usr/bin/env python3
"""Materialize and admit one development-only Wine/Metal fixture runtime.

Pure structural replay is separate from fresh Apple profile/signature admission.
Only the root orchestrator calls preparation or live admission; portable tests
exercise byte/provenance/refusal contracts without native commands.
"""
from __future__ import annotations
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import stat
import struct
import sys
import time
from types import SimpleNamespace
import uuid

from common import (REPO, MACH_ARM64, Error, decode_json, digest, encoded, fields,
                    need, owned_directory, output_directory, read_relative,
                    real_directory, relative, run_bounded, sha256, write_new)
import build as stage3
import pairing_build
import pairing_check
import tools

BUNDLE_ID='io.github.postmelee.pear.wine-loader'
BUNDLE='PearWineLoader.app'
PAYLOAD=BUNDLE+'/Contents/Resources/runtime'
MAIN=BUNDLE+'/Contents/MacOS/wine'
NTDLL_ALIAS=BUNDLE+'/Contents/MacOS/ntdll.so'
LOADER='lib/wine/aarch64-unix/wine'
NTDLL='lib/wine/aarch64-unix/ntdll.so'
SERVER='bin/wineserver'
API_LAUNCH='libexec/pear-stage3/api-launch'
SENTINEL='libexec/pear-stage2/sentinel'
DRIVER='lib/wine/aarch64-unix/winemac.so'
DRIVER_PE='lib/wine/aarch64-windows/winemac.drv'
WINEMETAL='lib/wine/aarch64-unix/winemetal.so'
FIXTURE='libexec/pear-dxmt/pairing-arm64.exe'
ENV={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C'}
LIMIT=2*1024**2
CERTIFICATE_LIMIT=128*1024
MAX_CERTIFICATES=8
RESERVE=4*1024**3
SCOPE='development_finite_native_metal_pairing'
INFO={'CFBundleIdentifier':BUNDLE_ID,'CFBundleExecutable':'wine','CFBundleName':'Pear Wine Loader',
      'CFBundlePackageType':'APPL','CFBundleVersion':'1','CFBundleShortVersionString':'0.1',
      'LSMinimumSystemVersion':'26.5'}
RUNTIME_FIELDS=('schema_version','record_kind','build_ref','producers','native_images','pe_images',
                'entrypoints','authorization','signed_receipt','arena_capacity','code_publication_policy',
                'runtime_eligible','game_qualified')
PRODUCERS=('tools/dxmt/pairing_runtime.py','tools/dxmt/pairing_check.py','tools/dxmt/run_pairing.py',
           'tools/dxmt/common.py','tools/dxmt/tools.py','tools/wine/common.py','tools/wine/signing.py',
           'tools/wine/toolchain.py','host/probe/provisioned_probe.py','host/probe/hardened_baseline.py')


def same(left,right,code):need(encoded(left)==encoded(right),code)


def native_error(exc):
    """Preserve a real OS failure through scoped Error wrappers, never invent errno."""
    if isinstance(exc,OSError):
        return {'domain':'POSIX','code':exc.errno if type(exc.errno)is int else None,
                'exception_type':type(exc).__name__}
    return getattr(exc,'native_error',None)


def failure_fields(exc):
    observed=native_error(exc)
    return {'native_error':observed}if observed is not None else{}


def wrapped_error(exc,code):
    error=Error(code)
    if native_error(exc)is not None:error.native_error=native_error(exc)
    return error


def certificate_prefix(root,ident):
    need(re.fullmatch('[a-z0-9][a-z0-9_.-]{0,95}',ident)is not None,'pair_certificate_id')
    return Path(root)/'certificates'/ident/'cert'


def signer_leaf(root,ident,private,raw_profile):
    """Bind codesign's documented DER certificate 0 to captured profile bytes.

    This is exact selected-certificate membership, not a new trust evaluator.
    codesign verification and fresh profile/device/identity admission stay required.
    """
    prefix=certificate_prefix(root,ident);directory=real_directory(prefix.parent)
    entries=[]
    for path in directory.iterdir():
        entries.append(path)
        need(len(entries)<=MAX_CERTIFICATES,'pair_certificate_count')
    need(0<len(entries)<=MAX_CERTIFICATES,'pair_certificate_count')
    names={path.name for path in entries}
    # Installed Apple codesign(1) specifies numbered files 0, 1, ... with 0 the
    # leaf; chain length varies. No particular intermediate/root is assumed.
    need(names=={'cert'+str(i)for i in range(len(entries))},'pair_certificate_chain_names')
    chain=[]
    for index in range(len(entries)):
        raw=read_relative(root,'certificates/'+ident+'/cert'+str(index),CERTIFICATE_LIMIT)
        need(0<len(raw)<=CERTIFICATE_LIMIT,'pair_certificate_size')
        chain.append(raw)
    certificates=cms_plist(raw_profile).get('DeveloperCertificates')
    need(type(certificates)is list and certificates and all(type(raw)is bytes and raw for raw in certificates),
         'pair_profile_certificates')
    selected={raw for raw in certificates if hashlib.sha1(raw).hexdigest().upper()==private['identity']}
    need(len(selected)==1,'pair_signer_certificate_identity')
    need(chain[0]==next(iter(selected)) and hashlib.sha1(chain[0]).hexdigest().upper()==private['identity'],
         'pair_signer_leaf_mismatch')
    return {'scope':'exact_profile_signer_leaf','sha1':private['identity'],
            'sha256':digest(chain[0]),'chain_count':len(chain)}


def select_functions(raw,names,namespace,label):
    tree=ast.parse(raw,filename=label)
    selected=[node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name in names]
    need({node.name for node in selected}==set(names)and len(selected)==len(names)
         and all(not node.decorator_list for node in selected),'pair_signing_source_functions')
    exec(compile(ast.Module(body=selected,type_ignores=[]),label,'exec'),namespace)
    return namespace


def source_constant(raw,name):
    values=[node.value for node in ast.parse(raw).body if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name)and target.id==name for target in node.targets)]
    need(len(values)==1,'pair_signing_source_constant')
    return ast.literal_eval(values[0])


def legacy(repo=REPO):
    """Reuse exact pure Wine/Host Probe functions without Task #4 entrypoints."""
    raw=read_relative(repo,'host/probe/provisioned_probe.py')
    baseline=read_relative(repo,'host/probe/hardened_baseline.py')
    values={key:source_constant(raw,key)for key in ['APP_ID','TEAM_ID','CROSS_KEYS']}
    values.update({'datetime':datetime,'timezone':timezone,'hashlib':hashlib,'re':re,'ControlError':Error})
    values['BASELINE']=SimpleNamespace(ALLOW_JIT=source_constant(baseline,'ALLOW_JIT'))
    select_functions(raw,['validate_profile'],values,'host/probe/provisioned_probe.py')
    profile=SimpleNamespace(**values)
    namespace={'PROFILE':profile,'APP_ID':values['APP_ID'],'TEAM_ID':values['TEAM_ID'],
        'CROSS_KEYS':values['CROSS_KEYS'],'Error':Error,'need':need,'Path':Path,'os':os,'stat':stat,
        'struct':struct,'plistlib':plistlib,'re':re,'relative':relative,'sha256':sha256,
        'read_relative':read_relative,'MACH_ARM64':MACH_ARM64,'BUNDLE_ID':BUNDLE_ID,
        'ExpatError':__import__('xml.parsers.expat',fromlist=['ExpatError']).ExpatError}
    select_functions(read_relative(repo,'tools/wine/signing.py'),['_relative_target','inventory',
        '_code_parts','verify_code_origin','profile_authorization','loader_claims','signature_check'],
        namespace,'tools/wine/signing.py')
    return SimpleNamespace(**namespace)


def producers(repo=REPO):return {name:digest(read_relative(repo,name))for name in sorted(PRODUCERS)}


def pe_machine(raw):
    need(type(raw)is bytes and len(raw)>=64 and raw[:2]==b'MZ','pair_runtime_pe')
    at=struct.unpack_from('<I',raw,60)[0]
    need(64<=at and at+26<=len(raw)and raw[at:at+4]==b'PE\0\0','pair_runtime_pe')
    return struct.unpack_from('<H',raw,at+4)[0]


def cms_plist(raw):
    """Extract a bounded definite DER SignedData/data plist, not signature trust.

    Apple security cms supplies the independent real decode/trust observation.
    Comparing complete plist content prevents a receipt for another CMS payload
    from standing in for the captured bytes. This parser never admits BER or
    arbitrary CMS/OCTET search and does not claim entitlement issuance.
    """
    need(type(raw)is bytes and 0<len(raw)<=LIMIT,'pair_cms_size')
    def tlv(at,end):
        need(at+2<=end,'pair_cms_der')
        tag=raw[at];size=raw[at+1];cursor=at+2
        need(tag&31!=31,'pair_cms_der')
        if size&128:
            count=size&127
            need(0<count<=4 and cursor+count<=end and raw[cursor]!=0,'pair_cms_der')
            size=int.from_bytes(raw[cursor:cursor+count],'big');cursor+=count
            need(size>=128 and size.bit_length()>8*(count-1),'pair_cms_der')
        need(cursor+size<=end,'pair_cms_der')
        return tag,cursor,cursor+size
    def children(start,end):
        rows=[]
        while start<end:
            tag,a,b=tlv(start,end);rows.append((tag,a,b));start=b
            need(len(rows)<=32,'pair_cms_der')
        need(start==end,'pair_cms_der');return rows
    tag,a,b=tlv(0,len(raw));need(tag==48 and b==len(raw),'pair_cms_envelope')
    outer=children(a,b)
    signed_oid=b'\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02'
    data_oid=b'\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01'
    need(len(outer)==2 and outer[0][0]==6 and raw[outer[0][1]:outer[0][2]]==signed_oid
         and outer[1][0]==160,'pair_cms_envelope')
    body=children(outer[1][1],outer[1][2]);need(len(body)==1 and body[0][0]==48,'pair_cms_envelope')
    entries=children(body[0][1],body[0][2])
    need(4<=len(entries)<=6 and entries[0][0]==2 and entries[1][0]==49
         and entries[2][0]==48 and entries[-1][0]==49
         and [entry[0]for entry in entries[3:-1]]in [[],[160],[161],[160,161]],'pair_cms_envelope')
    content=children(entries[2][1],entries[2][2])
    need(len(content)==2 and content[0][0]==6 and raw[content[0][1]:content[0][2]]==data_oid
         and content[1][0]==160,'pair_cms_content')
    octets=children(content[1][1],content[1][2]);need(len(octets)==1 and octets[0][0]==4,'pair_cms_content')
    value=plistlib.loads(raw[octets[0][1]:octets[0][2]])
    need(type(value)is dict,'pair_cms_plist')
    return value


def native(argv,root,ident,commands):
    """Root-only Apple operations with exact recipes and retained failure streams."""
    need(platform.system()=='Darwin'and platform.machine()=='arm64','pair_native_signing_host')
    need(argv and argv[0]in ['/usr/bin/security','/usr/bin/codesign','/usr/sbin/system_profiler']
         and re.fullmatch('[a-z0-9][a-z0-9_.-]{0,95}',ident),'pair_signing_command')
    directory=root/'logs'/ident;directory.mkdir(parents=True,mode=0o700)
    if ident.endswith('.certificates'):
        signature_id=ident[:-len('.certificates')];prefix=certificate_prefix(root,signature_id)
        need(argv[:2]==['/usr/bin/codesign','--display']and len(argv)==4
             and argv[2]=='--extract-certificates='+str(prefix),'pair_certificate_command')
        prefix.parent.mkdir(parents=True,mode=0o700)
    actual=['/usr/bin/arch','-arm64',*argv];started=time.monotonic_ns()
    row={'id':ident,'argv':actual,'environment':dict(ENV),'cwd':str(root),'exit_code':None,
         'elapsed_ms':0,'status':'attempted','error':None,'bound_outcome':None,'evidence_error':None,'logs':{}}
    try:
        result=run_bounded(actual,cwd=root,env=ENV,timeout=60,limit=LIMIT,log_directory=directory)
        row.update(exit_code=result['exit_code'],elapsed_ms=result['elapsed_ms'],status='completed')
        need(type(result['exit_code'])is int and result['exit_code']==0,'pair_signing_command_failed')
        return result['stdout'],result['stderr']
    except (Exception,KeyboardInterrupt)as exc:
        row.update(status='failed',error=getattr(exc,'code','pair_signing_operation'),
                   bound_outcome=getattr(exc,'bound_outcome',None))
        row.update(failure_fields(exc))
        raise
    finally:
        row['elapsed_ms']=(time.monotonic_ns()-started)//1000000
        # Append before metadata reads so even a hash/stat failure retains argv.
        commands.append(row)
        for channel in ['stdout','stderr']:
            path=directory/channel
            if path.is_file()and not path.is_symlink():
                try:
                    raw=read_relative(directory,channel,LIMIT+65536)
                    row['logs'][channel]={'path':path.relative_to(root).as_posix(),'sha256':digest(raw),
                                         'size_bytes':len(raw)}
                except (Exception,KeyboardInterrupt)as evidence:
                    row['evidence_error']=getattr(evidence,'code','pair_signing_log_read')
                    if native_error(evidence)is not None:row['evidence_native_error']=native_error(evidence)
                    if row['status']!='failed':raise wrapped_error(evidence,row['evidence_error'])from evidence


def verify_commands(root,rows,recipe):
    need(type(rows)is list and len(rows)==len(recipe),'pair_signing_command_set')
    by_id={}
    for row,(ident,argv)in zip(rows,recipe):
        fields(row,['id','argv','environment','cwd','exit_code','elapsed_ms','status','error','bound_outcome','evidence_error','logs'])
        need(row['id']==ident and row['argv']==['/usr/bin/arch','-arm64',*argv]
             and row['environment']==ENV and row['cwd']==str(root) and type(row['exit_code'])is int
             and row['exit_code']==0 and type(row['elapsed_ms'])is int and 0<=row['elapsed_ms']<=65000
             and row['status']=='completed'and row['error']is None and row['bound_outcome']is None
             and row['evidence_error']is None,
             'pair_signing_command_recipe')
        need(type(row['logs'])is dict and set(row['logs'])=={'stdout','stderr'},'pair_signing_logs')
        by_id[ident]={}
        total=0
        for channel,ref in row['logs'].items():
            fields(ref,['path','sha256','size_bytes'])
            need(ref['path']=='logs/'+ident+'/'+channel,'pair_signing_log_path')
            raw=read_relative(root,ref['path'],LIMIT)
            need(type(ref['size_bytes'])is int and ref['size_bytes']==len(raw)and digest(raw)==ref['sha256'],
                 'pair_signing_log_changed')
            total+=len(raw);by_id[ident][channel]=raw
        need(total<=LIMIT,'pair_signing_log_limit')
    return by_id


def profile_recipe(root):
    return [('profile.decode',['/usr/bin/security','cms','-D','-i',str(root/'captured-profile.provisionprofile')]),
            ('profile.identities',['/usr/bin/security','find-identity','-v','-p','codesigning']),
            ('profile.device',['/usr/sbin/system_profiler','-json','SPHardwareDataType'])]


def profile_from_logs(raw,logs,reader):
    decoded=plistlib.loads(logs['profile.decode']['stdout'])
    same(plistlib.dumps(cms_plist(raw),fmt=plistlib.FMT_BINARY,sort_keys=True).hex(),
         plistlib.dumps(decoded,fmt=plistlib.FMT_BINARY,sort_keys=True).hex(),'pair_cms_decode_content')
    info=decode_json(logs['profile.device']['stdout'])['SPHardwareDataType']
    need(type(info)is list and len(info)==1 and type(info[0])is dict,'pair_profile_device')
    devices=[value for key,value in info[0].items()if 'provision'in key.casefold()]
    need(len(devices)==1 and type(devices[0])is str and devices[0],'pair_profile_device')
    return reader.profile_authorization(decoded,logs['profile.identities']['stdout'].decode('utf-8'),
                                        devices[0],BUNDLE_ID)


def capture_authorization(profile_path,root,reader,commands=None):
    profile_path=Path(profile_path).absolute();real_directory(profile_path.parent)
    need(not profile_path.is_symlink()and '..'not in profile_path.parts,'pair_profile_path')
    raw=read_relative(profile_path.parent,profile_path.name,LIMIT)
    captured=root/'captured-profile.provisionprofile'
    stage3.write_bytes(root,captured.name,raw,0o600)
    commands=[]if commands is None else commands
    for ident,argv in profile_recipe(root):native(argv,root,ident,commands)
    need(read_relative(root,captured.name,LIMIT)==raw
         and read_relative(profile_path.parent,profile_path.name,LIMIT)==raw,'pair_profile_changed')
    logs=verify_commands(root,commands,profile_recipe(root));private=profile_from_logs(raw,logs,reader)
    authorization={'schema_version':1,'record_kind':'dxmt_pairing_authorization','scope':SCOPE,
        'original_ref':{'path':str(profile_path),'sha256':digest(raw)},
        'capture':{'path':captured.name,'sha256':digest(raw),'size_bytes':len(raw),'mode':0o600},
        'claims':reader.loader_claims(private,'page-wx'),'identity':private['identity'],
        'checks':private['checks'],'granted_cross_architecture_key':private['granted_cross_architecture_key'],
        'commands':commands,'permission_admitted':False,'execution_performed':False}
    write_new(root/'authorization.json',authorization)
    return authorization,private,raw


def verify_authorization(root,authorization,reader):
    fields(authorization,['schema_version','record_kind','scope','original_ref','capture','claims','identity',
        'checks','granted_cross_architecture_key','commands','permission_admitted','execution_performed'],
        'dxmt_pairing_authorization')
    need(authorization['scope']==SCOPE and authorization['permission_admitted']is False
         and authorization['execution_performed']is False,'pair_authorization_scope')
    fields(authorization['original_ref'],['path','sha256']);fields(authorization['capture'],['path','sha256','size_bytes','mode'])
    ref=authorization['capture'];raw=read_relative(root,ref['path'],LIMIT)
    need(ref['path']=='captured-profile.provisionprofile'and type(ref['size_bytes'])is int
         and ref['size_bytes']==len(raw)and ref['sha256']==digest(raw)==authorization['original_ref']['sha256']
         and type(ref['mode'])is int and ref['mode']==0o600
         and stat.S_IMODE((root/ref['path']).stat().st_mode)==ref['mode'],'pair_profile_capture_changed')
    logs=verify_commands(root,authorization['commands'],profile_recipe(root))
    private=profile_from_logs(raw,logs,reader)
    same(authorization['claims'],reader.loader_claims(private,'page-wx'),'pair_authorization_claims_changed')
    same(authorization['checks'],private['checks'],'pair_authorization_checks_changed')
    need(authorization['identity']==private['identity']and
         authorization['granted_cross_architecture_key']==private['granted_cross_architecture_key'],
         'pair_authorization_identity_changed')
    return private,raw


def prerequisite(build_root,repo=REPO):
    built=pairing_check.verify_build(build_root,repo=repo)
    _,roots,ref=stage3.selector(built['role_reference']['path'],repo)
    same(ref,built['role_reference'],'pair_runtime_role_changed')
    baseline=pairing_build.source_baseline(roots['native']);install=real_directory(baseline['install_root'])
    need(install==roots['native']/'install'and baseline['code_publication_policy']=='page-wx'
         and baseline['variant']=='arm64'and baseline['fixture_suite']=='mac-driver','pair_runtime_baseline_scope')
    manifest=baseline['artifacts_manifest'];raw=read_relative(roots['native'],manifest['path'])
    need(digest(raw)==manifest['sha256'],'pair_runtime_baseline_manifest')
    value=decode_json(raw);fields(value,['schema_version','record_kind','files','symlinks'],'wine_build_inventory')
    return built,roots['native'],baseline,install,value


def source_ledger(build_root,baseline_root,baseline,install,manifest,reader):
    inventory=reader.inventory(install)
    files={row['path']:row for row in inventory if row['kind']=='file'}
    aliases={row['path']:row['target']for row in inventory if row['kind']=='symlink'}
    need(len(files)==len(manifest['files'])and len(aliases)==len(manifest['symlinks']),'pair_runtime_baseline_set')
    expected={row['path']:row for row in manifest['files']}
    need(len(expected)==len(manifest['files'])and set(expected)==set(files),'pair_runtime_baseline_set')
    for path,row in files.items():
        old=expected[path]
        same({key:row[key]for key in ['path','sha256','size_bytes','mode']},
             {key:old[key]for key in ['path','sha256','size_bytes','mode']},'pair_runtime_baseline_bytes')
    same(sorted([{'path':path,'target':target}for path,target in aliases.items()],key=lambda row:row['path']),
         manifest['symlinks'],'pair_runtime_baseline_aliases')
    replacements={DRIVER:('rebuilt-driver',pairing_check.REBUILT_DRIVER),
                  DRIVER_PE:('rebuilt-driver',pairing_check.REBUILT_PE),
                  WINEMETAL:('rebuilt-dxmt','dxmt/install/aarch64-unix/winemetal.so'),
                  FIXTURE:('fixture-pe',pairing_check.FIXTURE_PE)}
    need(DRIVER in files and DRIVER_PE in files and WINEMETAL not in files and FIXTURE not in files,
         'pair_runtime_replacement_scope')
    result=[]
    for row in inventory:
        path=row['path'];item=dict(row)
        if item['kind']=='file':
            item['format_kind']=expected[path]['kind']
            if item['format_kind']=='macho':
                raw=read_relative(install,path,512*1024**2)
                need(raw[:4]==b'\xcf\xfa\xed\xfe','pair_runtime_baseline_native_format')
                info=tools.readers().inspect_macho(install/path)
                need(info['architectures']==[MACH_ARM64]and info['filetype']in [2,6,8],
                     'pair_runtime_baseline_native_target')
            role='fixturehelper'if path in [API_LAUNCH,SENTINEL]else'baseline-native'
            item['origin']={'role':role,'path':path,'sha256':item['sha256']}
        item['runtime_path']=MAIN if path==LOADER else PAYLOAD+'/'+path
        if path in replacements:continue
        result.append(item)
    for path,(role,origin_path)in replacements.items():
        data=read_relative(build_root,origin_path,512*1024**2)
        mode=stat.S_IMODE((build_root/origin_path).stat().st_mode)
        need(mode in [0o644,0o755],'pair_runtime_replacement_mode')
        result.append({'path':path,'kind':'file','mode':mode,'sha256':digest(data),'size_bytes':len(data),
            'runtime_path':PAYLOAD+'/'+path,'format_kind':'macho'if data[:4]==b'\xcf\xfa\xed\xfe'else'pe',
            'origin':{'role':role,'path':origin_path,'sha256':digest(data)}})
    known={row['path']for row in result}
    for path in ['libexec/pear-dxmt']:
        need(path not in known,'pair_runtime_added_directory')
        result.append({'path':path,'kind':'directory','mode':0o755,'runtime_path':PAYLOAD+'/'+path})
    need({LOADER,NTDLL,SERVER,API_LAUNCH,SENTINEL,DRIVER,DRIVER_PE,WINEMETAL,FIXTURE}<=
         {row['path']for row in result if row['kind']=='file'},'pair_runtime_entrypoint_sources')
    return sorted(result,key=lambda row:row['path'])


def origin_file(row,install,build_root):
    origin=row['origin'];role=origin['role']
    parent=install if role in ['baseline-native','fixturehelper']else build_root
    raw=read_relative(parent,origin['path'],512*1024**2)
    need(digest(raw)==origin['sha256']==row['sha256']and len(raw)==row['size_bytes'],'pair_runtime_origin_changed')
    return parent/origin['path'],raw


def materialize(root,ledger,install,build_root,raw_profile):
    """Create exact ordinary files first, then only source-contained aliases."""
    for row in ledger:
        path=root/row['runtime_path']
        if row['kind']=='directory':
            path.mkdir(parents=True,exist_ok=True,mode=row['mode']);path.chmod(row['mode'])
        elif row['kind']=='file':
            _,raw=origin_file(row,install,build_root)
            stage3.write_bytes(root,row['runtime_path'],raw,row['mode'])
    for row in ledger:
        if row['kind']=='symlink':
            path=root/row['runtime_path'];path.parent.mkdir(parents=True,exist_ok=True)
            path.symlink_to(row['target'])
    original=root/PAYLOAD/LOADER
    original.symlink_to(os.path.relpath(root/MAIN,original.parent))
    alias=root/NTDLL_ALIAS;alias.symlink_to(os.path.relpath(root/PAYLOAD/NTDLL,alias.parent))
    stage3.write_bytes(root,BUNDLE+'/Contents/embedded.provisionprofile',raw_profile,0o600)
    stage3.write_bytes(root,BUNDLE+'/Contents/Info.plist',plistlib.dumps(INFO),0o644)


def entrypoints():
    return {'loader':MAIN,'server':PAYLOAD+'/'+SERVER,'bootstrap_helper':PAYLOAD+'/'+API_LAUNCH,
        'sentinel':PAYLOAD+'/'+SENTINEL,'fixture_pe':PAYLOAD+'/'+FIXTURE,
        'winemac_native':PAYLOAD+'/'+DRIVER,'winemac_pe':PAYLOAD+'/'+DRIVER_PE,
        'winemetal_native':PAYLOAD+'/'+WINEMETAL}


def inventory_images(root,ledger,install,build_root,reader):
    native_images=[];pe_images=[];closures=[]
    expected_paths={row['runtime_path']for row in ledger}
    expected_paths|={PAYLOAD+'/'+LOADER,NTDLL_ALIAS,BUNDLE+'/Contents/embedded.provisionprofile',BUNDLE+'/Contents/Info.plist'}
    actual=reader.inventory(root/BUNDLE)
    # Signing may add only the bundle's resource seal; its bytes are separately
    # bound in signed-files and verified with codesign, never a native origin.
    names={BUNDLE+'/'+row['path']for row in actual}
    extras={BUNDLE+'/Contents',BUNDLE+'/Contents/MacOS',BUNDLE+'/Contents/Resources',PAYLOAD}
    seal={BUNDLE+'/Contents/_CodeSignature',BUNDLE+'/Contents/_CodeSignature/CodeResources'}
    need(expected_paths<=names and names-expected_paths-extras<=seal,'pair_runtime_payload_set')
    for row in ledger:
        path=root/row['runtime_path']
        if row['kind']=='directory':
            need(path.is_dir()and not path.is_symlink()and stat.S_IMODE(path.stat().st_mode)==row['mode'],
                 'pair_runtime_directory_changed');continue
        if row['kind']=='symlink':
            need(path.is_symlink()and os.readlink(path)==row['target'],'pair_runtime_alias_changed');continue
        raw=read_relative(root,row['runtime_path'],512*1024**2)
        need(stat.S_IMODE(path.stat().st_mode)==row['mode'],'pair_runtime_file_mode')
        origin,source=origin_file(row,install,build_root)
        if row['format_kind']=='macho':
            need(source[:4]==b'\xcf\xfa\xed\xfe','pair_runtime_native_format')
            reader.verify_code_origin(origin,path)
            info=tools.readers().inspect_macho(path)
            need(info['architectures']==[MACH_ARM64]and info['filetype']in [2,6,8], 'pair_runtime_native_target')
            closure=tools.readers().inspect_closure(path,root/BUNDLE)
            need(all(item['architectures']==[MACH_ARM64]and item['selected_cpu']==MACH_ARM64 for item in closure),
                 'pair_runtime_dependency_target')
            native_images.append({'path':row['runtime_path'],'sha256':digest(raw),'size_bytes':len(raw),
                'origin':row['origin'],'code_origin':{'scope':'macho_signature_fields_only','verified':True},
                'signature':None})
            closures.append({'path':row['runtime_path'],'images':closure})
        else:
            need(raw==source,'pair_runtime_data_changed')
            if row['format_kind']=='pe':
                pe_machine(source)
                pe_images.append({'path':row['runtime_path'],'sha256':digest(raw),'size_bytes':len(raw),'origin':row['origin']})
    for path,target in [(PAYLOAD+'/'+LOADER,os.path.relpath(root/MAIN,(root/PAYLOAD/LOADER).parent)),
                        (NTDLL_ALIAS,os.path.relpath(root/PAYLOAD/NTDLL,(root/NTDLL_ALIAS).parent))]:
        need((root/path).is_symlink()and os.readlink(root/path)==target,'pair_runtime_owned_alias')
    need(sum(row['origin']['path']==NTDLL and row['origin']['role']=='baseline-native'for row in native_images)==1,
         'pair_runtime_ntdll_set')
    return sorted(native_images,key=lambda row:row['path']),sorted(pe_images,key=lambda row:row['path']),closures


def signature_recipe(path,ident,root):
    return [(ident+'.verify',['/usr/bin/codesign','--verify','--strict',str(path)]),
            (ident+'.metadata',['/usr/bin/codesign','--display','--verbose=4',str(path)]),
            (ident+'.claims',['/usr/bin/codesign','--display','--entitlements',':-',str(path)]),
            (ident+'.certificates',['/usr/bin/codesign','--display',
                '--extract-certificates='+str(certificate_prefix(root,ident)),str(path)])]


def signature_from_logs(logs,ident,claims,private,reader,identifier):
    metadata=logs[ident+'.metadata']['stderr'].decode('utf-8')
    need(re.findall(r'^Identifier=([^\r\n]+)$',metadata,re.M)==[identifier],'pair_signature_identifier')
    observed=reader.signature_check(metadata,logs[ident+'.claims']['stdout'],claims,private['claims'][reader.TEAM_ID])
    need(observed['code_directory_page_size']==4096,'pair_signature_page_size')
    return observed


def signing_recipe(root,images,identity):
    recipe=[]
    for index,row in enumerate(images):
        if row['path']==MAIN:continue
        ident='native.'+str(index);path=root/row['path']
        recipe.append((ident+'.sign',['/usr/bin/codesign','--force','--sign',identity,'--options','runtime',
            '--timestamp=none','--pagesize','4096','--identifier',BUNDLE_ID+'.native.'+str(index),str(path)]))
        recipe.extend(signature_recipe(path,ident,root))
    recipe.append(('loader.sign',['/usr/bin/codesign','--force','--sign',identity,'--options','runtime',
        '--timestamp=none','--pagesize','4096','--entitlements',str(root/'authorized-entitlements.plist'),
        '--identifier',BUNDLE_ID,str(root/BUNDLE)]))
    recipe.extend(signature_recipe(root/MAIN,'loader',root));recipe.extend(signature_recipe(root/BUNDLE,'bundle',root))
    return recipe


def signatures_from_logs(root,images,logs,claims,private,reader,raw_profile):
    result=[]
    for index,row in enumerate(images):
        restricted=row['path']==MAIN;ident='loader'if restricted else'native.'+str(index)
        observed=signature_from_logs(logs,ident,claims if restricted else{},private,reader,
                                    BUNDLE_ID if restricted else BUNDLE_ID+'.native.'+str(index))
        signer_leaf(root,ident,private,raw_profile)
        result.append({**row,'signature':observed})
    signature_from_logs(logs,'bundle',claims,private,reader,BUNDLE_ID)
    signer_leaf(root,'bundle',private,raw_profile)
    return result


def prepare(build_root,profile_path,output,repo=REPO):
    build_root=owned_directory(build_root,repo);built,baseline_root,baseline,install,manifest=prerequisite(build_root,repo)
    reader=legacy(repo);ledger=source_ledger(build_root,baseline_root,baseline,install,manifest,reader)
    required=sum(row.get('size_bytes',0)for row in ledger)
    need(shutil.disk_usage(repo).free>=required+RESERVE,'pair_runtime_storage_admission')
    root=output_directory(output,repo);root.chmod(0o700);commands=[];authorization_commands=[]
    phase='authorization';authorization=None
    try:
        current=producers(repo)
        for path,sha in current.items():
            raw=read_relative(repo,path);need(digest(raw)==sha,'pair_runtime_producer_changed')
            stage3.write_bytes(root,'producers/'+path,raw)
        authorization,private,raw_profile=capture_authorization(profile_path,root,reader,authorization_commands)
        phase='materialization';materialize(root,ledger,install,build_root,raw_profile)
        materialization={'schema_version':1,'record_kind':'dxmt_pairing_materialization','scope':SCOPE,
            'baseline_ref':{'path':str(baseline_root),'sha256':digest(read_relative(baseline_root,'build.json'))},
            'baseline_manifest':baseline['artifacts_manifest'],'source_ledger':ledger,'entrypoints':entrypoints(),
            'arena_capacity':baseline['arena_capacity'],'capacity_scope':'retained_source_bound_loader_capacity',
            'build_ref':stage3.reference(build_root,'build.json'),
            'signing_performed':False,'execution_performed':False}
        write_new(root/'materialization.json',materialization)
        stage3.write_bytes(root,'authorized-entitlements.plist',plistlib.dumps(authorization['claims']),0o600)
        images,_,_=inventory_images(root,ledger,install,build_root,reader)
        phase='signing'
        for ident,argv in signing_recipe(root,images,private['identity']):native(argv,root,ident,commands)
        phase='signed_byte_replay'
        unsigned_images,pe_images,closures=inventory_images(root,ledger,install,build_root,reader)
        logs=verify_commands(root,commands,signing_recipe(root,unsigned_images,private['identity']))
        native_images=signatures_from_logs(root,unsigned_images,logs,authorization['claims'],private,reader,raw_profile)
        need(read_relative(root,BUNDLE+'/Contents/embedded.provisionprofile',LIMIT)==raw_profile,'pair_embedded_profile_changed')
        signed={'schema_version':1,'record_kind':'dxmt_pairing_signed_runtime','scope':SCOPE,
            'materialization_ref':{'path':'materialization.json','sha256':digest(read_relative(root,'materialization.json'))},
            'commands':commands,'native_dependency_closure':closures,'bundle_inventory':reader.inventory(root/BUNDLE),
            'passed':True,'execution_performed':False,'runtime_eligible':False,'distribution_qualified':False}
        write_new(root/'signed.json',signed)
        runtime={'schema_version':1,'record_kind':'dxmt_pairing_runtime','build_ref':stage3.reference(build_root,'build.json'),
            'producers':current,'native_images':native_images,'pe_images':pe_images,'entrypoints':entrypoints(),
            'authorization':{'path':'authorization.json','sha256':digest(read_relative(root,'authorization.json'))},
            'signed_receipt':{'path':'signed.json','sha256':digest(read_relative(root,'signed.json'))},
            'arena_capacity':baseline['arena_capacity'],'code_publication_policy':'page-wx',
            'runtime_eligible':False,'game_qualified':False}
        need(producers(repo)==current,'pair_runtime_producer_changed')
        write_new(root/'runtime.json',runtime)
        phase='current_admission';return verify_runtime(root,repo=repo)
    except (Exception,KeyboardInterrupt)as exc:
        write_new(root/'failed.json',{'schema_version':1,'record_kind':'dxmt_pairing_runtime_failure','phase':phase,
            'error':getattr(exc,'code','pair_runtime_operation'),
            'errno':native_error(exc)['code']if native_error(exc)is not None else None,**failure_fields(exc),
            'commands':commands,'authorization_commands':authorization_commands,'authorization':authorization,'passed':False,'runtime_eligible':False})
        raise wrapped_error(exc,getattr(exc,'code','pair_runtime_operation'))from exc


def verify_structural(root,repo=REPO):
    root=owned_directory(root,repo);need(not(root/'failed.json').exists(),'pair_failed_runtime')
    runtime=decode_json(read_relative(root,'runtime.json'));fields(runtime,RUNTIME_FIELDS,'dxmt_pairing_runtime')
    need(runtime['code_publication_policy']=='page-wx'and runtime['runtime_eligible']is False
         and runtime['game_qualified']is False,'pair_runtime_scope')
    same(runtime['producers'],producers(repo),'pair_runtime_producer_changed')
    for path,sha in runtime['producers'].items():need(digest(read_relative(root,'producers/'+path))==sha,'pair_runtime_producer_snapshot')
    snapshots=tools.files(root/'producers')
    need({row['path']for row in snapshots}==set(runtime['producers'])
         and all(row['mode']==0o644 for row in snapshots),'pair_runtime_producer_snapshot_set')
    fields(runtime['build_ref'],['path','sha256']);build_root=owned_directory(runtime['build_ref']['path'],repo)
    need(digest(read_relative(build_root,'build.json'))==runtime['build_ref']['sha256'],'pair_runtime_build_changed')
    built,baseline_root,baseline,install,manifest=prerequisite(build_root,repo);reader=legacy(repo)
    ledger=source_ledger(build_root,baseline_root,baseline,install,manifest,reader)
    for key,path in [('authorization','authorization.json'),('signed_receipt','signed.json')]:
        fields(runtime[key],['path','sha256']);need(runtime[key]['path']==path
            and digest(read_relative(root,path))==runtime[key]['sha256'],'pair_runtime_receipt_changed')
    authorization=decode_json(read_relative(root,'authorization.json'));private,raw=verify_authorization(root,authorization,reader)
    need(read_relative(root,BUNDLE+'/Contents/embedded.provisionprofile',LIMIT)==raw
         and stat.S_IMODE((root/BUNDLE/'Contents/embedded.provisionprofile').stat().st_mode)==0o600,
         'pair_embedded_profile_changed')
    same(plistlib.loads(read_relative(root,'authorized-entitlements.plist',LIMIT)),authorization['claims'],
         'pair_runtime_entitlements_changed')
    need(stat.S_IMODE((root/'authorized-entitlements.plist').stat().st_mode)==0o600,'pair_runtime_private_claims_mode')
    signed=decode_json(read_relative(root,'signed.json'));fields(signed,['schema_version','record_kind','scope',
        'materialization_ref','commands','native_dependency_closure','bundle_inventory','passed',
        'execution_performed','runtime_eligible','distribution_qualified'],'dxmt_pairing_signed_runtime')
    need(signed['scope']==SCOPE and signed['passed']is True and all(signed[key]is False for key in
        ['execution_performed','runtime_eligible','distribution_qualified']),'pair_signed_scope')
    fields(signed['materialization_ref'],['path','sha256']);need(signed['materialization_ref']['path']=='materialization.json'
        and digest(read_relative(root,'materialization.json'))==signed['materialization_ref']['sha256'],'pair_materialization_changed')
    expected={'schema_version':1,'record_kind':'dxmt_pairing_materialization','scope':SCOPE,
        'baseline_ref':{'path':str(baseline_root),'sha256':digest(read_relative(baseline_root,'build.json'))},
        'baseline_manifest':baseline['artifacts_manifest'],'source_ledger':ledger,'entrypoints':entrypoints(),
        'arena_capacity':baseline['arena_capacity'],'capacity_scope':'retained_source_bound_loader_capacity',
        'build_ref':runtime['build_ref'],
        'signing_performed':False,'execution_performed':False}
    same(decode_json(read_relative(root,'materialization.json')),expected,'pair_materialization_derivation_changed')
    images,pe_images,closures=inventory_images(root,ledger,install,build_root,reader)
    logs=verify_commands(root,signed['commands'],signing_recipe(root,images,private['identity']))
    native_images=signatures_from_logs(root,images,logs,authorization['claims'],private,reader,raw)
    same(native_images,runtime['native_images'],'pair_runtime_native_images_changed')
    same(pe_images,runtime['pe_images'],'pair_runtime_pe_images_changed')
    same(closures,signed['native_dependency_closure'],'pair_runtime_dependency_changed')
    same(reader.inventory(root/BUNDLE),signed['bundle_inventory'],'pair_runtime_inventory_changed')
    same(runtime['entrypoints'],entrypoints(),'pair_runtime_entrypoints_changed')
    same(runtime['arena_capacity'],baseline['arena_capacity'],'pair_runtime_capacity_changed')
    info=plistlib.loads(read_relative(root,BUNDLE+'/Contents/Info.plist',LIMIT))
    same(info,INFO,'pair_bundle_identity_changed')
    need(stat.S_IMODE((root/BUNDLE/'Contents/Info.plist').stat().st_mode)==0o644,'pair_bundle_info_mode')
    return runtime,private,raw


def admission_recipe(root,runtime):
    recipe=profile_recipe(root)
    for index,row in enumerate(runtime['native_images']):
        recipe.extend(signature_recipe(Path(root).parents[1]/row['path'],'current.'+str(index),root))
    recipe.extend(signature_recipe(Path(root).parents[1]/BUNDLE,'current.bundle',root))
    return recipe


def verify_runtime(root,repo=REPO):
    """Root-only fresh Apple admission, never Wine/PE/Metal execution."""
    root=owned_directory(root,repo);runtime,original,raw=verify_structural(root,repo)
    directory=root/'admission'/uuid.uuid4().hex;directory.mkdir(parents=True,mode=0o700)
    commands=[]
    try:
        # Decode an owned immutable copy of the currently bound embedded bytes.
        stage3.write_bytes(directory,'captured-profile.provisionprofile',raw,0o600)
        reader=legacy(repo);recipe=admission_recipe(directory,runtime)
        for ident,argv in recipe:native(argv,directory,ident,commands)
        logs=verify_commands(directory,commands,recipe);current=profile_from_logs(raw,logs,reader)
        same(current['claims'],original['claims'],'pair_current_profile_claims_changed')
        need(current['identity']==original['identity'],'pair_current_profile_identity_changed')
        claims=reader.loader_claims(current,'page-wx')
        for index,row in enumerate(runtime['native_images']):
            restricted=row['path']==MAIN
            observed=signature_from_logs(logs,'current.'+str(index),claims if restricted else{},current,reader,
                BUNDLE_ID if restricted else BUNDLE_ID+'.native.'+str(index))
            signer_leaf(directory,'current.'+str(index),current,raw)
            same(observed,row['signature'],'pair_current_signature_changed')
        signature_from_logs(logs,'current.bundle',claims,current,reader,BUNDLE_ID)
        signer_leaf(directory,'current.bundle',current,raw)
        need(read_relative(root,BUNDLE+'/Contents/embedded.provisionprofile',LIMIT)==raw
             and read_relative(directory,'captured-profile.provisionprofile',LIMIT)==raw,'pair_current_profile_changed')
        # Current bytes and complete payload ledger must also survive admission.
        repeated,_,_=verify_structural(root,repo);same(repeated,runtime,'pair_runtime_changed_during_admission')
        write_new(directory/'admission.json',{'schema_version':1,'record_kind':'dxmt_pairing_admission','scope':SCOPE,
            'runtime_ref':{'path':str(root),'sha256':digest(read_relative(root,'runtime.json'))},
            'profile_sha256':digest(raw),'commands':commands,'current_checks':current['checks'],
            'passed':True,'execution_performed':False,'runtime_eligible':False,'distribution_qualified':False})
        return runtime
    except (Exception,KeyboardInterrupt)as exc:
        write_new(directory/'failed.json',{'schema_version':1,'record_kind':'dxmt_pairing_admission_failure',
            'error':getattr(exc,'code','pair_current_admission_operation'),**failure_fields(exc),'commands':commands,
            'passed':False,'runtime_eligible':False})
        raise wrapped_error(exc,getattr(exc,'code','pair_current_admission_operation'))from exc


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--artifact',required=True)
    parser.add_argument('--profile',required=True);parser.add_argument('--output',required=True)
    parser.add_argument('--require-empty',required=True,action='store_true');args=parser.parse_args(argv)
    try:
        value=prepare(args.artifact,args.profile,args.output)
        print(encoded({'development_admission':'passed','native_images':len(value['native_images']),
            'pe_images':len(value['pe_images']),'execution_performed':False,'runtime_eligible':False}).decode(),end='')
        return 0
    except (Error,OSError,ValueError,KeyError,TypeError)as exc:
        print(encoded({'development_admission':'failed','error':getattr(exc,'code','pair_runtime_failed'),
            'execution_performed':False,'runtime_eligible':False}).decode(),end='',file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
