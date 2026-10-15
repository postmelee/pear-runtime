# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Admit one exact Wine-owned API fixture variant, never a general PE override."""
import ast
import hashlib
import struct
from pathlib import Path

from pear_runtime import build
from pear_runtime.assembly import core
from pear_runtime.assembly.helpers import PAYLOAD, SourcePack, signing_helpers
from pear_runtime.errors import need
from pear_runtime.fixtures.inputs import fact
from .binding import pe_timestamps

FIELDS={'schema_version','scope','policy_ref','recipe_ref','bindings_ref','build_ref','operation_ref','fixture_ref'}
VARIANT='arm64ec-class181-arm64-i386-v1'


def _generator(path, row):
    raw=path.read_bytes();need(fact(path)==row,'native_api_generator_changed')
    tree=ast.parse(raw,filename=str(path));namespace={'hashlib':hashlib,'__name__':'pear_native_api_variant_capture'}
    constants={'ORIGINAL_SHA256','ORIGINAL_SIZE','VARIANT','OLD','NEW'}
    functions={'generate','expected_architecture','provenance','tool_input_rows'}
    found=set();nodes=[]
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in constants:
            name=node.targets[0].id;need(name not in found,'native_api_generator_duplicate');found.add(name)
            namespace[name]=ast.literal_eval(node.value)
        if isinstance(node,ast.FunctionDef) and node.name in functions:
            need(node.name not in found and not node.decorator_list,'native_api_generator_duplicate');found.add(node.name);nodes.append(node)
    need(found==constants|functions,'native_api_generator_closure')
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),namespace)
    return namespace


def _recipe_inputs(recipe, bindings, built):
    roots=bindings['roots']
    need(set(roots)==set(recipe['roots'])==set(built['roots'])==
         {'wine','runtime','tools','baseline','configuration','host'} and built['inputs']==recipe['inputs'],
         'native_api_recipe_input_join')
    expected={};refs=[]
    for name,path in roots.items():
        directory=Path(path)
        need(directory.is_absolute() and directory.resolve(strict=True)==directory and directory.is_dir() and
             built['roots'][name]==dict(path=path,**recipe['roots'][name]),'native_api_recipe_root')
    for row in recipe['inputs']:
        rel=str(build.relative(row['path']));key=row['root'],rel
        need(key not in expected and row['root'] in roots,'native_api_recipe_input')
        path=Path(roots[row['root']])/rel
        need(path.resolve(strict=True).is_relative_to(Path(roots[row['root']])),'native_api_input_escape')
        if row.get('kind')=='symlink':
            need(path.is_symlink() and str(path.readlink())==row['target'],'native_api_input_alias')
        else:
            need(not path.is_symlink(),'native_api_input_alias')
            actual=fact(path)
            need(type(row['size_bytes']) is int and actual['sha256']==row['sha256'] and
                 actual['size_bytes']==row['size_bytes'],'native_api_build_input_changed')
            refs.append(fact(path.resolve(strict=True)))
        expected[key]=row
    return roots,expected,refs


def verify(ref, inputs, runtime, packet, provider):
    value=core.read_ref(ref)
    need(set(value)==FIELDS and type(value['schema_version']) is int and value['schema_version']==1 and
         value['scope']=='development_native_api_variant','native_api_variant_shape')
    policy=core.read_ref(value['policy_ref']);wine=Path(inputs['wine_source_ref']['path']).parent.parent
    need(Path(value['policy_ref']['path'])==wine/'pear/native-api-variant.json' and
         type(policy['schema_version']) is int and policy['schema_version']==1 and
         policy['variant']==VARIANT and policy['scope']=='selected_wine_api_fixture_variant','native_api_variant_policy')
    source_ref={'path':str(wine/policy['original']['path']),**{k:policy['original'][k] for k in ('sha256','size_bytes')}}
    generator_ref={'path':str(wine/policy['generator']['path']),**{k:policy['generator'][k] for k in ('sha256','size_bytes')}}
    source=core.checked_ref(source_ref);generator=core.checked_ref(generator_ref)
    need(source_ref==inputs['source_refs']['api_pe.c'] and generator==wine/'pear/native_api_variant.py',
         'native_api_variant_source_owner')
    owner=_generator(generator,generator_ref);generated=owner['generate'](source.read_bytes())
    need(owner['VARIANT']==VARIANT and policy['expected_architecture']==owner['expected_architecture']() and
         policy['generated_sha256']==hashlib.sha256(generated).hexdigest(),'native_api_variant_contract')
    recipe=core.read_ref(value['recipe_ref']);bindings=core.read_ref(value['bindings_ref']);built=core.read_ref(value['build_ref'])
    operation=core.read_ref(value['operation_ref']);root=Path(value['build_ref']['path']).parent
    need(built['scope']=='development_component_build' and built['status']=='passed' and built['variant']==VARIANT and
         built['runtime_eligible'] is False and built['game_qualified'] is False and
         built['recipe_sha256']==value['recipe_ref']['sha256'] and built['recipe_ref']==value['recipe_ref'] and
         built['bindings_ref']==value['bindings_ref'] and built['source_ref']==source_ref and
         built['generator_ref']==generator_ref and built['original_build_ref']==inputs['build_ref'],
         'native_api_variant_build_join')
    need(value['operation_ref']['path']==str(root/'operation.json') and operation['scope']=='task56_component_build' and
         operation['operation_id']==built['operation_id'] and operation['released'] is True,
         'native_api_variant_operation')
    roots,expected,refs=_recipe_inputs(recipe,bindings,built)
    need(Path(roots['wine'])==wine and Path(roots['baseline'])==Path(inputs['build_ref']['path']).parent and
         recipe['name']=='native-api-arm64ec-v1' and recipe['generator_sha256']==generator_ref['sha256'],
         'native_api_variant_recipe')
    manifest_ref=built['tool_evidence']['manifest_ref'];tool_manifest=core.read_ref(manifest_ref)
    prepared=core.read_ref(built['tool_evidence']['prepared_ref']);original=core.read_ref(inputs['build_ref'])
    need(built['tool_evidence']['prepared_ref']['sha256']==original['tool_prepared_sha256'] and
         manifest_ref['sha256']==next(row for row in prepared['artifacts'] if row['id']=='llvm-mingw')['files_manifest']['sha256'],
         'native_api_variant_tool_origin')
    need(sorted([row for row in recipe['inputs'] if row['root']=='tools' and row['path'].startswith('llvm-mingw/')],
                key=lambda row:row['path'])==owner['tool_input_rows'](tool_manifest),'native_api_variant_tool_closure')
    link=built['tool_evidence']['directory_link'];path=Path(link['path'])
    need(path==Path(roots['tools'])/'llvm-mingw/aarch64-w64-mingw32/include' and path.is_symlink() and
         str(path.readlink())==link['target']=='../generic-w64-mingw32/include','native_api_variant_include_alias')
    need(built['artifacts']=={'native_api_pe':value['fixture_ref']} and value['fixture_ref']['path']==str(root/'api-arm64ec.exe'),
         'native_api_variant_artifact')
    fixture=core.checked_ref(value['fixture_ref']);c_ref=built['outputs']['api-arm64ec.c']
    need(c_ref['path']==str(root/'api-arm64ec.c') and core.checked_ref(c_ref).read_bytes()==generated,
         'native_api_generated_source')
    need(core.read_ref(built['generation_ref'])==owner['provenance'](source.read_bytes()) and
         built['expected_architecture']==owner['expected_architecture'](),'native_api_generation_receipt')
    old=next(row for row in original['commands'] if row['id']=='fixture-api-arm64')['argv']
    argv=[*old[:12],str(root/'api-arm64ec.c'),'-lkernel32','-o',str(fixture),'-MD','-MF',str(root/'api-arm64ec.d'),'-v']
    commands=built['commands'];need(len(commands)==1,'native_api_variant_command_set');command=commands[0]
    need(command['id']=='fixture-api-arm64ec' and command['argv']==argv and command['cwd']==str(root) and
         type(command['exit_code']) is int and command['exit_code']==0 and command['error'] is None,
         'native_api_variant_command')
    need(command['env']=={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C','TMPDIR':str(root/'tmp')},
         'native_api_variant_environment')
    for row in command['logs'].values():core.checked_ref(row)
    need(len(built['dependencies'])==1 and built['dependencies'][0]['depfile']==built['outputs']['api-arm64ec.d'],
         'native_api_variant_dependencies')
    allowed={row['path']:row for row in refs};allowed[c_ref['path']]=c_ref
    group=built['dependencies'][0];core.checked_ref(group['depfile'])
    need(group['files'] and all(allowed.get(row['path'])==row for row in group['files']) and c_ref in group['files'],
         'native_api_variant_dependency_binding')
    for row in group['files']:core.checked_ref(row)
    raw=fixture.read_bytes();machine,_=pe_timestamps(raw);pe=struct.unpack_from('<I',raw,60)[0]
    need(machine==0xaa64 and struct.unpack_from('<H',raw,pe+24)[0]==0x20b and
         not struct.unpack_from('<H',raw,pe+22)[0]&0x2000,'native_api_variant_machine')
    # Current server is the admitted ARM64EC configuration, not the old native-only build.
    config=Path(roots['configuration']);makefile=(config/'objects/Makefile').read_text()
    need('\nPE_ARCHS =  aarch64 arm64ec\n' in makefile and '\nPEAR_NATIVE_ONLY_ARCH_CFLAGS = \n' in makefile,
         'native_api_variant_configuration')
    for name,row in policy['contract_sources'].items():
        current=wine/name;core.checked_ref({'path':str(current),**row})
    _,reader=signing_helpers(SourcePack(provider))
    original_server=config/'install/bin/wineserver';reader.verify_code_origin(original_server,runtime/PAYLOAD/'bin/wineserver')
    need({k:v for k,v in fact(original_server).items() if k!='path'}==policy['server_build_artifact'],
         'native_api_variant_server_source')
    snapshots=[ref,value['policy_ref'],value['recipe_ref'],value['bindings_ref'],value['build_ref'],value['operation_ref'],
               generator_ref,source_ref,c_ref,built['generation_ref'],manifest_ref,built['tool_evidence']['prepared_ref']]
    return {'binding_ref':ref,'fixture_ref':value['fixture_ref'],'expected_architecture':owner['expected_architecture'](),
            'variant':VARIANT,'cold_prefix_initialization':False,'snapshots':snapshots}
