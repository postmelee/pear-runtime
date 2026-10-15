#!/usr/bin/env python3
"""Construct the owned DXMT ARM64X/native pair; never load a guest or GPU.

Reuse pinned upstream Meson and immutable Stage 2 prerequisites. Raw compiler,
Wine builtin-marker, install and independent inspection phases stay distinct.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys

from common import (REPO, MACH_ARM64, Error, decode_json, digest, encoded, fields,
                    git, load_json, need, open_relative, output_directory,
                    owned_directory, read_relative, real_directory, relative,
                    sha256, write_new)
from prepare import validate_inputs, verify_prepared
from check import (inspect_cross_tools, inspect_wine_role, validate_config,
                   validate_toolchain, file_fact)
import build_native
import tools

PE_TARGETS = {
    'd3d11.dll': 'src/d3d11/d3d11.dll',
    'dxgi.dll': 'src/dxgi/dxgi.dll',
    'd3d10core.dll': 'src/d3d10/d3d10core.dll',
    'winemetal.dll': 'src/winemetal/winemetal.dll',
}
NATIVE_TARGET = 'src/winemetal/unix/winemetal.so'
NATIVE_ROLE_PATHS = ['bin/winebuild'] + [
    'lib/wine/aarch64-unix/' + name + '.so'
    for name in ['ntdll', 'winemac', 'win32u']]
COMPANION_ROLE_PATHS = ['lib/wine/aarch64-windows/lib' + name + '.a'
                        for name in ['winecrt0', 'ntdll', 'dbghelp']]
NOTICE_COMPONENTS = ('dxmt-upstream', 'dxmt-directx', 'llvm-dxmt', 'wine-upstream',
                     'llvm-mingw-source', 'llvm-mingw-llvm', 'mingw-w64-source')
BUILD_FIELDS = ['schema_version', 'record_kind', 'scope', 'refs', 'prepared_ref',
                'native_ref', 'tools_ref', 'wine_roles_ref', 'producers', 'policy',
                'environment', 'generated_inputs', 'wine_layout', 'role_facts',
                'source_files', 'commands', 'artifacts_manifest', 'passed',
                'dxmt_built', 'pairing_verified', 'gpu_or_guest_execution_performed',
                'runtime_eligible']


def inspector():
    spec = importlib.util.spec_from_file_location(
        '_pear_dxmt_artifact_inspector', REPO / 'tools/dxmt/inspect.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def producers(repo=REPO):
    paths = list(build_native.producers(repo)) + [
        'tools/dxmt/build.py', 'tools/dxmt/inspect.py',
        'tools/dxmt/verify.py', 'tools/wine/modules.py']
    return {name: digest(read_relative(repo, name)) for name in sorted(set(paths))}


def reference(root, name):
    return {'path': str(root), 'sha256': sha256(root / name)}


def input_values(refs, repo=REPO):
    need(set(refs) == {'inputs', 'config', 'toolchain'}, 'artifact_input_set')
    values = {}
    for name, ref in refs.items():
        fields(ref, ['path', 'sha256'])
        raw = read_relative(repo, ref['path'])
        need(digest(raw) == ref['sha256'], 'artifact_input_changed')
        values[name] = decode_json(raw)
    return (validate_inputs(values['inputs'], repo),
            validate_config(values['config']),
            validate_toolchain(values['toolchain'], repo))


def selector(path, repo=REPO):
    path = Path(path).absolute()
    parent = owned_directory(path.parent, repo)
    raw = read_relative(parent, path.name)
    value = decode_json(raw)
    fields(value, ['schema_version', 'record_kind', 'scope', 'native', 'companion',
                   'cross_tools'], 'dxmt_wine_role_selection')
    need(value['scope'] == 'dxmt_component', 'artifact_role_scope')
    roots = {name: real_directory(value[name])
             for name in ['native', 'companion', 'cross_tools']}
    need(roots['native'] != roots['companion'], 'artifact_role_mixed')
    return value, roots, {'path': str(path), 'sha256': digest(raw)}


def role_layout(roots, inputs, lock):
    facts = {name: inspect_wine_role(roots[name], name, inputs)
             for name in ['native', 'companion']}
    facts['cross_tools'] = inspect_cross_tools(roots['cross_tools'], lock)
    rows = []
    for role, selected in [('native', NATIVE_ROLE_PATHS),
                           ('companion', COMPANION_ROLE_PATHS)]:
        root = roots[role]
        build = load_json(root / 'build.json')
        manifest = load_json(root / build['artifacts_manifest']['path'])
        files = {row['path']: row for row in manifest['files']}
        for path in selected:
            need(path in files and 'symlink' not in files[path], 'artifact_role_missing')
            observed = file_fact(root / 'install', path, files[path])
            if path.endswith('.so') or path == 'bin/winebuild':
                actual = tools.readers().inspect_macho(root / 'install' / path)
                need(actual['architectures'] == [MACH_ARM64]
                     and actual['selected_cpu'] == MACH_ARM64
                     and actual['filetype'] == (2 if path == 'bin/winebuild' else 6),
                     'artifact_role_native_target')
                need(all(dep.startswith(('/System/Library/', '/usr/lib/'))
                         or dep in ['@rpath/ntdll.so', '@rpath/win32u.so']
                         for dep in actual['dependencies']), 'artifact_role_dependency')
            rows.append({**observed, 'path': 'wine-layout/' + path,
                         'origin_role': role, 'origin_path': path})
    return facts, rows


def write_bytes(root, path, raw, mode=0o644):
    """Create through owned directory descriptors; never follow output aliases."""
    parts = relative(path)
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in parts[:-1]:
            try:
                os.mkdir(name, dir_fd=parent)
            except FileExistsError:
                pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     mode, dir_fd=parent)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            os.fchmod(stream.fileno(), mode)
    finally:
        os.close(parent)


def copy_layout(root, rows, roots):
    for row in rows:
        raw = read_relative(roots[row['origin_role']] / 'install',
                            row['origin_path'], 64 * 1024**2)
        need(digest(raw) == row['sha256'] and len(raw) == row['size_bytes'],
             'artifact_role_copy_changed')
        write_bytes(root, row['path'], raw, row['mode'])


def check_layout(root, rows, expected):
    need(rows == expected, 'artifact_role_layout_changed')
    actual = tools.files(root / 'wine-layout')
    wanted = [{key: row[key] for key in ['path', 'sha256', 'size_bytes', 'mode']}
              for row in rows]
    wanted = [{**row, 'path': row['path'].removeprefix('wine-layout/')}
              for row in wanted]
    need(actual == sorted(wanted, key=lambda row: row['path']), 'artifact_role_bytes_changed')


def cross_file(cross_root):
    text = '[binaries]\n'
    for name, leaf in [('c', 'gcc'), ('cpp', 'g++'), ('ar', 'ar'),
                       ('strip', 'strip'), ('windres', 'windres')]:
        text += name + ' = ' + repr(['/usr/bin/arch', '-arm64',
                    str(cross_root / ('llvm-mingw/bin/arm64ec-w64-mingw32-' + leaf))]) + '\n'
    text += "pkg-config = '/usr/bin/false'\n\n[properties]\nneeds_exe_wrapper = true\n"
    text += '\n[built-in options]\n'
    for name in ['c_args', 'cpp_args', 'c_link_args', 'cpp_link_args']:
        text += name + " = ['-marm64x']\n"
    return (text + "\n[host_machine]\nsystem = 'windows'\ncpu_family = 'aarch64'\n"
            "cpu = 'aarch64'\nendian = 'little'\n").encode()


def version_adapter(commit):
    need(len(commit) == 40 and all(c in '0123456789abcdef' for c in commit),
         'artifact_version_pin')
    return ("#!/bin/sh\nset -eu\n"
            'test "$#" -eq 2 && test "$1" = describe && test "$2" = --always || exit 64\n'
            "printf '%s\\n' " + shlex.quote(commit) + '\n').encode()


def notice_bytes(inputs, prepared):
    rows = {}
    components = {row['id']: row for row in inputs['components']}
    cache = real_directory(prepared['source_cache'])
    for ident in NOTICE_COMPONENTS:
        component = components[ident]
        repository = cache.joinpath(*relative(component['cache_path']))
        for term in component['terms']:
            raw = git(repository, 'cat-file', 'blob', term['git_blob'])
            need(digest(raw) == term['sha256'] and len(raw) == term['size_bytes'],
                 'artifact_notice_changed')
            rows['notices/' + ident + '/' + term['path']] = (raw, 0o644)
    return rows


def generated_bytes(inputs, prepared, tools_root, tool_record, cap, roots):
    commit = next(c['commit'] for c in inputs['components'] if c['id'] == 'dxmt-upstream')
    rows = {
        'native.ini': (build_native.meson_native_file(tool_record), 0o644),
        'cross.ini': (cross_file(roots['cross_tools']), 0o644),
        'bin/xcrun': (build_native.xcrun_wrapper(cap['selected']), 0o755),
        'bin/git': (version_adapter(commit), 0o755),
    }
    rows.update(notice_bytes(inputs, prepared))
    return rows


def generated_facts(root, expected):
    result = []
    for name, (raw, mode) in sorted(expected.items()):
        actual = read_relative(root, name, 32 * 1024**2)
        fd = open_relative(root, name)
        try:
            actual_mode = stat.S_IMODE(os.fstat(fd).st_mode)
        finally:
            os.close(fd)
        need(actual == raw and actual_mode == mode, 'artifact_generated_input_changed')
        result.append({'path': name, 'sha256': digest(actual), 'size_bytes': len(actual), 'mode': mode})
    return result


def environment(root, tools_root, tool_record):
    env = build_native.native_environment(root, tools_root, tool_record)
    env['PATH'] = str(root / 'bin') + ':' + env['PATH']
    return env


def recipe(root, tools_root, tool_record, llvm_root, jobs):
    meson = ['/usr/bin/arch', '-arm64', tool_record['native_tools']['python']['path'],
             '-B', str(tools_root / 'meson-source/meson.py')]
    result = {
        'dxmt.configure': [*meson, 'setup', str(root / 'objects'), str(root / 'source'),
             '--native-file', str(root / 'native.ini'), '--cross-file', str(root / 'cross.ini'),
             '--prefix', str(root / 'install'), '--buildtype', 'release', '--backend', 'ninja',
             '--wrap-mode', 'nodownload', '-Dstrip=false', '-Dwine_builtin_dll=true',
             '-Dwine_install_path=' + str(root / 'wine-layout'),
             '-Dnative_llvm_path=' + str(llvm_root / 'install'),
             '-Dbuild_airconv_for_windows=false', '-Denable_tests=false',
             '-Denable_nvapi=false', '-Denable_nvngx=false', '-Denable_d3d12=false'],
        'dxmt.compile': [str(tools_root / 'ninja-source/ninja'), '-C', str(root / 'objects'),
                         '-j', str(jobs), *PE_TARGETS.values(), NATIVE_TARGET],
    }
    for name, target in PE_TARGETS.items():
        result['builtin.' + name] = ['/usr/bin/arch', '-arm64',
                str(root / 'wine-layout/bin/winebuild'), '--builtin', str(root / 'objects' / target)]
    result['dxmt.install'] = [*meson, 'install', '-C', str(root / 'objects'), '--no-rebuild', '--tags', 'runtime']
    return result


def prerequisite_values(prepared_root, native_root, tools_root, refs, roles_path, cross_root, repo=REPO):
    inputs, config, lock = input_values(refs, repo)
    prepared = verify_prepared(prepared_root, repo)
    native = build_native.verify_shader_build(native_root, repo)
    tool_record = tools.verify_tools(tools_root, repo)
    need(native['prepared_ref'] == reference(prepared_root, 'prepared.json')
         and native['tools_ref'] == reference(tools_root, 'prepared.json')
         and prepared['inputs_ref'] == refs['inputs'], 'artifact_prerequisites_mixed')
    _, roots, roles_ref = selector(roles_path, repo)
    need(roots['cross_tools'] == real_directory(cross_root), 'artifact_cross_role_mixed')
    facts, layout = role_layout(roots, inputs, lock)
    cap = load_json(Path(native['capabilities_ref']['path']) / 'capabilities.json')
    return inputs, prepared, native, tool_record, roots, roles_ref, facts, layout, cap


def construct(args, repo=REPO):
    refs = {name: {'path': str(getattr(args, name)),
                  'sha256': digest(read_relative(repo, str(getattr(args, name))))}
            for name in ['inputs', 'config', 'toolchain']}
    prepared_root, native_root, tools_root = [owned_directory(value, repo)
        for value in [args.prepared, args.native, args.tools]]
    inputs, prepared, native, tool_record, roots, role_ref, facts, layout, cap = prerequisite_values(
        prepared_root, native_root, tools_root, refs, args.wine_roles, args.cross_tools, repo)
    policy = build_native.storage_policy(args.jobs, args.max_growth_bytes, args.reserve_free_bytes)
    need(shutil.disk_usage(native_root).free >= policy['growth_ceiling_bytes'] + policy['reserve_free_bytes'],
         'artifact_start_space_below_ceiling_and_reserve')
    root = output_directory(args.output, repo)
    value = {'schema_version': 1, 'record_kind': 'dxmt_artifact_build', 'scope': 'dxmt_component',
             'refs': refs, 'prepared_ref': reference(prepared_root, 'prepared.json'),
             'native_ref': reference(native_root, 'build.json'), 'tools_ref': reference(tools_root, 'prepared.json'),
             'wine_roles_ref': role_ref, 'producers': producers(repo), 'policy': policy,
             'environment': environment(root, tools_root, tool_record), 'generated_inputs': [],
             'wine_layout': layout, 'role_facts': facts, 'source_files': [], 'commands': [],
             'artifacts_manifest': None, 'passed': False, 'dxmt_built': False,
             'pairing_verified': False, 'gpu_or_guest_execution_performed': False, 'runtime_eligible': False}
    phase = 'setup'
    try:
        (root / 'tmp').mkdir()
        build_native.copy_dxmt(prepared_root, root)
        value['source_files'] = tools.files(root / 'source')
        copy_layout(root, layout, roots)
        generated = generated_bytes(inputs, prepared, tools_root, tool_record, cap, roots)
        for name, (raw, mode) in generated.items():
            write_bytes(root, name, raw, mode)
        value['generated_inputs'] = generated_facts(root, generated)
        commands = recipe(root, tools_root, tool_record, Path(native['llvm_ref']['path']), policy['jobs'])
        for ident, argv in commands.items():
            phase = ident
            if ident == 'builtin.' + next(iter(PE_TARGETS)):
                for name, target in PE_TARGETS.items():
                    write_bytes(root, 'compiler/' + name, read_relative(root, 'objects/' + target, 64 * 1024**2))
            build_native.monitored_command(root, ident, argv, value['environment'], policy, value['commands'])
        phase = 'inspection'
        artifacts = inspector().inspect_outputs(root, value, repo=repo)
        write_new(root / 'artifacts.json', artifacts)
        value['artifacts_manifest'] = {'path': 'artifacts.json', 'sha256': sha256(root / 'artifacts.json')}
        value['passed'] = True
        value['dxmt_built'] = True
        write_new(root / 'build.json', value)
        return value
    except (Error, OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError) as error:
        value['passed'] = False
        value['dxmt_built'] = False
        value['phase'] = phase
        value['error'] = error.code if isinstance(error, Error) else 'artifact_build_failed'
        value['compilation_observation'] = ('observed' if any(row['id'] == 'dxmt.compile'
             and type(row.get('exit_code')) is int and row['exit_code'] == 0 for row in value['commands'])
             else 'attempted_unverified' if any(row['id'] == 'dxmt.compile' for row in value['commands'])
             else 'unperformed')
        write_new(root / 'failed.json', value)
        raise


def verify_build(root, repo=REPO):
    root = owned_directory(root, repo)
    need(not (root / 'failed.json').exists(), 'failed_artifact_build')
    value = load_json(root / 'build.json')
    fields(value, BUILD_FIELDS, 'dxmt_artifact_build')
    need(value['scope'] == 'dxmt_component' and value['passed'] is True and value['dxmt_built'] is True
         and all(value[name] is False for name in ['pairing_verified', 'gpu_or_guest_execution_performed',
                                                  'runtime_eligible']), 'artifact_build_scope')
    need(value['producers'] == producers(repo), 'artifact_producer_changed')
    paths = [owned_directory(value[name]['path'], repo)
             for name in ['prepared_ref', 'native_ref', 'tools_ref']]
    cross_root = real_directory(load_json(value['wine_roles_ref']['path'])['cross_tools'])
    inputs, prepared, native, tool_record, roots, role_ref, facts, layout, cap = prerequisite_values(
        *paths, value['refs'], value['wine_roles_ref']['path'], cross_root, repo)
    for key, directory, receipt in zip(['prepared_ref', 'native_ref', 'tools_ref'], paths,
                                     ['prepared.json', 'build.json', 'prepared.json']):
        need(value[key] == reference(directory, receipt), 'artifact_reference_changed')
    need(value['wine_roles_ref'] == role_ref and value['role_facts'] == facts, 'artifact_role_changed')
    check_layout(root, value['wine_layout'], layout)
    need(value['source_files'] == tools.files(root / 'source')
         == tools.files(paths[0] / 'source/dxmt'), 'artifact_source_changed')
    generated = generated_bytes(inputs, prepared, paths[2], tool_record, cap, roots)
    need(value['generated_inputs'] == generated_facts(root, generated), 'artifact_generated_facts_changed')
    policy = value['policy']
    need(policy == build_native.storage_policy(policy['jobs'], policy['growth_ceiling_bytes'],
                                              policy['reserve_free_bytes']), 'artifact_policy_changed')
    env = environment(root, paths[2], tool_record)
    need(value['environment'] == env, 'artifact_environment_changed')
    commands = recipe(root, paths[2], tool_record, Path(native['llvm_ref']['path']), policy['jobs'])
    build_native.verify_native_commands(root, value['commands'], commands, env, policy)
    ref = value['artifacts_manifest']; fields(ref, ['path', 'sha256'])
    need(ref['path'] == 'artifacts.json' and sha256(root / ref['path']) == ref['sha256'],
         'artifact_inventory_changed')
    actual = inspector().inspect_outputs(root, value, repo=repo)
    need(load_json(root / ref['path']) == actual, 'artifact_output_changed')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['inputs', 'config', 'toolchain', 'prepared', 'native', 'tools', 'cross-tools', 'wine-roles', 'output']:
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--jobs', required=True, type=int)
    parser.add_argument('--max-growth-bytes', required=True, type=int)
    parser.add_argument('--reserve-free-bytes', required=True, type=int)
    parser.add_argument('--require-empty', required=True, action='store_true')
    try:
        construct(parser.parse_args())
        print(encoded({'dxmt_built': True, 'pairing_verified': False, 'runtime_eligible': False,
                       'gpu_or_guest_execution_performed': False}).decode(), end='')
        return 0
    except (Error, OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError) as error:
        print(encoded({'dxmt_built': False, 'runtime_eligible': False,
                       'error': error.code if isinstance(error, Error) else 'artifact_build_failed'}).decode(), end='')
        return 1


if __name__ == '__main__':
    sys.exit(main())
