# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct the selected FEX development module from explicit inputs.

The three current source units are compiled again. Retained lower-layer inputs
are deliberately not described as a clean rebuild of the entire FEX tree.
Private bindings and all build receipts remain outside source repositories.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import sys

from .. import build
from ..build import Context, fact, load, relative
from ..errors import Error, need


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive_members(path):
    """Return ordered logical members, excluding only archive metadata members."""
    raw = Path(path).read_bytes()
    need(raw.startswith(b'!<arch>\n'), 'fex_archive_format')
    cursor, names, result = 8, b'', []
    while cursor < len(raw):
        need(cursor + 60 <= len(raw), 'fex_archive_truncated')
        header = raw[cursor:cursor + 60]
        need(header[58:] == b'`\n', 'fex_archive_header')
        try:
            length = int(header[48:58].decode('ascii').strip())
            name = header[:16].decode('ascii').strip()
        except (ValueError, UnicodeDecodeError):
            raise Error('fex_archive_header') from None
        begin, end = cursor + 60, cursor + 60 + length
        need(length >= 0 and end <= len(raw), 'fex_archive_truncated')
        data = raw[begin:end]
        cursor = end + (length % 2)
        need(cursor <= len(raw), 'fex_archive_padding')
        if name == '//':
            names = data
            continue
        if name in ('/', '/SYM64/', '/<ECSYMBOLS>/'):
            continue
        if name.startswith('#1/'):
            try:
                count = int(name[3:])
                need(0 < count <= len(data), 'fex_archive_name')
                name = data[:count].rstrip(b'\0').decode('utf-8')
                data = data[count:]
            except (ValueError, UnicodeDecodeError):
                raise Error('fex_archive_name') from None
        elif name.startswith('/'):
            try:
                start = int(name[1:])
                need(0 <= start < len(names), 'fex_archive_name')
                # COFF uses NUL-terminated names; GNU uses slash-newline.
                endings = [at for at in (names.find(b'/\n', start), names.find(b'\0', start)) if at >= 0]
                need(endings, 'fex_archive_name')
                stop = min(endings)
                name = names[start:stop].decode('utf-8')
            except (ValueError, UnicodeDecodeError):
                raise Error('fex_archive_name') from None
        else:
            name = name.removesuffix('/')
        if name.startswith('__.SYMDEF'):
            continue
        need(name and '/' not in name and '\\' not in name, 'fex_archive_member_name')
        result.append(dict(name=name, sha256=sha(data), size_bytes=len(data)))
    need(result and len({row['name'] for row in result}) == len(result), 'fex_archive_members')
    return result


def verify_archive(before, after, member, replacement):
    need([row['name'] for row in before] == [row['name'] for row in after],
         'fex_archive_member_order')
    need(sum(row['name'] == member for row in before) == 1, 'fex_archive_replacement_missing')
    unchanged = []
    for old, new in zip(before, after):
        if old['name'] == member:
            need(all(new[k] == replacement[k] for k in ('sha256', 'size_bytes')),
                 'fex_archive_replacement_mismatch')
        else:
            need(old == new, 'fex_archive_unexpected_member_change')
            unchanged.append(old)
    return dict(replaced_member=member, unchanged_members=unchanged,
                replacement=dict(sha256=replacement['sha256'], size_bytes=replacement['size_bytes']))


def coff_machine(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(20)
    need(len(raw) == 20, 'fex_coff_truncated')
    machine = struct.unpack_from('<H', raw)[0]
    need(machine == 0xa641, 'fex_coff_machine')
    return machine


def pe_info(path):
    """Check PE32+ plus mapped CHPE metadata; outer AMD64 alone is insufficient."""
    path = Path(path)
    raw = path.read_bytes()
    need(len(raw) >= 64 and raw[:2] == b'MZ', 'fex_pe_dos')
    pe = struct.unpack_from('<I', raw, 60)[0]
    need(pe >= 64 and pe + 24 <= len(raw) and raw[pe:pe + 4] == b'PE\0\0', 'fex_pe_signature')
    machine, count = struct.unpack_from('<HH', raw, pe + 4)
    symbol_pointer, symbol_count = struct.unpack_from('<II', raw, pe + 12)
    optional_size, characteristics = struct.unpack_from('<HH', raw, pe + 20)
    need(machine == 0x8664 and characteristics & 0x2000, 'fex_pe_machine_or_dll')
    optional = pe + 24
    table = optional + optional_size
    need(optional_size >= 208 and table + count * 40 <= len(raw), 'fex_pe_optional_bounds')
    need(struct.unpack_from('<H', raw, optional)[0] == 0x20b, 'fex_pe_optional_magic')
    need(struct.unpack_from('<I', raw, optional + 108)[0] > 10, 'fex_pe_load_config_missing')
    entry = struct.unpack_from('<I', raw, optional + 16)[0]
    image_base = struct.unpack_from('<Q', raw, optional + 24)[0]
    sections = []
    for index in range(count):
        at = table + index * 40
        try:
            name = raw[at:at + 8].rstrip(b'\0').decode('ascii')
        except UnicodeDecodeError:
            raise Error('fex_pe_section_name') from None
        header_name = name
        if name.startswith('/'):
            need(name[1:].isdigit() and symbol_pointer > 0, 'fex_pe_long_section_name')
            strings = symbol_pointer + symbol_count * 18
            need(strings + 4 <= len(raw), 'fex_pe_string_table')
            string_size = struct.unpack_from('<I', raw, strings)[0]
            offset = int(name[1:])
            need(4 <= offset < string_size and strings + string_size <= len(raw), 'fex_pe_string_table')
            end = raw.find(b'\0', strings + offset, strings + string_size)
            need(end >= 0, 'fex_pe_long_section_name')
            try:
                name = raw[strings + offset:end].decode('ascii')
            except UnicodeDecodeError:
                raise Error('fex_pe_long_section_name') from None
        virtual_size, rva, size, offset = struct.unpack_from('<IIII', raw, at + 8)
        flags = struct.unpack_from('<I', raw, at + 36)[0]
        need(offset + size <= len(raw), 'fex_pe_section_bounds')
        payload = raw[offset:offset + size]
        initialized = payload[:min(virtual_size, size)]
        padding = payload[len(initialized):]
        sections.append(dict(name=name, header_name=header_name, virtual_size=virtual_size, rva=rva, raw_size=size,
                             raw_offset=offset, characteristics=flags,
                             sha256=sha(payload), initialized_size=len(initialized),
                             initialized_sha256=sha(initialized), padding_bytes=len(padding),
                             padding_sha256=sha(padding), padding_values=sorted(set(padding))))
    need(count > 0 and len({s['name'] for s in sections}) == count, 'fex_pe_sections')
    need(any(s['rva'] <= entry < s['rva'] + s['virtual_size'] and s['characteristics'] & 0x20000000
             for s in sections), 'fex_pe_entrypoint')

    def map_rva(rva, size):
        matches = [s for s in sections if s['rva'] <= rva and rva + size <= s['rva'] + s['raw_size']]
        need(len(matches) == 1, 'fex_pe_rva_bounds')
        return matches[0]['raw_offset'] + rva - matches[0]['rva']

    load_rva, load_size = struct.unpack_from('<II', raw, optional + 112 + 10 * 8)
    need(load_rva and load_size >= 208, 'fex_pe_load_config_missing')
    at = map_rva(load_rva, 208)
    declared_size = struct.unpack_from('<I', raw, at)[0]
    need(declared_size >= 208, 'fex_pe_load_config_size')
    chpe = struct.unpack_from('<Q', raw, at + 200)[0]
    need(chpe >= image_base and chpe != 0, 'fex_pe_chpe_missing')
    chpe_at = map_rva(chpe - image_base, 4)
    version = struct.unpack_from('<I', raw, chpe_at)[0]
    need(version > 0, 'fex_pe_chpe_version')
    return dict(machine=machine, entrypoint_rva=entry, image_base=image_base,
                chpe_metadata_pointer=chpe, chpe_metadata_version=version,
                sections=sections, **fact(path))


def compare_pe(current, baseline):
    old = {row['name']: row for row in baseline['sections']}
    new = {row['name']: row for row in current['sections']}
    rows = []
    for name in sorted(old.keys() | new.keys()):
        left, right = old.get(name), new.get(name)
        fields = ('sha256', 'raw_size', 'virtual_size', 'rva')
        equal = left is not None and right is not None and all(left[k] == right[k] for k in fields)
        rows.append(dict(name=name, equal=equal,
                         baseline={k: left[k] for k in fields} if left else None,
                         rebuilt={k: right[k] for k in fields} if right else None))
    return dict(byte_identical=current['sha256'] == baseline['sha256'],
                entrypoint_equal=current['entrypoint_rva'] == baseline['entrypoint_rva'],
                sections=rows, review='identical' if all(row['equal'] for row in rows)
                else 'changed_sections_require_review; no automatic debug-path explanation')


def compare_stripped_text(before, after):
    """Keep executable bytes fixed; report strip's separate raw tail padding."""
    left = next(row for row in before['sections'] if row['name'] == '.text')
    right = next(row for row in after['sections'] if row['name'] == '.text')
    need(all(row['initialized_size'] == row['virtual_size'] for row in (left, right)),
         'fex_strip_text_bounds')
    required = ('virtual_size', 'rva', 'characteristics', 'initialized_sha256')
    need(all(left[key] == right[key] for key in required), 'fex_strip_changed_text')
    fields = (*required, 'raw_size', 'sha256', 'padding_bytes', 'padding_sha256', 'padding_values')
    return dict(virtual_code_unchanged=True, raw_section_equal=left['sha256'] == right['sha256'],
                before={key: left[key] for key in fields}, after={key: right[key] for key in fields})


def bind_token(ctx, token):
    if isinstance(token, str):
        need(not token.startswith('/') and '\x00' not in token and '-ivfsoverlay' not in token,
             'fex_unbound_argument')
        return token
    need(type(token) is dict and set(token) == {'root', 'path', 'prefix'}, 'fex_argument_shape')
    root, rel, prefix = token['root'], str(relative(token['path'])), token['prefix']
    need(prefix in ('', '-I', '-Wl,-Xlink=/map:', '-Wl,--out-implib,'), 'fex_argument_prefix')
    if root == 'output':
        path = ctx.path(rel)
        if prefix == '-I':
            need(rel.startswith('empty-search/') or rel == 'exports/wire', 'fex_output_include')
            if rel.startswith('empty-search/'):
                path.mkdir(parents=True, exist_ok=True)
            else:
                need(path.is_dir(), 'fex_wire_export_missing')
        elif path.exists():
            ctx._admit_path(path)
    else:
        path = ctx.root(root) / rel
        need(path.resolve(strict=True).is_relative_to(ctx.root(root)), 'fex_argument_escape')
        if prefix == '-I':
            need(path.is_dir(), 'fex_include_missing')
        else:
            ctx._admit_path(path)
    return prefix + str(path)


def private_recipe(recipe, bindings, manifest):
    """Inject the sole private identity from local data, never a Git manifest."""
    recipe = copy.deepcopy(recipe)
    data = load(manifest)
    bound = bindings.get('roots', bindings)
    root = bound['private']
    root = root['path'] if isinstance(root, dict) else root
    root = Path(root)
    need(data.get('schema_version') == 1 and data.get('root') == str(root), 'fex_private_binding')
    need(root.is_absolute() and root.resolve(strict=True) == root, 'fex_private_root')
    need(not any((parent / '.git').exists() for parent in [root, *root.parents]),
         'fex_private_inside_repository')
    rows = data.get('files')
    need(type(rows) is list and len(rows) == 1 and rows[0].get('path') == 'PearPhaseSelection.h',
         'fex_private_manifest')
    need(not any(row['root'] == 'private' for row in recipe['inputs']), 'fex_public_private_identity')
    row = rows[0]
    need(type(row.get('size_bytes')) is int and row['size_bytes'] > 0, 'fex_private_manifest')
    recipe['inputs'].append(dict(root='private', path=row['path'], sha256=row['sha256'],
                                 size_bytes=row['size_bytes']))
    return recipe


def link_trace(ctx, command, recipe):
    """Admit every traced file; require all declared implicit libraries to appear."""
    expected = {str(ctx.input('llvm_mingw', row['path']).resolve()): row
                for row in recipe['toolchain']['implicit_libraries']}
    allowed = {str(ctx.input('inputs', row['path']).resolve()) for row in recipe['inputs']
               if row['root'] == 'inputs' and row['path'].startswith('link/')}
    allowed.update(str(ctx.path(rel).resolve()) for rel in ('core.obj', 'module.obj', 'libCommonWindows.a'))
    allowed.update(expected)
    observed, seen = [], set()
    for channel in ('stdout', 'stderr'):
        text = Path(command['logs'][channel]['path']).read_text(errors='strict')
        for line in text.splitlines():
            candidate = line.strip()
            for prefix in ('lld-link: Reading ', 'ld.lld: Reading ', 'Reading '):
                if candidate.startswith(prefix):
                    candidate = candidate[len(prefix):]
                    break
            if not candidate.startswith('/'):
                continue
            # GNU/COFF traces append a logical archive member in parentheses.
            if '.a(' in candidate:
                candidate = candidate.split('.a(', 1)[0] + '.a'
            path = Path(candidate)
            need(path.is_file(), 'fex_link_trace_path')
            resolved = str(path.resolve(strict=True))
            need(resolved in allowed, 'fex_link_trace_unexpected_input')
            reference = ctx._admit_path(path)
            if resolved not in seen:
                observed.append(reference)
                seen.add(resolved)
    need(set(expected) <= seen, 'fex_link_trace_missing_implicit_library')
    return dict(inputs=observed, implicit_libraries=[dict(link_argument=expected[path]['link_argument'],
                actual=next(row for row in observed if str(Path(row['path']).resolve()) == path))
                for path in sorted(expected)])


def builder_sources():
    return [fact(Path(__file__).resolve()), fact(Path(build.__file__).resolve()),
            fact(Path(sys.modules[Error.__module__].__file__).resolve())]


def canonical_input_path(value):
    path = Path(value)
    need('..' not in path.parts, 'fex_input_path')
    if not path.is_absolute():
        path = Path.cwd() / path
    need(path.resolve(strict=True) == path and path.is_file(), 'fex_input_alias')
    return path


def reconstruct(recipe_path, bindings_path, private_manifest, output, *, lock_path=None):
    recipe_path = canonical_input_path(recipe_path)
    bindings_path = canonical_input_path(bindings_path)
    private_manifest = canonical_input_path(private_manifest)
    recipe = load(recipe_path)
    bindings = load(bindings_path)
    need([row['id'] for row in recipe['commands']] == ['module', 'core', 'memory', 'debug', 'strip'],
         'fex_command_sequence')
    need({row['id'] for row in recipe['compile_units']} == {'module', 'core', 'memory'}, 'fex_compile_units')
    public_recipe = fact(recipe_path)
    local_bindings = fact(bindings_path)
    producer_before = builder_sources()
    local_private = fact(private_manifest)
    expanded = private_recipe(recipe, bindings, private_manifest)
    context_args = {'lock_path': lock_path} if lock_path is not None else {}
    with Context(expanded, bindings, output, **context_args) as ctx:
        extra = dict(public_recipe=public_recipe, bindings_manifest=local_bindings, private_manifest=local_private,
                     builder_sources={'before': producer_before},
                     host=dict(platform=platform.platform(), machine=platform.machine(),
                               mac_version=platform.mac_ver()[0], python=sys.version,
                               interpreter=fact(Path(sys.executable).resolve())),
                     historical_environment=recipe['historical']['environment'])
        comparisons = {}
        try:
            # Preserve producers before any child command, even if a later
            # receipt serialization fails. These are owned local evidence.
            for reference in producer_before:
                rel = 'provenance/builder-sources/' + Path(reference['path']).name
                with Path(reference['path']).open('rb') as src, ctx.path(rel).open('xb') as dst:
                    shutil.copyfileobj(src, dst, 1024**2)
                need(ctx.record_output(rel)['sha256'] == reference['sha256'], 'fex_builder_changed')
            for source, rel in ((recipe_path, 'provenance/recipe-public.json'),
                                (bindings_path, 'provenance/local-bindings.json'),
                                (private_manifest, 'provenance/private-input-manifest.json')):
                with Path(source).open('rb') as src, ctx.path(rel).open('xb') as dst:
                    shutil.copyfileobj(src, dst, 1024**2)
                ctx.record_output(rel)
            build.write_json(ctx.path('provenance/builder-sources.json'), producer_before)
            ctx.record_output('provenance/builder-sources.json')
            for row in recipe['compile_units']:
                ctx.input('fex', row['path'], row['sha256'])
            for row in recipe['shared_headers']:
                name = {'pear-runtime': 'runtime', 'pear-wine': 'wine'}[row['owner']]
                ctx.input(name, row['path'], row['sha256'])
            for row in recipe['source_exports']:
                ctx.input(row['root'], row['path'], row['sha256'])
                ctx.copy_input(row['root'], row['path'], row['output'])
            compile_arguments = {command['id']: [bind_token(ctx, value) for value in command['argv']]
                                 for command in recipe['commands'][:3]}
            env = dict(PATH=os.pathsep.join(str(ctx.root(k) / 'bin') if k == 'llvm_mingw'
                                           else str(ctx.root(k)) for k in ('llvm_mingw', 'apple_tools', 'system_bin')),
                       LANG='C', LC_ALL='C', CCACHE='', TMPDIR=str(ctx.output / 'tmp'))
            compiler = [str(ctx.input('apple_tools', 'arch')), '-arm64',
                        str(ctx.input('llvm_mingw', 'bin/arm64ec-w64-mingw32-clang++'))]
            resource = ctx.run('compiler-resource', compiler + ['-print-resource-dir'], env=env, timeout=60)
            resource_path = Path(Path(resource['logs']['stdout']['path']).read_text().strip()).resolve(strict=True)
            need(resource_path == (ctx.root('llvm_mingw') / recipe['toolchain']['resource_directory']).resolve(strict=True),
                 'fex_compiler_resource_directory')
            extra['compiler_resource_directory'] = str(resource_path)
            units = {row['id']: row for row in recipe['compile_units']}
            for command in recipe['commands'][:3]:
                ctx.run(command['id'], compile_arguments[command['id']], env=env)
                unit = units[command['id']]
                ctx.record_output(unit['object'])
                ctx.record_output(unit['depfile'])
                coff_machine(ctx.path(unit['object']))
                ctx.audit_depfile(ctx.path(unit['depfile']), cwd=ctx.output)
            archive = recipe['archive']
            original = ctx.input('inputs', archive['template'])
            before = archive_members(original)
            destination = ctx.copy_input('inputs', archive['template'], archive['output'])
            destination.chmod(0o644)
            ctx.run('archive-replace', [str(ctx.input('apple_tools', 'arch')), '-arm64',
                    str(ctx.input('llvm_mingw', 'bin/llvm-ar')), 'r', str(destination),
                    str(ctx.path(units['memory']['object']))], env=env)
            ctx.record_output(archive['output'])
            comparisons['archive'] = verify_archive(before, archive_members(destination),
                archive['replace_member'], ctx.outputs[units['memory']['object']])
            command = recipe['commands'][3]
            link = ctx.run('debug', [bind_token(ctx, value) for value in command['argv']], env=env)
            for rel in ('debug.dll', 'debug.map', 'debug.dll.a'):
                ctx.record_output(rel)
            extra['link_trace'] = link_trace(ctx, link, recipe)
            marker = recipe['builtin_marker']
            need(marker['offset'] == 64 and marker['count'] == 32, 'fex_builtin_contract')
            source = ctx.input(marker['root'], marker['path'], marker['sha256'])
            marker_bytes = source.read_bytes()[:marker['count']]
            debug = ctx.path('debug.dll')
            need(len(marker_bytes) == marker['count'] and debug.stat().st_size >= 96, 'fex_builtin_bounds')
            with debug.open('r+b') as stream:
                stream.seek(marker['offset'])
                stream.write(marker_bytes)
            ctx.record_output('debug.dll')
            debug_info = pe_info(debug)
            deployment = ctx.path('deployment.dll')
            with debug.open('rb') as src, deployment.open('xb') as dst:
                shutil.copyfileobj(src, dst, 1024**2)
            ctx.record_output('deployment.dll')
            command = recipe['commands'][4]
            ctx.run('strip', [bind_token(ctx, value) for value in command['argv']], env=env)
            ctx.record_output('deployment.dll')
            deployment_info = pe_info(deployment)
            comparisons['strip'] = compare_stripped_text(debug_info, deployment_info)
            comparisons.update(debug=compare_pe(debug_info, recipe['baseline']['debug']),
                               deployment=compare_pe(deployment_info, recipe['baseline']['deployment']),
                               strip_text_unchanged=True)
            extra.update(artifacts=dict(fex_pe=ctx.outputs['deployment.dll'], fex_debug=ctx.outputs['debug.dll']),
                         pe=dict(debug=debug_info, deployment=deployment_info))
            extra['builder_sources']['after'] = builder_sources()
            need(extra['builder_sources']['before'] == extra['builder_sources']['after'], 'fex_builder_changed')
            need(fact(recipe_path) == public_recipe and fact(private_manifest) == local_private
                 and fact(bindings_path) == local_bindings,
                 'fex_recipe_changed')
            return ctx.finish('passed', comparisons=comparisons, extra=extra)
        except BaseException as exc:
            extra['failure'] = getattr(exc, 'code', type(exc).__name__)
            extra['builder_sources']['after'] = builder_sources()
            ctx.finish('failed', comparisons=comparisons, extra=extra)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--bindings', type=Path, required=True)
    parser.add_argument('--private-manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = reconstruct(args.recipe, args.bindings, args.private_manifest, args.output)
    except Error as exc:
        print(json.dumps({'status': 'failed', 'error': exc.code}), file=sys.stderr)
        return 1
    print(json.dumps({'status': result['status'], 'output': str(args.output),
                      'runtime_eligible': False, 'game_qualified': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
