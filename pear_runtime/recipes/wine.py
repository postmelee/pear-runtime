# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconstruct selected Wine units from explicit forks and immutable inputs.

The recipe preserves the recorded D27 and string-build3 operations. The original
MIT producers, hashes and path-only adaptations are identified in recipe data.
This creates build evidence; it neither signs nor executes a runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct

from pear_runtime.build import Context, fact, load
from pear_runtime.errors import Error, need

PLACEHOLDER = re.compile(r'\{([a-z][a-z0-9_]*)\}')


def expand(value, context):
    """Resolve only named admitted roots, never an environment or old fallback."""
    need(type(value) is str and '\x00' not in value, 'recipe_string')
    result = PLACEHOLDER.sub(lambda m: str(context.output if m[1] == 'output'
                                          else context.root(m[1])), value)
    need('{' not in result and '}' not in result, 'recipe_placeholder')
    return result


def command(context, record, *, ident=None, replacements=None):
    replacements = replacements or {}
    argv = [expand(replacements.get(value, value), context) for value in record['argv']]
    env = {key: expand(value, context) for key, value in record['env'].items()}
    cwd = Path(expand(record['cwd'], context))
    need(cwd.is_relative_to(context.output), 'recipe_cwd')
    cwd.mkdir(parents=True, exist_ok=True)
    return context.run(ident or record['id'], argv, cwd=cwd, env=env, timeout=600)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def take(data, offset, size):
    need(type(offset) is int and type(size) is int and 0 <= offset <= len(data)
         and 0 <= size <= len(data) - offset, 'recipe_binary_bounds')
    return data[offset:offset + size]


def number(data, fmt, offset):
    return struct.unpack('<' + fmt, take(data, offset, struct.calcsize('<' + fmt)))[0]


def macho_sections(data):
    """Inspect thin native Mach-O sections without loading the library."""
    need(take(data, 0, 4) == b'\xcf\xfa\xed\xfe', 'recipe_macho_magic')
    cpu = number(data, 'I', 4)
    need(cpu == 0x0100000c, 'recipe_macho_architecture')
    count, command_bytes = number(data, 'I', 16), number(data, 'I', 20)
    need(0 < count <= 4096 and 32 + command_bytes <= len(data), 'recipe_macho_commands')
    at, sections, uuids = 32, {}, []
    for _ in range(count):
        kind, size = number(data, 'I', at), number(data, 'I', at + 4)
        need(size >= 8 and at + size <= 32 + command_bytes, 'recipe_macho_command')
        if kind == 0x1b:
            need(size == 24, 'recipe_macho_uuid')
            uuids.append(take(data, at + 8, 16).hex())
        if kind == 0x19:
            nsects = number(data, 'I', at + 64)
            need(size >= 72 + nsects * 80, 'recipe_macho_sections')
            for index in range(nsects):
                section = at + 72 + index * 80
                name = take(data, section, 16).split(b'\0', 1)[0].decode('ascii')
                segment = take(data, section + 16, 16).split(b'\0', 1)[0].decode('ascii')
                length = number(data, 'Q', section + 40)
                offset = number(data, 'I', section + 48)
                flags = number(data, 'I', section + 64)
                key = segment + ',' + name
                need(key not in sections, 'recipe_macho_duplicate_section')
                zero_fill = flags & 0xff in (1, 12, 18)
                sections[key] = {'size_bytes': length, 'zero_fill': zero_fill,
                                 'sha256': None if zero_fill else sha(take(data, offset, length))}
        at += size
    need(at == 32 + command_bytes and '__TEXT,__text' in sections, 'recipe_macho_text')
    return {'cpu_type': cpu, 'cpu_subtype': number(data, 'I', 8),
            'sections': sections, 'uuids': uuids, 'sha256': sha(data)}


def compare_macho(reference, candidate):
    old, new = macho_sections(Path(reference).read_bytes()), macho_sections(Path(candidate).read_bytes())
    changed = sorted(key for key in old['sections'].keys() | new['sections'].keys()
                     if old['sections'].get(key) != new['sections'].get(key))
    equal = old['sections']['__TEXT,__text'] == new['sections']['__TEXT,__text']
    return {'architecture': 'arm64', 'text_equal': equal, 'whole_file_equal': old['sha256'] == new['sha256'],
            'changed_sections': changed, 'reference': old, 'candidate': new,
            'claim': 'Static native section comparison; no process or library execution.'}


class PE:
    """Bounded PE32+ inspection for timestamp and ARM64X correspondence.

    Reuses the field semantics of Pear tools/wine/modules.py and the original
    string builder. Whole normalized payload equality remains the final gate.
    """
    def __init__(self, data):
        need(type(data) is bytes and 64 <= len(data) <= 64 * 1024**2, 'recipe_pe_size')
        self.data = data
        need(data[:2] == b'MZ', 'recipe_pe_dos')
        self.pe = number(data, 'I', 60)
        need(take(data, self.pe, 4) == b'PE\0\0', 'recipe_pe_signature')
        self.machine = number(data, 'H', self.pe + 4)
        count, size = number(data, 'H', self.pe + 6), number(data, 'H', self.pe + 20)
        self.opt = self.pe + 24
        need(number(data, 'H', self.opt) == 0x20b and size >= 240 and 1 <= count <= 96,
             'recipe_pe_optional')
        self.base = number(data, 'Q', self.opt + 24)
        self.headers = number(data, 'I', self.opt + 60)
        need(self.opt + size + count * 40 <= self.headers <= len(data), 'recipe_pe_headers')
        need(number(data, 'I', self.opt + 108) == 16, 'recipe_pe_directories')
        self.dirs = [struct.unpack('<II', take(data, self.opt + 112 + i * 8, 8)) for i in range(16)]
        self.sections = []
        for i in range(count):
            at = self.opt + size + 40 * i
            name = take(data, at, 8).rstrip(b'\0').decode('ascii')
            virtual, rva, raw_size, raw = struct.unpack('<IIII', take(data, at + 8, 16))
            take(data, raw, raw_size)
            self.sections.append({'name': name, 'rva': rva, 'virtual_size': virtual,
                                  'raw_size': raw_size, 'raw_offset': raw,
                                  'characteristics': number(data, 'I', at + 36)})

    def offset(self, rva, size):
        need(type(rva) is int and rva >= 0 and size >= 0, 'recipe_pe_rva')
        hits = [rva] if rva + size <= self.headers else []
        for entry in self.sections:
            delta = rva - entry['rva']
            if 0 <= delta and delta + size <= min(entry['raw_size'], entry['virtual_size']):
                hits.append(entry['raw_offset'] + delta)
        need(len(hits) == 1, 'recipe_pe_rva_mapping')
        return hits[0]

    def hybrid(self):
        need(self.machine == 0xaa64, 'recipe_pe_native_machine')
        rva, length = self.dirs[10]
        start = self.offset(rva, length)
        size = min(length, number(self.data, 'I', start))
        need(size >= 0xe8, 'recipe_pe_load_config')
        pointer = number(self.data, 'Q', start + 0xc8)
        metadata = self.offset(pointer - self.base, 12)
        version, codemap, count = struct.unpack('<III', take(self.data, metadata, 12))
        need(version in (1, 2) and 0 < count <= 65536, 'recipe_pe_chpe')
        code = self.offset(codemap, count * 8)
        kinds = set()
        for index in range(count):
            encoded, span = struct.unpack('<II', take(self.data, code + index * 8, 8))
            need(encoded & 3 <= 2 and span > 0, 'recipe_pe_code_map')
            kinds.add(encoded & 3)
        need({0, 1} <= kinds, 'recipe_pe_hybrid_code_ranges')
        relative, section = struct.unpack('<IH', take(self.data, start + 0xe0, 6))
        need(1 <= section <= len(self.sections), 'recipe_pe_dynamic_section')
        table_rva = self.sections[section - 1]['rva'] + relative
        table = self.offset(table_rva, 8)
        dynamic_version, dynamic_size = struct.unpack('<II', take(self.data, table, 8))
        need(dynamic_version == 1 and 12 <= dynamic_size <= 4 * 1024**2, 'recipe_pe_dynamic_table')
        self.offset(table_rva, dynamic_size + 8)
        at, end, fixups = table + 8, table + 8 + dynamic_size, []
        while at < end:
            need(at + 12 <= end, 'recipe_pe_dynamic_record')
            symbol, span = struct.unpack('<QI', take(self.data, at, 12))
            at += 12
            stop = at + span
            need(stop <= end, 'recipe_pe_dynamic_record')
            if symbol == 6:
                while at < stop:
                    page, block = struct.unpack('<II', take(self.data, at, 8))
                    block_end = at + block
                    need(block >= 8 and block % 2 == 0 and block_end <= stop, 'recipe_pe_dynamic_block')
                    at += 8
                    while at < block_end:
                        value = number(self.data, 'H', at)
                        at += 2
                        if not value:
                            need(not any(take(self.data, at, block_end - at)), 'recipe_pe_dynamic_padding')
                            break
                        kind, arg = (value >> 12) & 3, value >> 14
                        need(kind <= 2, 'recipe_pe_dynamic_kind')
                        payload = (1 << arg) if kind == 1 else (2 if kind == 2 else 0)
                        need(at + payload <= block_end, 'recipe_pe_dynamic_payload')
                        if kind == 1 and page + (value & 0xfff) == self.pe + 4:
                            need(payload == 2, 'recipe_pe_machine_fixup')
                            fixups.append(number(self.data, 'H', at))
                        at += payload
                    at = block_end
            at = stop
        need(fixups == [0x8664], 'recipe_pe_arm64x_fixup')
        return {'native_machine': self.machine, 'chpe_version': version, 'chpe_pointer': hex(pointer),
                'code_range_count': count, 'code_types': sorted(kinds),
                'dynamic_relocation_version': dynamic_version, 'machine_fixups': fixups}


def normalize_coff(data, original):
    need(len(data) >= 20 and len(original) >= 20 and data[:2] == original[:2]
         and data[:2] in (b'\x64\xaa', b'\x41\xa6'), 'recipe_coff_machine')
    need(data[:4] + data[8:] == original[:4] + original[8:], 'recipe_coff_code_changed')
    return data[:4] + original[4:8] + data[8:], {'before': data[4:8].hex(), 'normalized': original[4:8].hex()}


def normalize_pe(data, original):
    new, old = PE(data), PE(original)
    stamp = take(original, old.pe + 8, 4)
    offsets = [new.pe + 8]
    rva, size = new.dirs[6]
    need(size % 28 == 0, 'recipe_pe_debug_directory')
    offsets += [new.offset(rva + index, 28) + 4 for index in range(0, size, 28)]
    result = bytearray(data)
    changes = []
    for offset in offsets:
        changes.append({'offset': offset, 'before': take(data, offset, 4).hex(), 'normalized': stamp.hex()})
        result[offset:offset + 4] = stamp
    return bytes(result), changes


def copy_result(context, source, relative):
    destination = context.path(relative)
    need(not destination.exists(), 'recipe_copy_exists')
    shutil.copy2(source, destination)
    return context.record_output(relative)


def audit_link_map(context, path):
    """Require every Object files entry to be understood and admitted."""
    checked, indices = [], set()
    in_objects = found_objects = False
    for line in Path(path).read_text().splitlines():
        if line.strip() == '# Object files:':
            need(not found_objects, 'recipe_link_map_duplicate_table')
            in_objects = found_objects = True
            continue
        if not in_objects:
            continue
        if line.startswith('#'):
            in_objects = False
            continue
        if not line.strip():
            continue
        match = re.fullmatch(r'\[\s*(\d+)\]\s+(.+)', line)
        need(match is not None, 'recipe_link_map_unknown_entry')
        index, value = int(match[1]), match[2]
        need(index not in indices, 'recipe_link_map_duplicate_index')
        indices.add(index)
        if value == 'linker synthesized':
            need(index == 0, 'recipe_link_map_sentinel')
            continue
        archive = re.fullmatch(r'(.+\.a)(?:\[\d+\])?\(([^()]+)\)', value)
        if archive:
            value = archive[1]
        else:
            need('(' not in value and ')' not in value
                 and Path(value).suffix in ('.o', '.obj', '.a', '.dylib', '.so', '.tbd'),
                 'recipe_link_map_unknown_entry')
        source = Path(value)
        if not source.is_absolute():
            source = path.parent / source
        need(source.is_file(), 'recipe_link_map_missing_input')
        checked.append(context._admit_path(source))
    need(found_objects and checked, 'recipe_link_map_empty')
    return {'map': fact(path), 'inputs': checked}


def audit_pe_trace(context, record, argv):
    """Admit all COFF linker reads and the verbose child tools they came from."""
    cwd = Path(record['cwd'])
    expected = {str(Path(value).resolve()) for value in argv
                if Path(value).suffix in ('.o', '.obj', '.a') and Path(value).is_file()}
    observed, tools, reads = {}, {}, []
    for directory in cwd.glob('tmp*'):
        need(re.fullmatch(r'tmp[0-9a-f]{8}', directory.name) is not None
             and directory.is_dir() and not directory.is_symlink(), 'wine_pe_temp_directory')
        for path in directory.rglob('*'):
            need(not path.is_symlink(), 'wine_pe_temp_alias')
            if path.is_file():
                context.record_output(str(path.relative_to(context.output)))
    for channel in ('stdout', 'stderr'):
        for line in Path(record['logs'][channel]['path']).read_text().splitlines():
            line = line.strip()
            match = re.match(r'^(?:lld-link: |ld.lld: )?Reading (.+)$', line)
            if match:
                value = match[1]
                archive = re.fullmatch(r'(.+\.(?:a|lib))\(([^()]+)\)', value)
                if archive:
                    value = archive[1]
                else:
                    need('(' not in value and ')' not in value, 'wine_pe_trace_format')
                path = Path(value)
                if archive and len(path.parts) == 1:
                    # LLD prints a full archive read first, then basename-only
                    # member reads. Resolve only an unambiguous prior read.
                    matches = [Path(name) for name in observed if Path(name).name == value]
                    need(len(matches) == 1, 'wine_pe_trace_archive_ambiguous')
                    path = matches[0]
                elif not path.is_absolute():
                    path = cwd / path
                need(path.is_file(), 'wine_pe_trace_missing_input')
                current = context._admit_path(path)
                observed[str(path.resolve())] = current
                reads.append(value)
                continue
            if not line.startswith(('/', '"/')):
                continue
            # Wine's stdio buffer can interleave the long argv tail with child
            # stdout. Its leading executable field remains independently exact.
            quoted = re.match(r'^"(/[^"\n]+)"\s+(?=-|"-)', line)
            bare = re.match(r'^(/[^\s"]+)\s+(?=-|"-)', line)
            match = quoted or bare
            need(match is not None, 'wine_pe_trace_command')
            executable = Path(match[1])
            need(executable.is_file(), 'wine_pe_trace_tool')
            tools[str(executable)] = context._admit_path(executable)
    need(reads and expected <= set(observed), 'wine_pe_trace_missing_declared_input')
    names = {Path(path).name for path in tools}
    need({'winebuild', 'clang', 'lld-link'} <= names, 'wine_pe_trace_missing_tool')
    return {'command_id': record['id'], 'inputs': list(observed.values()),
            'tools': list(tools.values()), 'required_operand_count': len(expected)}


def check_source_view(context, pe, dependencies):
    exclusions = {str(context.root(row['root']) / row['path']) for row in pe.get('source_view_exclusions', [])}
    need(not any(row['path'] in exclusions for row in dependencies), 'wine_pe_source_view_changed')


def builder_sources(context):
    root = Path(__file__).resolve().parents[1]
    files = [root / 'build.py', root / 'errors.py', Path(__file__).resolve()]
    return [fact(path) for path in files]


def snapshot_attempt(context, recipe_path, bindings_path, sources):
    """Retain admitted recipe and builder bytes before the first child starts."""
    recipe, recipe_bytes = load(recipe_path, with_bytes=True)
    bindings, bindings_bytes = load(bindings_path, with_bytes=True)
    need(sha(recipe_bytes) == context.recipe_sha256 and recipe == context.recipe,
         'recipe_snapshot_changed')
    need(bindings.get('roots', bindings) == context.bindings, 'recipe_bindings_changed')
    retained = []
    for relative, data in [('recipe.json', recipe_bytes), ('bindings.json', bindings_bytes)]:
        path = context.path('builder-snapshot/' + relative)
        with path.open('xb') as stream:
            stream.write(data)
        retained.append(context.record_output('builder-snapshot/' + relative))
    for expected in sources:
        source = Path(expected['path'])
        need(fact(source) == expected, 'recipe_builder_changed')
        saved = copy_result(context, source, 'builder-snapshot/' + source.name)
        need(saved['sha256'] == expected['sha256'] and fact(source) == expected,
             'recipe_builder_changed')
        retained.append(saved)
    manifest = context.path('builder-snapshot/manifest.json')
    manifest.write_text(json.dumps({'source_files': sources, 'retained_files': retained},
                                   indent=2, sort_keys=True) + '\n')
    return context.record_output('builder-snapshot/manifest.json')


def build(context):
    recipe = context.recipe
    need(recipe.get('driver') == 'wine' and recipe.get('recipe_version') == 1, 'wine_recipe_version')
    before = builder_sources(context)
    comparisons, implicit, artifacts, links_materialized = {}, [], {}, []
    native = recipe['native']
    reference = Path(expand(native['reference'], context))
    for record in native['commands']:
        command(context, record)
        if record['id'] == 'native-owner':
            context.record_output('native/owner.obj')
            context.record_output('native/owner.d')
            context.audit_depfile(context.output / 'native/owner.d')
        else:
            filename = 'control.so' if record['id'] == 'native-control' else 'ntdll.so'
            current = context.output / 'native' / filename
            context.record_output('native/' + filename)
            check = compare_macho(reference, current)
            comparisons[record['id']] = check
            need(check['text_equal'], 'wine_native_text_changed')
            mapname = 'control.map' if record['id'] == 'native-control' else 'link.map'
            context.record_output('native/' + mapname)
            implicit.append(audit_link_map(context, context.output / 'native' / mapname))
    artifacts['wine_native'] = context.outputs['native/ntdll.so']
    pe = recipe['pe']
    for row in recipe['inputs']:
        if row['root'] == 'inputs' and row['path'].startswith(pe['copy_prefix']):
            if row.get('kind') == 'symlink':
                admitted = context.input('inputs', row['path'])
                resolved = admitted.resolve(strict=True)
                relative = str(resolved.relative_to(context.root('inputs')))
                context.copy_input('inputs', relative, row['path'])
                links_materialized.append({'input': row['path'], 'target': row['target'],
                                           'resolved_input': relative, 'output_kind': 'regular_file',
                                           'identical_payload_sha256': row['sha256']})
            else:
                context.copy_input('inputs', row['path'], row['path'])
    original = Path(expand(pe['reference'], context)).read_bytes()
    expected_hybrid = PE(original).hybrid()
    target = context.output / 'pe/objects/dlls/ntdll/aarch64-windows/ntdll.dll'
    link = pe['commands'][-1]
    need(link['id'] == 'pe-optimized-link', 'wine_pe_link_recipe')
    env = {key: expand(value, context) for key, value in link['env'].items()}
    selected_compiler = context.input('llvm_mingw', 'bin/clang').resolve(strict=True)
    resolved_compiler = shutil.which('clang', path=env['PATH'])
    need(resolved_compiler is not None and Path(resolved_compiler).resolve(strict=True) == selected_compiler,
         'wine_path_compiler_mismatch')
    control_record = command(context, link, ident='pe-control-link')
    normalized, stamps = normalize_pe(target.read_bytes(), original)
    target.write_bytes(normalized)
    context.record_output(str(target.relative_to(context.output)))
    implicit.append(audit_pe_trace(context, control_record, [expand(v, context) for v in link['argv']]))
    need(normalized == original, 'wine_pe_control_changed')
    copy_result(context, target, 'pe/control.dll')
    comparisons['pe-control'] = {'normalized_whole_payload_equal': True, 'timestamps': stamps,
                                 'hybrid': expected_hybrid}
    for record in pe['commands'][:-1]:
        need(pe['optimization_flag'] in record['argv'], 'wine_pe_optimization')
        command(context, record)
        argv = [expand(value, context) for value in record['argv']]
        obj = Path(argv[argv.index('-o') + 1])
        rel = str(obj.relative_to(context.output))
        baseline = context.input('inputs', rel).read_bytes()
        normalized, stamp = normalize_coff(obj.read_bytes(), baseline)
        obj.write_bytes(normalized)
        context.record_output(rel)
        dep = Path(argv[argv.index('-MF') + 1])
        context.record_output(str(dep.relative_to(context.output)))
        dependencies = context.audit_depfile(dep)
        check_source_view(context, pe, dependencies)
        comparisons[record['id']] = {'selected_object_equal': True, 'timestamp': stamp}
    selected_record = command(context, link)
    normalized, stamps = normalize_pe(target.read_bytes(), original)
    target.write_bytes(normalized)
    context.record_output(str(target.relative_to(context.output)))
    implicit.append(audit_pe_trace(context, selected_record, [expand(v, context) for v in link['argv']]))
    actual_hybrid = PE(normalized).hybrid()
    comparisons['pe-selected'] = {'normalized_whole_payload_equal': normalized == original,
                                  'timestamps': stamps, 'hybrid': actual_hybrid,
                                  'reference_sha256': sha(original), 'candidate_sha256': sha(normalized)}
    need(normalized == original and actual_hybrid == expected_hybrid, 'wine_pe_selected_changed')
    artifacts['wine_pe'] = copy_result(context, target, 'pe/ntdll.dll')
    after = builder_sources(context)
    need(before == after, 'wine_builder_changed')
    return context.finish('passed', comparisons=comparisons,
                          extra={'artifacts': artifacts, 'implicit_link_inputs': implicit,
                                 'input_links_materialized': links_materialized,
                                 'builder_sources': {'before': before, 'after': after},
                                 'historical_semantics_gate': 'Selected reconstruction equivalence; does not rerun the original optimization experiment or game diagnostics.'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--bindings', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with Context(args.recipe, args.bindings, args.output) as context:
        try:
            snapshot_attempt(context, args.recipe, args.bindings, builder_sources(context))
            build(context)
        except Exception as error:
            context.finish('failed', extra={'failure_code': getattr(error, 'code', type(error).__name__)})
            raise


if __name__ == '__main__':
    main()
