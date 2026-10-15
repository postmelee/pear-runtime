#!/usr/bin/env python3
"""Inspect selected built PE modules without loading or executing guest code."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time

from common import Error, load_json, need, read_relative, record, sha256
from toolchain import MACH_ARM64, base_env, inspect_closure, task_path, write_new

NAMES = ('ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'win32u.dll',
         'winemac.drv', 'wineboot.exe', 'wow64.dll')
OPTIONS = ('--file-headers', '--coff-imports', '--coff-exports', '--coff-load-config')
PRODUCERS = ('modules.py', 'common.py', 'toolchain.py')
MAX_PE = 64 * 1024 * 1024
MAX_LOG = 1024 * 1024


class PE:
    """Bounded parser for the pinned build's native-view PE32+ structures."""
    def __init__(self, data):
        self.data = data
        need(isinstance(data, bytes) and 64 <= len(data) <= MAX_PE, 'module_size')
        need(data[:2] == b'MZ', 'module_dos_signature')
        self.pe = self.u('I', 60)
        need(self.take(self.pe, 4) == b'PE\0\0', 'module_pe_signature')
        self.machine = self.u('H', self.pe + 4)
        count = self.u('H', self.pe + 6)
        size = self.u('H', self.pe + 20)
        self.opt = self.pe + 24
        need(self.u('H', self.opt) == 0x20b and size >= 240 and 1 <= count <= 96,
             'module_optional_header')
        self.base = self.u('Q', self.opt + 24)
        self.headers_size = self.u('I', self.opt + 60)
        need(self.headers_size <= len(data), 'module_headers_size')
        need(self.u('I', self.opt + 108) == 16, 'module_directory_count')
        self.dirs = [self.unpack('II', self.opt + 112 + i * 8) for i in range(16)]
        self.sections = []
        for i in range(count):
            start = self.opt + size + i * 40
            name = self.take(start, 8).rstrip(b'\0').decode('ascii')
            virtual, rva, raw_size, raw = self.unpack('IIII', start + 8)
            need(raw + raw_size <= len(data), 'module_section_bounds')
            self.sections.append({'name': name, 'rva': rva, 'virtual_size': virtual,
                                  'raw_size': raw_size, 'raw_offset': raw,
                                  'characteristics': self.u('I', start + 36)})

    def take(self, offset, size):
        need(0 <= offset <= len(self.data) and 0 <= size <= len(self.data) - offset,
             'module_structure_bounds')
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack('<' + fmt, self.take(offset, struct.calcsize('<' + fmt)))

    def u(self, fmt, offset):
        return self.unpack(fmt, offset)[0]

    def offset(self, rva, size):
        need(type(rva) is int and rva >= 0 and size >= 0, 'module_rva')
        hits = []
        if rva + size <= self.headers_size:
            hits.append(rva)
        for s in self.sections:
            delta = rva - s['rva']
            if 0 <= delta and delta + size <= min(s['raw_size'], s['virtual_size']):
                hits.append(s['raw_offset'] + delta)
        need(len(hits) == 1, 'module_unmapped_or_ambiguous_rva')
        return hits[0]

    def string(self, rva):
        # Map each byte so an unterminated string cannot escape its section.
        value = bytearray()
        for i in range(4096):
            byte = self.data[self.offset(rva + i, 1)]
            if byte == 0:
                need(all(32 <= c < 127 for c in value), 'module_string_encoding')
                return value.decode('ascii')
            value.append(byte)
        raise Error('module_string_limit')

    def code_range(self, rva, size):
        # LLVM may coalesce a CHPE range across adjacent executable sections,
        # including their on-disk alignment padding (.text and .hexpthk).
        end = rva + size
        need(size > 0 and end <= self.u('I', self.opt + 56), 'module_chpe_range_bounds')
        cursor = rva
        for section in sorted(self.sections, key=lambda row: row['rva']):
            start = section['rva']
            stop = start + max(section['raw_size'], section['virtual_size'])
            if section['characteristics'] & 0x20000000 and start <= cursor < stop:
                cursor = min(end, stop)
                if cursor == end:
                    return
        raise Error('module_chpe_range_unmapped')

    def imports(self, delay=False):
        rva, size = self.dirs[13 if delay else 1]
        if not rva and not size:
            return []
        stride = 32 if delay else 20
        start = self.offset(rva, size)
        need(stride <= size <= 1024 * stride, 'module_import_size')
        names = []
        for at in range(start, start + size - stride + 1, stride):
            values = self.unpack('8I' if delay else '5I', at)
            if not any(values):
                return names
            if delay:
                need(values[0] == 1, 'module_delay_import_not_rva')
            names.append(self.string(values[1 if delay else 3]))
        raise Error('module_import_terminator')

    def exports(self):
        rva, size = self.dirs[0]
        if not rva and not size:
            return []
        start = self.offset(rva, 40)
        base, functions, count, addresses, names, ordinals = self.unpack('6I', start + 16)
        need(count <= functions <= 65536, 'module_export_count')
        addr = self.offset(addresses, functions * 4)
        names_at = self.offset(names, count * 4) if count else 0
        ordinal_at = self.offset(ordinals, count * 2) if count else 0
        by_ordinal = {}
        for i in range(count):
            ordinal = self.u('H', ordinal_at + i * 2)
            need(ordinal < functions and ordinal not in by_ordinal, 'module_export_name_ordinal')
            by_ordinal[ordinal] = self.string(self.u('I', names_at + i * 4))
        result = []
        for i in range(functions):
            address = self.u('I', addr + i * 4)
            entry = {'ordinal': base + i, 'name': by_ordinal.get(i, ''), 'rva': address}
            if rva <= address < rva + size:
                entry['forwarder'] = self.string(address)
            result.append(entry)
        return result

    def load_config(self):
        rva, size = self.dirs[10]
        if not rva and not size:
            return {'present': False, 'chpe_pointer': '0x0', 'arm64x_machine_fixups': []}
        start = self.offset(rva, size)
        size = min(size, self.u('I', start))
        need(size >= 4, 'module_load_config_size')
        pointer = self.u('Q', start + 0xc8) if size >= 0xd0 else 0
        result = {'present': True, 'size': size, 'chpe_pointer': hex(pointer),
                  'arm64x_machine_fixups': []}
        if pointer:
            metadata = self.offset(pointer - self.base, 12)
            version, codemap, count = self.unpack('3I', metadata)
            need(1 <= version <= 2 and 0 < count <= 65536, 'module_chpe_header')
            code_map = self.offset(codemap, count * 8)
            ranges = []
            for index in range(count):
                encoded_rva, length = self.unpack('II', code_map + index * 8)
                kind, range_start = encoded_rva & 3, encoded_rva & ~3
                need(kind <= 2 and length > 0, 'module_chpe_range')
                self.code_range(range_start, length)
                ranges.append({'rva': range_start, 'size': length, 'type': kind})
            result['chpe'] = {'version': version, 'code_map_rva': codemap,
                              'code_map_count': count, 'code_ranges': ranges}
        if size < 0xe8:
            return result
        offset, section = self.unpack('IH', start + 0xe0)
        result.update(dynamic_relocation_offset=offset, dynamic_relocation_section=section)
        if not section:
            return result
        need(section <= len(self.sections), 'module_dynamic_section')
        table_rva = self.sections[section - 1]['rva'] + offset
        table = self.offset(table_rva, 8)
        version, length = self.unpack('II', table)
        need(version == 1 and 12 <= length <= 4 * 1024 * 1024, 'module_dynamic_table')
        self.offset(table_rva, length + 8)
        result.update(dynamic_relocation_version=version, dynamic_relocation_size=length)
        at, end, fixups = table + 8, table + 8 + length, []
        while at < end:
            need(at + 12 <= end, 'module_dynamic_record')
            symbol, span = self.unpack('QI', at)
            at += 12
            stop = at + span
            need(stop <= end, 'module_dynamic_record')
            if symbol == 6:  # IMAGE_DYNAMIC_RELOCATION_ARM64X, winnt.h.
                while at < stop:
                    need(at + 8 <= stop, 'module_dynamic_block')
                    page, block_size = self.unpack('II', at)
                    block_end = at + block_size
                    need(block_size >= 8 and block_size % 2 == 0 and block_end <= stop,
                         'module_dynamic_block')
                    at += 8
                    while at < block_end:
                        value = self.u('H', at)
                        at += 2
                        if value == 0:
                            need(not any(self.take(at, block_end - at)), 'module_dynamic_padding')
                            break
                        target = page + (value & 0xfff)
                        kind, arg = (value >> 12) & 3, value >> 14
                        need(kind <= 2, 'module_dynamic_fixup_type')
                        payload = (1 << arg) if kind == 1 else (2 if kind == 2 else 0)
                        need(at + payload <= block_end, 'module_dynamic_fixup_size')
                        if kind == 1 and target == self.pe + 4:
                            need(payload == 2, 'module_dynamic_machine_size')
                            fixups.append({'rva': target, 'value': self.u('H', at)})
                        at += payload
                    at = block_end
            at = stop
        result['arm64x_machine_fixups'] = fixups
        return result


def inspect_pe(data):
    pe = PE(data)
    need(pe.machine == 0xaa64, 'module_native_view_machine')
    return {'machine': pe.machine, 'optional_magic': 0x20b,
            'entrypoint_rva': pe.u('I', pe.opt + 16), 'image_base': hex(pe.base),
            'sections': pe.sections, 'imports': pe.imports(), 'delay_imports': pe.imports(True),
            'exports': pe.exports(), 'load_config': pe.load_config()}


def require_hybrid(facts):
    config = facts['load_config']
    need(config.get('chpe') and int(config['chpe_pointer'], 16) > 0
         and config.get('dynamic_relocation_version') == 1
         and len(config['arm64x_machine_fixups']) == 1
         and config['arm64x_machine_fixups'][0]['value'] == 0x8664,
         'module_arm64x_metadata_missing')
    need({0, 1}.issubset({row['type'] for row in config['chpe']['code_ranges']}),
         'module_arm64x_code_ranges_missing')


def assess_readobj(text, facts, module):
    """Cross-check text observations against independently parsed module bytes."""
    need(text.count('\nFile: ') == 1 and '\nFile: ' + str(module) + '\n' in text,
         'module_tool_file_identity')
    machines = re.findall(r'^  Machine: .*\(0x([0-9A-Fa-f]+)\)$', text, re.M)
    reader_machine = facts['machine']
    if facts['load_config']['arm64x_machine_fixups']:
        # LLVM reports a semantic ARM64X machine for the raw ARM64 outer header.
        # A filename or AA64 header alone does not establish that classification.
        require_hybrid(facts)
        reader_machine = 0xa64e
    need(machines == [format(reader_machine, 'X')], 'module_tool_machine')
    imports = re.findall(r'^Import \{\n  Name: ([^\n]+)', text, re.M)
    delays = re.findall(r'^DelayImport \{\n  Name: ([^\n]+)', text, re.M)
    need(imports == facts['imports'] and delays == facts['delay_imports'], 'module_tool_imports')
    exports = []
    for ordinal, name, kind, value in re.findall(
            r'^Export \{\n  Ordinal: (\d+)\n  Name: ([^\n]*)\n  (RVA|ForwardedTo): ([^\n]+)\n\}', text, re.M):
        entry = {'ordinal': int(ordinal), 'name': name}
        entry['rva' if kind == 'RVA' else 'forwarder'] = int(value, 16) if kind == 'RVA' else value
        exports.append(entry)
    expected = [{k: row[k] for k in ('ordinal', 'name', 'forwarder' if 'forwarder' in row else 'rva')}
                for row in facts['exports']]
    need(exports == expected,
         'module_tool_exports')
    pointer = facts['load_config']['chpe_pointer']
    if int(pointer, 16):
        pointers = re.findall(r'^  CHPEMetadataPointer: 0x([0-9A-Fa-f]+)$', text, re.M)
        need(len(pointers) == 1 and int(pointers[0], 16) == int(pointer, 16), 'module_tool_chpe')
    if facts['load_config']['arm64x_machine_fixups']:
        need('DynamicRelocations [' in text and 'Arm64X [' in text, 'module_tool_dynamic_relocations')


def tool_identity(built):
    tools = task_path(built['tools_root']).resolve()
    bundle = tools / 'llvm-mingw'
    executable = bundle / 'bin/llvm-readobj'
    closure = inspect_closure(executable, bundle)
    need(all(MACH_ARM64 in row['architectures'] for row in closure), 'module_tool_native_arm64')
    return {'path': str(executable), 'resolved_path': str(executable.resolve()),
            'sha256': sha256(executable.resolve()), 'closure': closure}


def producers():
    return {name: sha256(Path(__file__).parent / name) for name in PRODUCERS}


def run_reader(commands, name, argv, work, env, timeout=60):
    """Capture larger CHPE tables with bounded files and owned child cleanup."""
    argv = ['/usr/bin/arch', '-arm64', *map(str, argv)]
    row = {'id': name, 'argv': argv, 'cwd': str(work)}
    commands.append(row)
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(argv, cwd=work, env=env, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, start_new_session=True)
        started = time.monotonic()
        timed_out = output_limit = False
        try:
            while process.poll() is None:
                timed_out = time.monotonic() - started > timeout
                output_limit = max(os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size) > MAX_LOG
                if timed_out or output_limit:
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                time.sleep(0.02)
            code = process.wait(timeout=5)
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            raise
        output_limit = output_limit or max(os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size) > MAX_LOG
        row.update(exit_code=code, timed_out=timed_out, output_limit=output_limit,
                   elapsed_ms=round((time.monotonic() - started) * 1000))
        logs = work / '.pear-command-logs'
        logs.mkdir(exist_ok=True)
        for stream, handle in (('stdout', out), ('stderr', err)):
            handle.seek(0)
            raw = handle.read(MAX_LOG)
            path = logs / (name + '.' + stream)
            with path.open('xb') as target:
                target.write(raw)
            row[stream] = raw[:16000].decode('utf-8', errors='replace')
            row[stream + '_preview_truncated'] = len(raw) > 16000
            row[stream + '_log'] = {'path': str(path), 'sha256': sha256(path), 'size_bytes': len(raw)}
    need(code == 0 and not timed_out and not output_limit, 'module_reader_failed')
    return row


def validate_inventory(buildroot, *, verified_build=None):
    """Rehash selected images and reparse their structures and exact local logs."""
    from build import verify_build
    root = task_path(buildroot).resolve()
    built = verified_build if verified_build is not None else verify_build(root)
    result = record(load_json(root / 'modules.json'), 'wine_module_inventory')
    need(result.get('passed') is True and result.get('guest_execution') is False
         and result.get('coverage') == 'selected_native_view_pe_modules', 'module_inventory_scope')
    need(result['build_sha256'] == sha256(root / 'build.json')
         and load_json(root / 'build.json') == built and built.get('passed') is True,
         'module_build_changed')
    need(result['producer_sha256'] == producers(), 'module_producer_changed')
    need(result['tool'] == tool_identity(built), 'module_tool_changed')
    need(result['variant'] == built['variant'] and len(result['modules']) == len(NAMES)
         and len(result['commands']) == len(NAMES), 'module_inventory_coverage')
    work = root / 'modules.work'
    for name, row, command in zip(NAMES, result['modules'], result['commands']):
        path = 'lib/wine/aarch64-windows/' + name
        module = root / 'install' / path
        raw = read_relative(root / 'install', path, MAX_PE)
        facts = inspect_pe(raw)
        hybrid = name == 'ntdll.dll' and built['variant'] == 'arm64ec-build'
        if hybrid:
            require_hybrid(facts)
        need(row == {'path': path, 'sha256': hashlib.sha256(raw).hexdigest(),
                     'size_bytes': len(raw), 'facts': facts, 'hybrid_required': hybrid,
                     'command_id': name}, 'module_bytes_or_facts_changed')
        need(command['id'] == name and command['cwd'] == str(work)
             and command['argv'] == ['/usr/bin/arch', '-arm64', result['tool']['path'], *OPTIONS, str(module)]
             and type(command['exit_code']) is int and command['exit_code'] == 0
             and command['timed_out'] is False and command['output_limit'] is False,
             'module_command_outcome')
        logs = {}
        for stream in ('stdout', 'stderr'):
            reference = command[stream + '_log']
            relative_name = 'modules.work/.pear-command-logs/' + name + '.' + stream
            raw = read_relative(root, relative_name, MAX_LOG)
            need(reference == {'path': str(root / relative_name),
                               'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)},
                 'module_log_changed')
            need(command[stream] == raw[:16000].decode('utf-8', errors='replace')
                 and command[stream + '_preview_truncated'] == (len(raw) > 16000),
                 'module_log_preview_changed')
            logs[stream] = raw.decode('utf-8', errors='strict')
        need(not logs['stderr'], 'module_tool_diagnostic')
        assess_readobj(logs['stdout'], facts, module)
    return result


def create_inventory(buildroot, output):
    from build import verify_build
    root = task_path(buildroot).resolve()
    output = Path(output).absolute()
    need(output == root / 'modules.json' and not output.exists() and not output.is_symlink(),
         'module_output_path')
    built = verify_build(root)
    work = root / 'modules.work'
    work.mkdir()  # Existing attempts are preserved and must not be overwritten.
    result = {'schema_version': 1, 'record_kind': 'wine_module_inventory',
              'coverage': 'selected_native_view_pe_modules', 'guest_execution': False,
              'variant': built['variant'], 'build_sha256': sha256(root / 'build.json'),
              'producer_sha256': producers(), 'tool': tool_identity(built),
              'modules': [], 'commands': [], 'passed': False}
    try:
        for name in NAMES:
            path = 'lib/wine/aarch64-windows/' + name
            module = root / 'install' / path
            raw = read_relative(root / 'install', path, MAX_PE)
            facts = inspect_pe(raw)
            hybrid = name == 'ntdll.dll' and built['variant'] == 'arm64ec-build'
            if hybrid:
                require_hybrid(facts)
            result['modules'].append({'path': path, 'sha256': hashlib.sha256(raw).hexdigest(),
                                      'size_bytes': len(raw), 'facts': facts,
                                      'hybrid_required': hybrid, 'command_id': name})
            run_reader(result['commands'], name,
                       [result['tool']['path'], *OPTIONS, module], work,
                       base_env(built['sdk']['resolved_path']))
            stdout = read_relative(work, '.pear-command-logs/' + name + '.stdout', MAX_LOG).decode('utf-8')
            stderr = read_relative(work, '.pear-command-logs/' + name + '.stderr', MAX_LOG)
            need(not stderr, 'module_tool_diagnostic')
            assess_readobj(stdout, facts, module)
        need(result['producer_sha256'] == producers(), 'module_producer_changed')
        need(result['build_sha256'] == sha256(root / 'build.json'), 'module_build_changed')
        result['passed'] = True
    except (Error, OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as exc:
        result['error'] = getattr(exc, 'code', type(exc).__name__)
    write_new(output, result)
    if result['passed']:
        validate_inventory(root, verified_build=built)
    return 0 if result['passed'] else 3


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args(argv)
    try:
        return create_inventory(args.build, args.output)
    except (Error, OSError, ValueError, KeyError, TypeError) as exc:
        print(getattr(exc, 'code', type(exc).__name__), file=sys.stderr)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
