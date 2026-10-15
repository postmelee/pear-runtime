# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact bounded metadata reader; no constructor or compiler."""
import struct
from pear_runtime.errors import need

def pe_facts(data, dll):
    need(isinstance(data, bytes) and len(data) <= 64 * 1024**2, 'memory_wine_pe_size')
    def number(fmt, offset):
        need(0 <= offset and offset + struct.calcsize('<' + fmt) <= len(data), 'memory_wine_pe_bounds')
        return struct.unpack_from('<' + fmt, data, offset)[0]
    need(len(data) >= 64 and data[:2] == b'MZ', 'memory_wine_pe_header')
    at = number('I', 60); opt = at + 24; count = number('H', at + 6); size = number('H', at + 20)
    need(at >= 64 and data[at:at + 4] == b'PE\0\0' and number('H', at + 4) == 0xaa64
         and number('H', opt) == 0x20b and 1 <= count <= 96 and size >= 240
         and number('I', opt + 108) == 16 and bool(number('H', at + 22) & 0x2000) == dll,
         'memory_wine_pe_native_arm64')
    sections = []
    for i in range(count):
        p = opt + size + i * 40
        span, rva, raw_size, raw, flags = [number('I', p + n) for n in (8, 12, 16, 20, 36)]
        need(raw + raw_size <= len(data), 'memory_wine_pe_section')
        sections.append((rva, min(span, raw_size), raw, flags))
    def mapped(rva, span):
        found = [raw + rva - base for base, length, raw, _ in sections
                 if span > 0 and rva >= base and rva - base + span <= length]
        need(len(found) == 1, 'memory_wine_pe_rva'); return found[0]
    def string(rva):
        p = mapped(rva, 1); end = data.find(b'\0', p, min(p + 4096, len(data)))
        need(end > p, 'memory_wine_pe_string'); mapped(rva, end - p + 1)
        return data[p:end].decode('ascii')
    need((number('I', opt + 112 + 13 * 8), number('I', opt + 116 + 13 * 8)) == (0, 0),
         'memory_wine_pe_delay_import')
    import_rva, import_size = number('I', opt + 120), number('I', opt + 124)
    imports = []
    if import_rva or import_size:
        need(import_rva and 20 <= import_size <= 1024**2, 'memory_wine_pe_import_directory')
        p = mapped(import_rva, import_size); terminated = False
        for offset in range(0, import_size - 19, 20):
            row = struct.unpack_from('<5I', data, p + offset)
            if not any(row): terminated = True; break
            name = string(row[3]).lower(); need(name not in imports, 'memory_wine_pe_import_duplicate'); imports.append(name)
        need(terminated, 'memory_wine_pe_import_terminator')
    exports = []; private_thunk = False
    export_rva, export_size = number('I', opt + 112), number('I', opt + 116)
    if export_rva or export_size:
        need(export_rva and 40 <= export_size <= 1024**2, 'memory_wine_pe_exports')
        p = mapped(export_rva, export_size)
        functions, names = number('I', p + 20), number('I', p + 24)
        need(0 < names <= functions <= 4096, 'memory_wine_pe_exports')
        table = mapped(number('I', p + 32), names * 4)
        ordinals = mapped(number('I', p + 36), names * 2)
        addresses = mapped(number('I', p + 28), functions * 4)
        exports = [string(number('I', table + 4 * i)) for i in range(names)]
        selected_ordinals = set()
        for index, name in enumerate(exports):
            ordinal = number('H', ordinals + 2 * index)
            need(ordinal < functions and ordinal not in selected_ordinals, 'memory_wine_pe_export_ordinal')
            selected_ordinals.add(ordinal)
            target = number('I', addresses + ordinal * 4)
            need(target, 'memory_wine_pe_export_missing_target')
            if name == '__wine_pear_fex_memory':
                need(not export_rva <= target < export_rva + export_size, 'memory_wine_pe_thunk_forwarded')
                mapped(target, 1)
                need(any(base <= target < base + length and flags & 0x20000000
                         for base, length, _, flags in sections), 'memory_wine_pe_thunk_non_executable')
                private_thunk = True
        need(len(set(exports)) == len(exports), 'memory_wine_pe_exports')
    return {'machine': 0xaa64, 'dll': dll, 'imports': sorted(imports), 'named_exports': sorted(exports),
            'delay_imports': False, 'private_memory_thunk_export': private_thunk, 'execution': False}
