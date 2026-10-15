# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable binary correspondence and explicit-root recipe refusal controls."""
from pathlib import Path
import hashlib
import json
import struct
import tempfile
import unittest

from pear_runtime.errors import Error
from pear_runtime.build import fact
from pear_runtime.recipes.wine import (PE, audit_link_map, audit_pe_trace, check_source_view, compare_macho,
                                      expand, macho_sections, normalize_coff, normalize_pe, snapshot_attempt)


def pe_fixture():
    data = bytearray(0x800)
    def put(fmt, off, *values):
        struct.pack_into('<' + fmt, data, off, *values)
    data[:2] = b'MZ'
    put('I', 60, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    put('HHI', 0x84, 0xaa64, 2, 111)
    put('H', 0x94, 240)
    opt = 0x98
    put('H', opt, 0x20b)
    put('Q', opt + 24, 0x180000000)
    put('I', opt + 60, 0x200)
    put('I', opt + 108, 16)
    put('II', opt + 112 + 6 * 8, 0x2300, 28)
    put('II', opt + 112 + 10 * 8, 0x2000, 0xe8)
    for i, (name, rva, raw, size) in enumerate([(b'.text', 0x1000, 0x200, 0x200), (b'.rdata', 0x2000, 0x400, 0x400)]):
        at = opt + 240 + i * 40
        data[at:at + 8] = name.ljust(8, b'\0')
        put('IIII', at + 8, size, rva, size, raw)
        put('I', at + 36, 0x60000020 if i == 0 else 0x40000040)
    put('I', 0x400, 0xe8)
    put('Q', 0x4c8, 0x180002100)
    put('IH', 0x4e0, 0x180, 2)
    put('III', 0x500, 2, 0x2120, 2)
    put('IIII', 0x520, 0x1000, 16, 0x1011, 16)
    put('IIQI', 0x580, 1, 24, 6, 12)
    put('IIHH', 0x594, 0, 12, 0x5084, 0x8664)
    put('I', 0x704, 111)
    return bytes(data)


def macho_fixture(text=b'CODE', cpu=0x0100000c):
    data = bytearray(0x200 + len(text))
    struct.pack_into('<8I', data, 0, 0xfeedfacf, cpu, 0, 6, 1, 152, 0, 0)
    struct.pack_into('<II', data, 32, 0x19, 152)
    struct.pack_into('<I', data, 32 + 64, 1)
    section = 32 + 72
    data[section:section + 16] = b'__text'.ljust(16, b'\0')
    data[section + 16:section + 32] = b'__TEXT'.ljust(16, b'\0')
    struct.pack_into('<Q', data, section + 40, len(text))
    struct.pack_into('<I', data, section + 48, 0x200)
    data[0x200:] = text
    return bytes(data)


class WineRecipeTests(unittest.TestCase):
    def test_attempt_snapshot_preserves_inputs_and_rejects_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            recipe_path, bindings_path, source = (root / n for n in ('recipe.json', 'bindings.json', 'driver.py'))
            recipe_path.write_text('{"name":"fixture"}\n')
            bindings_path.write_text('{"roots": {"input": "/selected"}}\n')
            source.write_bytes(b'# exact driver bytes\n')
            class Context:
                recipe = json.loads(recipe_path.read_text())
                recipe_sha256 = hashlib.sha256(recipe_path.read_bytes()).hexdigest()
                bindings = {'input': '/selected'}
                def path(self, rel):
                    path = root / 'output' / rel
                    path.parent.mkdir(parents=True, exist_ok=True)
                    return path
                def record_output(self, rel):
                    return fact(self.path(rel))
            snapshot_attempt(Context(), recipe_path, bindings_path, [fact(source)])
            self.assertEqual((root / 'output/builder-snapshot/driver.py').read_bytes(), source.read_bytes())
            self.assertEqual((root / 'output/builder-snapshot/recipe.json').read_bytes(), recipe_path.read_bytes())
            recipe_path.write_text('{"name":"replaced"}\n')
            with self.assertRaisesRegex(Error, 'recipe_snapshot_changed'):
                snapshot_attempt(Context(), recipe_path, bindings_path, [fact(source)])

    def test_only_coff_timestamp_is_normalized(self):
        old = b'\x64\xaa\x01\x00' + b'old!' + b'unchanged payload'
        new = old[:4] + b'new!' + old[8:]
        self.assertEqual(normalize_coff(new, old)[0], old)

    def test_coff_code_difference_is_refused(self):
        old = b'\x41\xa6\x01\x00' + b'old!' + b'unchanged payload'
        with self.assertRaisesRegex(Error, 'recipe_coff_code_changed'):
            normalize_coff(old[:-1] + b'?', old)

    def test_coff_wrong_machine_is_refused(self):
        with self.assertRaisesRegex(Error, 'recipe_coff_machine'):
            normalize_coff(b'\x64\x86' + bytes(20), b'\x64\x86' + bytes(20))

    def test_pe_timestamps_preserve_other_payload(self):
        original = pe_fixture()
        new = bytearray(original)
        struct.pack_into('<I', new, 0x88, 999)
        struct.pack_into('<I', new, 0x704, 888)
        result, changes = normalize_pe(bytes(new), original)
        self.assertEqual(result, original)
        self.assertEqual([x['offset'] for x in changes], [0x88, 0x704])

    def test_pe_code_difference_survives_normalization(self):
        old = pe_fixture()
        new = bytearray(old)
        new[0x210] = 1
        self.assertNotEqual(normalize_pe(bytes(new), old)[0], old)

    def test_arm64x_requires_chpe_and_machine_fixup(self):
        data = pe_fixture()
        result = PE(data).hybrid()
        self.assertEqual(result['code_types'], [0, 1])
        self.assertEqual(result['machine_fixups'], [0x8664])
        wrong = bytearray(data)
        struct.pack_into('<H', wrong, 0x59e, 0xaa64)
        with self.assertRaisesRegex(Error, 'recipe_pe_arm64x_fixup'):
            PE(bytes(wrong)).hybrid()

    def test_outer_arm64_header_alone_is_insufficient(self):
        wrong = bytearray(pe_fixture())
        struct.pack_into('<Q', wrong, 0x4c8, 0)
        with self.assertRaises(Error):
            PE(bytes(wrong)).hybrid()

    def test_malformed_pe_bounds_are_refused(self):
        wrong = bytearray(pe_fixture())
        struct.pack_into('<I', wrong, 0x188 + 20, len(wrong) + 100)
        with self.assertRaises(Error):
            PE(bytes(wrong))

    def test_native_wrong_architecture_is_refused(self):
        with self.assertRaisesRegex(Error, 'recipe_macho_architecture'):
            macho_sections(macho_fixture(cpu=0x01000007))

    def test_native_text_difference_is_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'old').write_bytes(macho_fixture())
            (root / 'new').write_bytes(macho_fixture(b'DIFF'))
            result = compare_macho(root / 'old', root / 'new')
            self.assertFalse(result['text_equal'])
            self.assertEqual(result['changed_sections'], ['__TEXT,__text'])

    def test_explicit_roots_preserve_spaces(self):
        class Context:
            output = Path('/new output')
            def root(self, name):
                if name != 'wine':
                    raise Error('build_unknown_root')
                return Path('/new source')
        self.assertEqual(expand('-I{wine}/include', Context()), '-I/new source/include')
        with self.assertRaisesRegex(Error, 'build_unknown_root'):
            expand('{old_worktree}/include', Context())

    def test_different_historical_header_must_be_absent(self):
        class Context:
            def root(self, name):
                return Path('/source')
        policy = {'source_view_exclusions': [{'root': 'wine', 'path': 'different.h'}]}
        check_source_view(Context(), policy, [{'path': '/source/unchanged.h'}])
        with self.assertRaisesRegex(Error, 'wine_pe_source_view_changed'):
            check_source_view(Context(), policy, [{'path': '/source/different.h'}])

    def test_pe_trace_requires_all_read_inputs_and_child_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('one.o', 'two.a', 'winebuild', 'clang', 'lld-link'):
                (root / name).write_bytes(name.encode())
            trace = root / 'trace.log'
            lines = ['"' + str(root / name) + '" -v' for name in ('winebuild', 'clang', 'lld-link')]
            lines += ['lld-link: Reading ' + str(root / 'one.o'),
                      'lld-link: Reading ' + str(root / 'two.a') + '(member.o)']
            trace.write_text('\n'.join(lines) + '\n')
            (root / 'empty.log').write_text('')
            class Context:
                output = root
                def _admit_path(self, path):
                    return fact(path)
            command = {'id': 'link', 'cwd': str(root), 'env': {'PATH': str(root)},
                       'logs': {'stdout': {'path': str(trace)}, 'stderr': {'path': str(root / 'empty.log')}}}
            args = [str(root / n) for n in ('one.o', 'two.a')]
            result = audit_pe_trace(Context(), command, args)
            self.assertEqual(len(result['inputs']), 2)
            trace.write_text('\n'.join(lines + ['lld-link: Reading two.a(member.o)']) + '\n')
            self.assertEqual(len(audit_pe_trace(Context(), command, args)['inputs']), 2)
            trace.write_text('lld-link: Reading unknown.a(member.o)\n')
            with self.assertRaisesRegex(Error, 'wine_pe_trace_archive_ambiguous'):
                audit_pe_trace(Context(), command, args)
            # Buffered argv tails can interleave, but the exact executable
            # field and independent linker Reading rows remain required.
            interleaved = list(lines)
            interleaved[0] += ' "unfinished parent argv' + lines[1]
            trace.write_text('\n'.join(interleaved) + '\n')
            self.assertEqual(len(audit_pe_trace(Context(), command, args)['tools']), 3)
            trace.write_text('\n'.join(lines[1:]) + '\n')
            with self.assertRaisesRegex(Error, 'wine_pe_trace_missing_tool'):
                audit_pe_trace(Context(), command, args)
            trace.write_text('"' + str(root / 'winebuild') + '\n')
            with self.assertRaisesRegex(Error, 'wine_pe_trace_command'):
                audit_pe_trace(Context(), command, args)
            trace.write_text('\n'.join(lines[:-1]) + '\n')
            with self.assertRaisesRegex(Error, 'wine_pe_trace_missing_declared_input'):
                audit_pe_trace(Context(), command, args)
            trace.write_text('lld-link: Reading ' + str(root / 'missing.o') + '\n')
            with self.assertRaisesRegex(Error, 'wine_pe_trace_missing_input'):
                audit_pe_trace(Context(), command, args)
            trace.write_text('lld-link: Reading unknown(object)format\n')
            with self.assertRaisesRegex(Error, 'wine_pe_trace_format'):
                audit_pe_trace(Context(), command, args)

    def test_link_map_admits_all_object_and_archive_entries(self):
        class Context:
            def _admit_path(self, path):
                return {'path': str(path)}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'one.o').write_bytes(b'object')
            (root / 'two.a').write_bytes(b'archive')
            path = root / 'link.map'
            path.write_text('# Object files:\n[  0] linker synthesized\n[  1] one.o\n[  2] two.a(member.o)\n# Symbols:\nnot-an-input\n')
            result = audit_link_map(Context(), path)
            self.assertEqual([Path(r['path']).name for r in result['inputs']], ['one.o', 'two.a'])

    def test_link_map_missing_input_is_refused(self):
        class Context:
            def _admit_path(self, path):
                return {'path': str(path)}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'one.o').write_bytes(b'object')
            path = root / 'link.map'
            path.write_text('# Object files:\n[  0] linker synthesized\n[  1] one.o\n[  2] missing.a(member.o)\n# Sections:\n')
            with self.assertRaisesRegex(Error, 'recipe_link_map_missing_input'):
                audit_link_map(Context(), path)

    def test_link_map_unknown_entry_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'link.map'
            path.write_text('# Object files:\n[  0] linker synthesized\nunknown object encoding\n# Sections:\n')
            with self.assertRaisesRegex(Error, 'recipe_link_map_unknown_entry'):
                audit_link_map(None, path)


if __name__ == '__main__':
    unittest.main()
