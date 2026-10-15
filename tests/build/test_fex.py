# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable archive, PE/COFF, path, private-input and trace rejection checks."""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from pear_runtime.build import Context, fact
from pear_runtime.errors import Error
from pear_runtime.recipes.fex import (
    archive_members, bind_token, canonical_input_path, coff_machine, compare_pe, compare_stripped_text, link_trace,
    pe_info, private_recipe, verify_archive,
)


def archive(*members):
    result = b'!<arch>\n'
    for name, data in members:
        header = (name.ljust(16) + '0'.ljust(12) + '0'.ljust(6) + '0'.ljust(6)
                  + '100644'.ljust(8) + str(len(data)).ljust(10) + '`\n').encode('ascii')
        result += header + data + (b'\n' if len(data) % 2 else b'')
    return result


def synthetic_pe():
    raw = bytearray(2048)
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 60, 128)
    raw[128:132] = b'PE\0\0'
    struct.pack_into('<HH', raw, 132, 0x8664, 3)
    struct.pack_into('<HH', raw, 148, 240, 0x2000)
    optional = 152
    struct.pack_into('<H', raw, optional, 0x20b)
    struct.pack_into('<I', raw, optional + 16, 0x1000)
    struct.pack_into('<Q', raw, optional + 24, 0x180000000)
    struct.pack_into('<I', raw, optional + 108, 16)
    struct.pack_into('<II', raw, optional + 112 + 10 * 8, 0x2000, 208)
    for index, (name, rva, flags) in enumerate(((b'.text', 0x1000, 0x60000020),
                                               (b'.rdata', 0x2000, 0x40000040),
                                               (b'.data', 0x3000, 0xc0000040))):
        at = optional + 240 + index * 40
        raw[at:at + len(name)] = name
        struct.pack_into('<IIII', raw, at + 8, 512, rva, 512, 512 + index * 512)
        struct.pack_into('<I', raw, at + 36, flags)
    raw[512:516] = b'code'
    struct.pack_into('<I', raw, 1024, 208)
    struct.pack_into('<Q', raw, 1224, 0x180003000)
    struct.pack_into('<I', raw, 1536, 2)
    return raw


class FexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pear-fex-build-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def file(self, name, raw):
        path = self.base / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return path

    def test_archive_gnu_names_and_metadata(self):
        path = self.file('gnu.a', archive(('/', b'index'), ('//', b'long-file.cpp.obj/\n'),
                                        ('/0', b'long object'), ('short.obj/', b'short object')))
        rows = archive_members(path)
        self.assertEqual([row['name'] for row in rows], ['long-file.cpp.obj', 'short.obj'])
        self.assertEqual(rows[0]['size_bytes'], len(b'long object'))

    def test_archive_bsd_name_and_payload(self):
        path = self.file('bsd.a', archive(('#1/9', b'entry.objpayload')))
        rows = archive_members(path)
        self.assertEqual(rows[0]['name'], 'entry.obj')
        self.assertEqual(rows[0]['size_bytes'], 7)

    def test_archive_coff_names_and_arm64ec_symbol_metadata(self):
        path = self.file('ec.a', archive(('/', b'first index'), ('/', b'second index'),
            ('//', b'long-file.cpp.obj\0\n'), ('/<ECSYMBOLS>/', b'EC symbol index'),
            ('/0', b'actual object')))
        rows = archive_members(path)
        self.assertEqual([row['name'] for row in rows], ['long-file.cpp.obj'])
        self.assertEqual(rows[0]['size_bytes'], len(b'actual object'))

    def test_archive_replacement_keeps_other_bytes_and_order(self):
        before = archive_members(self.file('old.a', archive(('a.obj/', b'old'), ('memory.obj/', b'prior'))))
        after = archive_members(self.file('new.a', archive(('a.obj/', b'old'), ('memory.obj/', b'fresh'))))
        replacement = fact(self.file('memory.obj', b'fresh'))
        result = verify_archive(before, after, 'memory.obj', replacement)
        self.assertEqual(len(result['unchanged_members']), 1)
        bad = copy.deepcopy(after)
        bad[0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(Error, 'fex_archive_unexpected_member_change'):
            verify_archive(before, bad, 'memory.obj', replacement)
        with self.assertRaisesRegex(Error, 'fex_archive_member_order'):
            verify_archive(before, list(reversed(after)), 'memory.obj', replacement)
        with self.assertRaisesRegex(Error, 'fex_archive_replacement_mismatch'):
            verify_archive(before, after, 'memory.obj', fact(self.file('wrong.obj', b'wrong')))

    def test_archive_missing_duplicate_and_truncated_refuse(self):
        cases = [('thin.a', b'!<thin>\n'), ('truncated.a', archive(('a.obj/', b'object'))[:-2]),
                 ('duplicate.a', archive(('a.obj/', b'one'), ('a.obj/', b'two')))]
        for name, raw in cases:
            with self.subTest(name=name), self.assertRaises(Error):
                archive_members(self.file(name, raw))

    def test_arm64ec_coff_is_distinct_from_outer_pe(self):
        self.assertEqual(coff_machine(self.file('arm64ec.obj', struct.pack('<H', 0xa641) + bytes(18))), 0xa641)
        with self.assertRaisesRegex(Error, 'fex_coff_machine'):
            coff_machine(self.file('amd64.obj', struct.pack('<H', 0x8664) + bytes(18)))
        with self.assertRaisesRegex(Error, 'fex_coff_truncated'):
            coff_machine(self.file('short.obj', bytes(2)))

    def test_pe_requires_valid_chpe_and_executable_entrypoint(self):
        info = pe_info(self.file('valid.dll', synthetic_pe()))
        self.assertEqual(info['machine'], 0x8664)
        self.assertEqual(info['chpe_metadata_version'], 2)
        cases = [('no-chpe', 1224, '<Q', 0, 'fex_pe_chpe_missing'),
                 ('outside-chpe', 1224, '<Q', 0x180009000, 'fex_pe_rva_bounds'),
                 ('data-entry', 168, '<I', 0x3000, 'fex_pe_entrypoint'),
                 ('wrong-machine', 132, '<H', 0xa641, 'fex_pe_machine_or_dll'),
                 ('short-load-config', 1024, '<I', 200, 'fex_pe_load_config_size')]
        for name, offset, fmt, value, error in cases:
            with self.subTest(name=name):
                raw = synthetic_pe()
                struct.pack_into(fmt, raw, offset, value)
                with self.assertRaisesRegex(Error, error):
                    pe_info(self.file(name + '.dll', raw))

    def test_pe_rejects_bad_signature_and_section_bounds(self):
        raw = synthetic_pe()
        raw[128:132] = b'bad!'
        with self.assertRaisesRegex(Error, 'fex_pe_signature'):
            pe_info(self.file('signature.dll', raw))
        raw = synthetic_pe()
        struct.pack_into('<I', raw, 392 + 20, 2000)
        with self.assertRaisesRegex(Error, 'fex_pe_section_bounds'):
            pe_info(self.file('bounds.dll', raw))

    def test_section_changes_are_explicit_not_assumed_debug_only(self):
        original = pe_info(self.file('original.dll', synthetic_pe()))
        raw = synthetic_pe()
        raw[512] ^= 1
        changed = pe_info(self.file('changed.dll', raw))
        result = compare_pe(changed, original)
        self.assertFalse(result['byte_identical'])
        self.assertFalse(next(row['equal'] for row in result['sections'] if row['name'] == '.text'))
        self.assertIn('require_review', result['review'])
        self.assertTrue(compare_pe(original, original)['byte_identical'])

    def test_strip_padding_is_distinct_from_executable_bytes(self):
        original = synthetic_pe()
        struct.pack_into('<I', original, 392 + 8, 4)
        padded = bytearray(original)
        padded[516:1024] = b'\xcc' * 508
        before = pe_info(self.file('before.dll', original))
        after = pe_info(self.file('after.dll', padded))
        result = compare_stripped_text(before, after)
        self.assertTrue(result['virtual_code_unchanged'])
        self.assertFalse(result['raw_section_equal'])
        self.assertEqual(result['after']['padding_values'], [204])
        padded[512] ^= 1
        with self.assertRaisesRegex(Error, 'fex_strip_changed_text'):
            compare_stripped_text(before, pe_info(self.file('bad-code.dll', padded)))
        changed = copy.deepcopy(after)
        next(row for row in changed['sections'] if row['name'] == '.text')['virtual_size'] -= 1
        with self.assertRaisesRegex(Error, 'fex_strip_text_bounds'):
            compare_stripped_text(before, changed)

    def test_pe_resolves_long_section_names_with_bounds(self):
        raw = synthetic_pe()
        strings = b'.debug_fixture\0'
        struct.pack_into('<II', raw, 140, len(raw), 0)
        raw.extend(struct.pack('<I', len(strings) + 4) + strings)
        raw[472:480] = b'/4\0\0\0\0\0\0'
        info = pe_info(self.file('long-name.dll', raw))
        self.assertEqual(info['sections'][2]['name'], '.debug_fixture')
        self.assertEqual(info['sections'][2]['header_name'], '/4')
        raw[472:480] = b'/999\0\0\0\0'
        with self.assertRaisesRegex(Error, 'fex_pe_string_table'):
            pe_info(self.file('bad-name.dll', raw))

    def private_setup(self):
        root = self.base / 'private'
        root.mkdir()
        path = root / 'PearPhaseSelection.h'
        path.write_text('// synthetic fixture only\n')
        row = fact(path)
        manifest = self.file('manifest.json', json.dumps(dict(schema_version=1, root=str(root),
            files=[dict(path=path.name, sha256=row['sha256'], size_bytes=row['size_bytes'])])).encode())
        recipe = dict(schema_version=1, name='synthetic', inputs=[], roots={'private': {'kind': 'private'}},
                      budget={'additional_bytes': 4096, 'floor_bytes': 0})
        return root, path, manifest, recipe, {'roots': {'private': str(root)}}

    def test_private_identity_only_enters_expanded_local_recipe(self):
        root, path, manifest, recipe, bindings = self.private_setup()
        expanded = private_recipe(recipe, bindings, manifest)
        self.assertEqual(recipe['inputs'], [])
        ctx = Context(expanded, bindings, self.base / 'out', lock_path=self.base / 'lock')
        ctx.validate_inputs()
        path.write_text('drift')
        with self.assertRaisesRegex(Error, 'build_input_mismatch'):
            ctx.validate_inputs()

    def test_private_binding_and_git_location_refuse(self):
        root, path, manifest, recipe, bindings = self.private_setup()
        data = json.loads(manifest.read_text())
        data['root'] = str(self.base)
        manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(Error, 'fex_private_binding'):
            private_recipe(recipe, bindings, manifest)
        data['root'] = str(root)
        manifest.write_text(json.dumps(data))
        (self.base / '.git').mkdir()
        with self.assertRaisesRegex(Error, 'fex_private_inside_repository'):
            private_recipe(recipe, bindings, manifest)

    def test_public_recipe_cannot_supply_private_identity(self):
        root, path, manifest, recipe, bindings = self.private_setup()
        recipe['inputs'] = [dict(root='private', path=path.name)]
        with self.assertRaisesRegex(Error, 'fex_public_private_identity'):
            private_recipe(recipe, bindings, manifest)

    def test_path_tokens_reject_absolute_overlay_and_traversal(self):
        for value in ('/old/build/source.cpp', '-ivfsoverlay', {'root': 'fex', 'path': '../outside', 'prefix': ''}):
            with self.subTest(value=value), self.assertRaises(Error):
                bind_token(None, value)
        self.assertEqual(bind_token(None, '-O2'), '-O2')

    def test_relative_manifest_reference_is_absolute_and_aliases_refuse(self):
        path = self.file('recipes/selected.json', b'{}\n')
        with patch('pear_runtime.recipes.fex.Path.cwd', return_value=self.base):
            reference = fact(canonical_input_path('recipes/selected.json'))
        self.assertEqual(reference['path'], str(path))
        self.assertTrue(Path(reference['path']).is_absolute())
        alias = self.base / 'alias'
        alias.symlink_to(path.parent, target_is_directory=True)
        with self.assertRaisesRegex(Error, 'fex_input_alias'):
            canonical_input_path(alias / path.name)
        with self.assertRaisesRegex(Error, 'fex_input_path'):
            canonical_input_path('recipes/../recipes/selected.json')

    def test_wire_export_does_not_expose_full_wine_include_tree(self):
        root = self.base / 'wine'
        source = self.file('wine/include/wine/pear_fex_memory.h', b'// synthetic ABI\n')
        self.file('wine/include/memoryapi.h', b'// unrelated platform header\n')
        identity = fact(source)
        recipe = dict(schema_version=1, name='wire-export', roots={'wine': {'kind': 'input'}},
            inputs=[dict(root='wine', path='include/wine/pear_fex_memory.h',
                         sha256=identity['sha256'], size_bytes=identity['size_bytes'])],
            budget=dict(additional_bytes=4096, floor_bytes=0))
        with Context(recipe, {'wine': str(root)}, self.base / 'out', lock_path=self.base / 'lock') as ctx:
            with self.assertRaisesRegex(Error, 'fex_wire_export_missing'):
                bind_token(ctx, dict(root='output', path='exports/wire', prefix='-I'))
            dest = ctx.copy_input('wine', 'include/wine/pear_fex_memory.h',
                                  'exports/wire/wine/pear_fex_memory.h')
            argument = bind_token(ctx, dict(root='output', path='exports/wire', prefix='-I'))
            self.assertEqual(argument, '-I' + str(ctx.output / 'exports/wire'))
            self.assertFalse((ctx.output / 'exports/wire/memoryapi.h').exists())
            self.assertEqual(ctx._admit_path(dest)['sha256'], identity['sha256'])
            ctx.finish('passed')

    def trace_setup(self):
        roots = {'llvm_mingw': self.base / 'tools', 'inputs': self.base / 'inputs'}
        for path in roots.values():
            path.mkdir()
        library = self.file('tools/lib/libc++.a', b'archive bytes')
        obj = self.file('inputs/link/0.obj', b'object bytes')
        rows = []
        for name, path in (('llvm_mingw', library), ('inputs', obj)):
            ref = fact(path)
            rows.append(dict(root=name, path=path.relative_to(roots[name]).as_posix(),
                             sha256=ref['sha256'], size_bytes=ref['size_bytes']))
        recipe = dict(schema_version=1, name='synthetic-trace', roots={name: {'kind': 'input'} for name in roots},
                      inputs=rows, budget=dict(additional_bytes=4096, floor_bytes=0),
                      toolchain={'implicit_libraries': [{'path': 'lib/libc++.a', 'link_argument': '-lc++'}]})
        return Context(recipe, {k: str(v) for k, v in roots.items()}, self.base / 'out',
                       lock_path=self.base / 'lock'), recipe, library, obj

    def test_trace_checks_actual_archive_member_path(self):
        ctx, recipe, library, obj = self.trace_setup()
        with ctx:
            stdout = ctx.path('trace.stdout')
            stderr = ctx.path('trace.stderr')
            stdout.write_text(str(library) + '(used.obj)\n' + str(obj) + '\n')
            stderr.write_text('')
            command = {'logs': {'stdout': fact(stdout), 'stderr': fact(stderr)}}
            result = link_trace(ctx, command, recipe)
            self.assertEqual(result['implicit_libraries'][0]['actual']['sha256'], fact(library)['sha256'])
            stdout.write_text('lld-link: Reading ' + str(library) + '(used.obj)\nReading ' + str(obj) + '\n')
            self.assertEqual(len(link_trace(ctx, command, recipe)['inputs']), 2)
            stdout.write_text(str(obj) + '\n')
            with self.assertRaisesRegex(Error, 'fex_link_trace_missing_implicit_library'):
                link_trace(ctx, command, recipe)
            stdout.write_text(str(self.file('unknown.a', b'unknown')) + '\n')
            with self.assertRaisesRegex(Error, 'fex_link_trace_unexpected_input'):
                link_trace(ctx, command, recipe)
            ctx.finish('passed')


if __name__ == '__main__':
    unittest.main()
