# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable controls for the selected graphics command and dependency policy."""
import copy
import struct
from pathlib import Path
import tempfile
import unittest

from pear_runtime.build import fact
from pear_runtime.errors import Error
from pear_runtime.recipes.graphics import ORDER, audit_graphics_link_map, control_recipe, linked_libraries, validate_plan


def fixture():
    commands = []
    for ident in ORDER:
        metal = ident.startswith('metal-')
        commands.append({'id': ident, 'argv': ['clang', '-mmacosx-version-min=14.0'] if metal else ['clang'],
                         'env': {} if metal else {'MACOSX_DEPLOYMENT_TARGET': '26.5'}})
    commands[1]['argv'][0] = 'clang++'
    commands[1]['argv'].append('-Wl,-objc_stubs_small')
    return {'name': 'task56-graphics-selected-v1', 'driver': 'graphics', 'recipe_version': 1,
            'targets': {'metal': '14.0', 'wine': '26.5'}, 'commands': commands,
            'tool_invocations': {row['id']: {'argv_index': 0, 'lexical_argument': row['argv'][0]} for row in commands},
            'control_inputs': {'{output}/surface/bridge.o': '{inputs}/selected/bridge.o'}}


class GraphicsRecipeTests(unittest.TestCase):
    def test_preserves_distinct_deployment_targets(self):
        validate_plan(fixture())

    def test_rejects_canonicalizing_cxx_driver_to_c(self):
        recipe = fixture()
        recipe['commands'][1]['argv'][0] = 'clang'
        with self.assertRaisesRegex(Error, 'graphics_tool_invocation'):
            validate_plan(recipe)

    def test_dependency_load_command_records_cxx_runtime(self):
        name = b'/usr/lib/libc++.1.dylib\0'
        size = 24 + len(name)
        size = (size + 7) & ~7
        header = struct.pack('<8I', 0xfeedfacf, 0x0100000c, 0, 6, 1, size, 0, 0)
        command = struct.pack('<6I', 0xc, size, 24, 0, 0x10000, 0x10000) + name
        data = header + command.ljust(size, b'\0')
        self.assertEqual(linked_libraries(data)[0]['name'], '/usr/lib/libc++.1.dylib')
        changed = bytearray(data)
        struct.pack_into('<I', changed, 40, size)
        with self.assertRaisesRegex(Error, 'graphics_macho_library_name'):
            linked_libraries(bytes(changed))

    def test_binary_symbol_map_preserves_exact_input_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'one.o').write_bytes(b'object')
            table = b'# Object files:\n[  0] linker synthesized\n[  1] one.o\n'
            original = b'# Arch: arm64\n' + table + b'# Symbols:\nliteral string: \xfe\xed\xfa\xce\n'
            path = root / 'link.map'
            path.write_bytes(original)
            class Context:
                output = root
                def path(self, rel):
                    return root / rel
                def record_output(self, rel):
                    return fact(root / rel)
                def _admit_path(self, path):
                    return fact(path)
            result = audit_graphics_link_map(Context(), path)
            self.assertEqual(Path(result['map']['path']).read_bytes(), table)
            self.assertEqual(result['source_map'], fact(path))
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(len(result['inputs']), 1)

    def test_map_refuses_missing_duplicate_or_malformed_input_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            class Context:
                output = root
                def path(self, rel):
                    return root / rel
                def record_output(self, rel):
                    return fact(root / rel)
            cases = [
                (b'# Symbols:\n', 'graphics_link_map_object_table'),
                (b'# Object files:\n[0] linker synthesized\n', 'graphics_link_map_table_boundary'),
                (b'# Object files:\n# Symbols:\n# Object files:\n', 'graphics_link_map_object_table'),
                (b'# Object files:\n[1] \xfe\n# Symbols:\n', 'graphics_link_map_object_encoding'),
                (b'# Object files:\nunknown input\n# Symbols:\n', 'recipe_link_map_unknown_entry')]
            for index, (raw, expected) in enumerate(cases):
                path = root / ('link' + str(index) + '.map')
                path.write_bytes(raw)
                with self.assertRaisesRegex(Error, expected):
                    audit_graphics_link_map(Context(), path)

    def test_rejects_missing_objc_linker_policy(self):
        recipe = fixture()
        recipe['commands'][1]['argv'].remove('-Wl,-objc_stubs_small')
        with self.assertRaisesRegex(Error, 'graphics_objc_stub_policy'):
            validate_plan(recipe)

    def test_rejects_wine_target_leaking_into_metal(self):
        recipe = fixture()
        recipe['commands'][0]['env']['MACOSX_DEPLOYMENT_TARGET'] = '26.5'
        with self.assertRaisesRegex(Error, 'graphics_metal_target'):
            validate_plan(recipe)

    def test_rejects_reordered_link_dependency(self):
        recipe = fixture()
        recipe['commands'][-1], recipe['commands'][-2] = recipe['commands'][-2], recipe['commands'][-1]
        with self.assertRaisesRegex(Error, 'graphics_recipe_order'):
            validate_plan(recipe)

    def test_control_uses_retained_objects_and_fresh_win32u(self):
        recipe = fixture()
        row = {'id': 'driver-link', 'argv': ['clang', '-o', '{output}/surface/winemac.so',
                 '{output}/surface/bridge.o', '{output}/surface/win32u.so',
                 '-Wl,-map,{output}/surface/driver-link.map']}
        before = copy.deepcopy(row)
        result = control_recipe(recipe, row)
        self.assertEqual(row, before)
        self.assertIn('{inputs}/selected/bridge.o', result['argv'])
        self.assertIn('{output}/surface/control-win32u.so', result['argv'])
        self.assertIn('{output}/surface/control-winemac.so', result['argv'])
        self.assertIn('-Wl,-map,{output}/surface/control-driver-link.map', result['argv'])


if __name__ == '__main__':
    unittest.main()
