# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable refusal controls for the migrated graphics evidence boundary.

All bytes and process records here are synthetic. These tests launch no process,
create no live prefix and make no graphics or host-execution claim.
"""
from pathlib import Path
import copy
import hashlib
import struct
import tempfile
import unittest

from pear_runtime.assembly.helpers import PAYLOAD
from pear_runtime.errors import Error
from pear_runtime.fixtures.graphics import check_rendering, render
from pear_runtime.fixtures.graphics.backend import backend


MODULES = ('d3d11.dll', 'dxgi.dll', 'winemetal.dll', 'd3dcompiler_47.dll')
COMPILER_MODULES = ('wined3d.dll', 'ucrtbase.dll', 'kernel32.dll', 'ntdll.dll')
VALIDATION_ENV = {
    'MTL_DEBUG_LAYER': '1',
    'MTL_SHADER_VALIDATION': '1',
    'MTL_SHADER_VALIDATION_DEFAULT_STATE': 'all',
    'MTL_SHADER_VALIDATION_ENABLE_ERROR_REPORTING': '1',
    'PEAR_METAL_PIPELINE_OBSERVE': '1',
}


def shader(entry):
    raw = bytearray(b'DXBC' + bytes(28))
    raw[4:4 + len(entry)] = entry.encode()
    struct.pack_into('<I', raw, 24, len(raw))
    return bytes(raw)


def complete_terminal():
    """Synthetic endpoint values describe the fixture's mathematical contract."""
    lines = ['{"record_kind":"pear_bootstrap_helper"}',
             'PEAR_RENDER_BEGIN version=1 cases=5',
             'PEAR_RENDER_DEVICE level=b000']
    lines.extend(f'PEAR_RENDER_HR operation={name} hr=00000000' for name in render.OPERATIONS)
    for index, name in enumerate(MODULES, 1):
        lines.append(f'PEAR_GRAPHICS_MODULE name={name} base={index * 4096:x} '
                     f'path=C:\\windows\\system32\\{name}')
    for entry, profile in render.SHADERS.items():
        lines.append(f'PEAR_RENDER_SHADER entry={entry} profile={profile} data={shader(entry).hex()}')
    readbacks = [
        ('buffer', 64, 1, 'uint32', struct.pack('<64I', *(5 + n * 66051 for n in range(64)))),
        ('texture_copy', 8, 8, 'rgba8', bytes(c for y in range(8) for x in range(8)
                                           for c in (3 + x * 17, 5 + y * 19, 7 + (x + y) * 11, 255))),
        ('texture_sample', 8, 8, 'rgba8', bytes(c for y in range(8) for x in range(8)
                                             for c in (3 + x * 17, 5 + y * 19, 7 + (x + y) * 11, 255))),
        ('raster', 64, 64, 'rgba8', bytes(c for y in range(64) for x in range(64)
                                       for c in ((0, 255, 0, 255) if 18 <= x <= 45 and 18 <= y <= 45
                                                 else (17, 34, 51, 255)))),
        ('depth', 64, 64, 'rgba8', bytes((255, 0, 0, 255)) * 4096),
        ('blend', 64, 64, 'rgba8', bytes((128, 0, 128, 128)) * 4096),
        ('compute', 64, 1, 'uint32', struct.pack('<64I', *(7 + (n ^ 165) * 3 for n in range(64)))),
    ]
    for name, width, height, fmt, raw in readbacks:
        lines.append(f'PEAR_RENDER_DATA name={name} width={width} height={height} '
                     f'pitch={width * 4} format={fmt} data={raw.hex()}')
    lines.append('PEAR_RENDER_END cases=5 readbacks=7 completed=1')
    return ('\n'.join(lines) + '\n').encode()


class TerminalEvidenceTests(unittest.TestCase):
    def test_complete_terminal_binds_all_readbacks_and_shader_bytes(self):
        result = render.terminal(complete_terminal())
        self.assertEqual(list(result['readbacks']), list(render.NAMES))
        self.assertEqual(result['readbacks']['buffer']['checked_elements'], 64)
        self.assertEqual(result['readbacks']['depth']['checked_elements'], 4096)
        self.assertEqual(result['shaders']['vertex']['sha256'], hashlib.sha256(shader('vertex')).hexdigest())

    def test_missing_failed_or_reordered_operation_is_rejected(self):
        raw = complete_terminal()
        row = b'PEAR_RENDER_HR operation=device hr=00000000\n'
        corrupt = [raw.replace(row, b'', 1), raw.replace(row, row.replace(b'00000000', b'80004005'), 1),
                   raw.replace(row, b'', 1).replace(b'PEAR_RENDER_END', row + b'PEAR_RENDER_END', 1)]
        for data in corrupt:
            with self.subTest(data=data[:100]), self.assertRaises(Error):
                render.terminal(data)

    def test_duplicate_unknown_or_substitute_module_is_rejected(self):
        raw = complete_terminal()
        row = next(line for line in raw.splitlines(keepends=True) if b'name=dxgi.dll' in line)
        for data in (raw.replace(row, row * 2, 1), raw.replace(row, b'UNEXPECTED RECORD\n', 1),
                     raw.replace(b'name=dxgi.dll', b'name=wined3d.dll', 1)):
            with self.subTest(data=data[:100]), self.assertRaises(Error):
                render.terminal(data)

    def test_duplicate_readback_or_shader_is_rejected(self):
        raw = complete_terminal()
        for token in (b'PEAR_RENDER_SHADER entry=vertex ', b'PEAR_RENDER_DATA name=buffer '):
            row = next(line for line in raw.splitlines(keepends=True) if line.startswith(token))
            with self.subTest(token=token), self.assertRaises(Error):
                render.terminal(raw.replace(row, row * 2, 1))

    def test_wrong_shader_profile_length_or_signature_is_rejected(self):
        raw = complete_terminal()
        for data in (raw.replace(b'profile=vs_5_0', b'profile=ps_5_0', 1),
                     raw.replace(shader('vertex').hex().encode(), (shader('vertex') + b'x').hex().encode(), 1),
                     raw.replace(shader('vertex').hex().encode(), (b'FAIL' + shader('vertex')[4:]).hex().encode(), 1)):
            with self.subTest(data=data[:100]), self.assertRaises(Error):
                render.terminal(data)

    def test_oversized_terminal_is_rejected_before_parsing(self):
        with self.assertRaisesRegex(Error, 'render_terminal_bound'):
            render.terminal(b'\n' * (1024 * 1024 + 1))


class SyntheticEvidence:
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        base = Path(self.scratch.name)
        self.run, self.runtime = base / 'run-root', base / 'runtime'
        self.prefix = self.run / 'run/prefix/drive_c/windows/system32'
        self.source = self.runtime / PAYLOAD / 'lib/wine/aarch64-windows'
        self.prefix.mkdir(parents=True)
        self.source.mkdir(parents=True)
        self.value = {'fixtures': {'rendering-original': {'path': 'fixtures/rendering.exe'}}}
        self.record = {
            'fixture_id': 'rendering-original',
            'diagnostic_fixture': {'name': 'rendering-original'},
            'launches': [{'role': 'loader', 'argv': [str(self.runtime / 'wine'), str(self.runtime / 'fixtures/rendering.exe')],
                          'environment': dict(VALIDATION_ENV)}],
            'processes': {'loader': {'identity': {'pid': 123}}},
            'events': {'loader': [{'event': 'image', 'path': str(self.runtime / PAYLOAD / 'lib/wine/aarch64-unix' / name)}
                                 for name in ('winemac.so', 'winemetal.so', 'libarm64ecfex.so')]
                       + [{'event': 'image', 'path': '/System/Library/Frameworks/Metal.framework/Metal'}]},
        }
        stdout = complete_terminal()
        self.terminal = render.terminal(stdout)
        stderr = (b'wine[123:4] Metal API Validation Enabled\n'
                  b'wine[123:5] Metal GPU Validation Enabled\n'
                  b'Pear FEX init ProcessInit.complete: status=00000000\n'
                  b'Pear FEX init ECGate.enter: status=00000000\n'
                  b'Pear FEX init Unaligned.repaired: status=00000000 domain=0 code=-1\n')
        for index, name in enumerate(MODULES + COMPILER_MODULES, 1):
            data = ('synthetic module bytes ' + name).encode()
            (self.source / name).write_bytes(data)
            (self.prefix / name).write_bytes(data)
            stderr += f'Loaded L"C:\\\\windows\\\\system32\\\\{name}" at {index * 4096:x}: builtin\n'.encode()
        vertex = self.terminal['shaders']['vertex']['sha1'][:8]
        compute = self.terminal['shaders']['transform']['sha1'][:8]
        stderr += f'PEAR_METAL_PIPELINE kind=render validation=1 function=vs_{vertex}_variant\n'.encode() * 4
        stderr += f'PEAR_METAL_PIPELINE kind=compute validation=1 function=cs_{compute}_variant\n'.encode()
        self.raw = {('loader', 'stdout'): stdout, ('loader', 'stderr'): stderr}

    def assess(self, *, record=None, raw=None, modules=None):
        return backend(self.run, self.runtime, self.value, record or self.record, raw or self.raw,
                       modules or self.terminal['modules'])

    def with_stderr(self, data):
        return {**self.raw, ('loader', 'stderr'): data}


class BackendEvidenceTests(SyntheticEvidence, unittest.TestCase):
    def test_complete_backend_identity_evidence(self):
        self.assertIsNone(self.assess())

    def test_different_executable_is_rejected(self):
        record = copy.deepcopy(self.record)
        record['launches'][0]['argv'][-1] = str(self.runtime / 'fixtures/substitute.exe')
        with self.assertRaisesRegex(Error, 'translated_fixture_launch'):
            self.assess(record=record)

    def test_validation_banner_from_another_process_is_rejected(self):
        raw = self.with_stderr(self.raw[('loader', 'stderr')].replace(b'wine[123:', b'wine[456:'))
        with self.assertRaisesRegex(Error, 'translated_validation_unobserved'):
            self.assess(raw=raw)

    def test_fex_initialization_and_gate_are_both_required(self):
        for marker in (b'ProcessInit.complete', b'ECGate.'):
            raw = self.with_stderr(self.raw[('loader', 'stderr')].replace(marker, b'absent'))
            with self.subTest(marker=marker), self.assertRaisesRegex(Error, 'translated_fex_unobserved'):
                self.assess(raw=raw)

    def test_required_error_overrides_success_markers(self):
        for error in (b'Exception c0000005', b'Pear FEX assertion:', b'err:sync:',
                      b'failed assertion', b'validation error'):
            raw = self.with_stderr(self.raw[('loader', 'stderr')] + error + b'\n')
            with self.subTest(error=error), self.assertRaisesRegex(Error, 'translated_required_error'):
                self.assess(raw=raw)

    def test_module_fallback_path_is_rejected(self):
        modules = copy.deepcopy(self.terminal['modules'])
        modules['dxgi.dll']['path'] = 'C:\\other\\dxgi.dll'
        with self.assertRaisesRegex(Error, 'translated_module_fallback'):
            self.assess(modules=modules)

    def test_changed_or_absent_loaded_module_is_rejected(self):
        target = self.prefix / 'dxgi.dll'
        target.write_bytes(b'substitute')
        with self.assertRaisesRegex(Error, 'translated_loaded_module_bytes'):
            self.assess()
        target.unlink()
        with self.assertRaisesRegex(Error, 'translated_loaded_module_bytes'):
            self.assess()

    def test_terminal_module_address_must_match_builtin_load(self):
        modules = copy.deepcopy(self.terminal['modules'])
        modules['dxgi.dll']['base'] += 1
        with self.assertRaisesRegex(Error, 'translated_loaded_module_address'):
            self.assess(modules=modules)

    def test_builtin_load_record_is_required(self):
        stderr = self.raw[('loader', 'stderr')].replace(b'dxgi.dll" at', b'other.dll" at')
        with self.assertRaisesRegex(Error, 'translated_loaded_module_address'):
            self.assess(raw=self.with_stderr(stderr))

    def test_each_native_backend_image_is_required_at_current_root(self):
        for name in ('winemac.so', 'winemetal.so', 'libarm64ecfex.so'):
            record = copy.deepcopy(self.record)
            for row in record['events']['loader']:
                if row['path'].endswith(name):
                    row['path'] = str(self.runtime / 'unselected' / name)
            with self.subTest(name=name), self.assertRaisesRegex(Error, 'translated_backend_image_missing'):
                self.assess(record=record)

    def test_metal_image_is_required(self):
        record = copy.deepcopy(self.record)
        record['events']['loader'] = record['events']['loader'][:-1]
        with self.assertRaisesRegex(Error, 'translated_metal_unobserved'):
            self.assess(record=record)


class RenderingBranchTests(SyntheticEvidence, unittest.TestCase):
    def branch(self, *, record=None, raw=None):
        return check_rendering(self.run, self.runtime, self.value, record or self.record,
                               raw or self.raw, self.terminal)

    def test_branch_returns_original_fields_without_full_qualification(self):
        self.assess()
        result = self.branch()
        self.assertEqual(set(result), {'repair_marker_observed', 'readbacks', 'pipelines'})
        self.assertTrue(result['repair_marker_observed'])
        self.assertEqual(result['pipelines']['observed_pipeline_count'], 5)

    def test_branch_refuses_other_fixture(self):
        record = copy.deepcopy(self.record)
        record['diagnostic_fixture']['name'] = 'presentation-original'
        with self.assertRaisesRegex(Error, 'checkpoint_rendering_fixture'):
            self.branch(record=record)

    def test_actual_scalar_repair_marker_is_required(self):
        raw = self.with_stderr(self.raw[('loader', 'stderr')].replace(b'Unaligned.repaired', b'Unaligned.absent'))
        with self.assertRaisesRegex(Error, 'checkpoint_required_repair_marker'):
            self.branch(raw=raw)

    def test_each_validation_setting_is_required(self):
        for key in VALIDATION_ENV:
            record = copy.deepcopy(self.record)
            record['launches'][0]['environment'][key] = 'disabled'
            with self.subTest(key=key), self.assertRaisesRegex(Error, 'checkpoint_validation_settings'):
                self.branch(record=record)

    def test_changed_compiler_dependency_bytes_are_rejected(self):
        for name in COMPILER_MODULES:
            target = self.prefix / name
            original = target.read_bytes()
            target.write_bytes(b'substitute')
            with self.subTest(name=name), self.assertRaisesRegex(Error, 'checkpoint_compiler_bytes'):
                self.branch()
            target.write_bytes(original)

    def test_compiler_dependencies_need_actual_builtin_loads(self):
        for name in COMPILER_MODULES:
            raw = self.with_stderr(self.raw[('loader', 'stderr')].replace(name.encode(), b'other.dll'))
            with self.subTest(name=name), self.assertRaisesRegex(Error, 'checkpoint_compiler_load'):
                self.branch(raw=raw)

    def test_branch_rejects_validation_error(self):
        raw = self.with_stderr(self.raw[('loader', 'stderr')] + b'GPU AddressSanitizer: invalid read\n')
        with self.assertRaisesRegex(Error, 'render_validation_error'):
            self.branch(raw=raw)

    def test_branch_requires_current_shader_pipeline_identity(self):
        raw = self.with_stderr(self.raw[('loader', 'stderr')].replace(b'function=vs_', b'function=other_'))
        with self.assertRaisesRegex(Error, 'render_pipeline_instrumentation_missing'):
            self.branch(raw=raw)


if __name__ == '__main__':
    unittest.main()
