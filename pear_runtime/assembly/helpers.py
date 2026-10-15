# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact original signing checks captured from a declared immutable source pack."""
from __future__ import annotations

import ast
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import platform
import plistlib
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

from ._common import (Error, need, relative, read_relative, open_relative,
                      decode_json, record, encoded, sha256)
from . import _byte_readers

BUNDLE_ID = 'io.github.postmelee.pear.wine-loader'
BUNDLE = 'PearWineLoader.app'
PAYLOAD = BUNDLE + '/Contents/Resources/runtime'
MAIN = BUNDLE + '/Contents/MacOS/wine'
SCOPE = 'development_finite_native_memory_owner'
LIMIT = 2 * 1024**2
REUSE_NAMES = {
    'tools/dxmt/common.py': ('digest', 'fields', 'real_directory', 'write_new', 'clean_env'),
    'tools/dxmt/build.py': ('write_bytes',),
    'tools/dxmt/pairing_runtime.py': (
        'same', 'native_error', 'failure_fields', 'wrapped_error', 'certificate_prefix', 'signer_leaf',
        'select_functions', 'source_constant', 'legacy', 'pe_machine', 'cms_plist', 'native', 'verify_commands',
        'profile_recipe', 'profile_from_logs', 'capture_authorization', 'verify_authorization',
        'signature_recipe', 'signature_from_logs', 'signing_recipe', 'signatures_from_logs'),
}
SOURCE_PATHS = frozenset((*REUSE_NAMES, 'tools/wine/signing.py',
                          'host/probe/provisioned_probe.py', 'host/probe/hardened_baseline.py'))


def canonical_directory(value):
    path = Path(value)
    need(path.is_absolute() and path != Path('/') and path.is_dir()
         and path.resolve(strict=True) == path, 'assembly_root_alias')
    return path


class SourcePack:
    """No ambient repository root or caller-supplied replacement source identity."""
    def __init__(self, root):
        self.root = canonical_directory(root)
        provenance = Path(__file__).resolve().parents[2] / 'provenance/assembly-import.json'
        rows = decode_json(provenance.read_bytes(), 2 * 1024**2)['helper_sources']
        need(len(rows) == len(SOURCE_PATHS) and {r['path'] for r in rows} == SOURCE_PATHS,
             'assembly_helper_set')
        self.pins = {r['path']: dict(sha256=r['sha256'], size_bytes=r['size_bytes']) for r in rows}

    def capture(self):
        captured = {}
        for path, expected in self.pins.items():
            target = self.root.joinpath(*relative(path))
            need(target.resolve(strict=True) == target and not target.is_symlink(), 'assembly_helper_alias')
            raw = read_relative(self.root, path, LIMIT)
            need(len(raw) == expected['size_bytes'] and hashlib.sha256(raw).hexdigest() == expected['sha256'],
                 'assembly_helper_changed')
            captured[path] = raw
        return captured


def _selected(raw, names, namespace, label):
    # This is memory_wine_runtime.selected, with a local private function name.
    nodes = [node for node in ast.parse(raw, filename=label).body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    need(len(nodes) == len(names) and {node.name for node in nodes} == set(names)
         and all(not node.decorator_list for node in nodes), 'memory_runtime_reuse_functions')
    exec(compile(ast.Module(body=nodes, type_ignores=[]), label, 'exec'), namespace)


def signing_helpers(source_pack):
    """Retain original authorization/signature bodies and explicit source bindings.

    The source-only pack is mandatory. Its six files are captured and hashed
    before compilation; legacy() reads those captured bytes, closing the gap
    between a preliminary pin check and later dynamic source reads.
    """
    need(type(source_pack) is SourcePack, 'assembly_source_pack')
    captured = source_pack.capture()

    def bound_read(root, path, limit=8 * 1024**2):
        if Path(root) == source_pack.root:
            need(path in captured, 'assembly_undeclared_helper')
            raw = captured[path]
            need(len(raw) <= limit, 'input_size_limit')
            return raw
        return read_relative(root, path, limit)

    namespace = {'REPO': source_pack.root, 'Error': Error, 'need': need, 'relative': relative,
        'read_relative': bound_read, 'open_relative': open_relative, 'decode_json': decode_json, 'record': record,
        'encoded': encoded, 'sha256': sha256, 'Path': Path, 'os': os, 'stat': stat, 're': re,
        'hashlib': hashlib, 'ast': ast, 'datetime': datetime, 'timezone': timezone, 'plistlib': plistlib,
        'platform': platform, 'struct': struct, 'sys': sys, 'time': time, 'uuid': uuid,
        'selectors': selectors, 'signal': signal, 'subprocess': subprocess,
        'SimpleNamespace': SimpleNamespace, 'MACH_ARM64': _byte_readers.MACH_ARM64,
        'MAX_LISTING': 32 * 1024**2, 'LIMIT': LIMIT, 'CERTIFICATE_LIMIT': 128 * 1024,
        'MAX_CERTIFICATES': 8, 'BUNDLE_ID': BUNDLE_ID, 'BUNDLE': BUNDLE, 'MAIN': MAIN,
        'SCOPE': SCOPE, 'ENV': {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C'}}
    _selected(captured['tools/dxmt/common.py'], REUSE_NAMES['tools/dxmt/common.py'], namespace,
              'captured tools/dxmt/common.py')
    byte_namespace = {'relative': relative, 'os': os}
    _selected(captured['tools/dxmt/build.py'], REUSE_NAMES['tools/dxmt/build.py'], byte_namespace,
              'captured tools/dxmt/build.py')
    namespace['stage3'] = SimpleNamespace(write_bytes=byte_namespace['write_bytes'])
    # D36's worker guard and evidence remain; owned child-group cleanup is the
    # explicit lifecycle adaptation. Original modules/default roots stay intact.
    transport = {'Path': Path, 'os': os, 'selectors': selectors, 'subprocess': subprocess,
                 'time': time, 'signal': signal, 'original': SimpleNamespace(Error=Error, need=need),
                 'clean_env': namespace['clean_env']}
    _selected(Path(__file__).with_name('_transport.py').read_bytes(), ('run_bounded',), transport,
              'pear_runtime/assembly/_transport.py')
    namespace['run_bounded'] = transport['run_bounded']
    _selected(captured['tools/dxmt/pairing_runtime.py'], REUSE_NAMES['tools/dxmt/pairing_runtime.py'], namespace,
              'captured tools/dxmt/pairing_runtime.py')
    helpers = SimpleNamespace(**namespace)
    reader = helpers.legacy(source_pack.root)
    return helpers, reader
