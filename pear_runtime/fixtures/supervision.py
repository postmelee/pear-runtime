# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Captured original Wine supervisor; no new launcher or implicit source root.

Use one synchronous context at a time. The caller owns execution, admission and
cleanup; this module imports source without constructing a host session.
"""
from __future__ import annotations

import ast
import builtins
from contextlib import contextmanager
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import signal
import sys
import threading
import time
from types import SimpleNamespace, ModuleType

from pear_runtime.assembly._common import (decode_json, encoded, read_relative,
                                          relative)
from pear_runtime.assembly.helpers import canonical_directory
from pear_runtime.errors import Error, need
from .admission import prefix_inventory

WINE_HELPERS = ('common', 'prepare', 'toolchain', 'modules', 'abi_review',
                'dynamic_evidence', 'exception_evidence', 'run_fixtures', 'api_runner')
REUSE_PATH = 'tools/dxmt/run_pairing.py'
REUSE_FUNCTIONS = ('local', 'wine_helpers', 'integer', 'failure_detail', 'finish_capture',
                   'cleanup_session', 'launch_recipes', 'validate_launches')
AUDIT_PATH = 'tools/sources/validate_inventory.py'
AUDIT_ALIAS = 'pear_source_audit'
SOURCE_PATHS = frozenset(('tools/wine/' + name + '.py' for name in WINE_HELPERS)) | {
    REUSE_PATH, AUDIT_PATH, 'tools/dxmt/common.py', 'tools/dxmt/build.py',
    'tools/dxmt/pairing_runtime.py', 'tools/wine/signing.py',
    'host/probe/provisioned_probe.py', 'host/probe/hardened_baseline.py'}
BOUNDS = {'grace_ms': 3000, 'terminate_ms': 2000, 'kill_ms': 5000, 'drain_ms': 1000}
STREAM_LIMIT = 2 * 1024**2
LIMIT = 2 * 1024**2
_ACTIVE = threading.Lock()


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _provenance():
    root = Path(__file__).resolve().parents[2]
    name = 'provenance/fixture-provider-import.json'
    raw = read_relative(root, name, LIMIT)
    return decode_json(raw, LIMIT), {'path': str(root / name), 'sha256': _digest(raw),
                                   'size_bytes': len(raw)}


def provenance_ref():
    """Exact current provider manifest input for the caller's producer record."""
    return _provenance()[1]


def _capture(root):
    root = canonical_directory(root)
    document, proof = _provenance()
    rows = document['files']
    need(len(rows) == len(SOURCE_PATHS) and {row['path'] for row in rows} == SOURCE_PATHS,
         'fixture_provider_set')
    captured, refs = {}, {}
    for row in rows:
        name = row['path']; path = root.joinpath(*relative(name))
        need(path.resolve(strict=True) == path and not path.is_symlink(), 'fixture_provider_alias')
        raw = read_relative(root, name, LIMIT)
        need(len(raw) == row['size_bytes'] and _digest(raw) == row['sha256'], 'fixture_provider_changed')
        captured[name] = raw
        refs[name] = {'path': str(path), 'sha256': _digest(raw), 'size_bytes': len(raw)}
    return root, captured, refs, proof


def source_refs(root):
    """Capture all 17 explicit provider files without importing or executing them."""
    return _capture(root)[2]


def _prepare_tree(raw, label):
    """Change only the original module-level path insertion and audit reopening."""
    tree = ast.parse(raw, filename=label)
    wanted = {
        'path_insert': "sys.path.insert(0, str(Path(__file__).resolve().parent))",
        'audit_spec': "_spec = importlib.util.spec_from_file_location('pear_source_audit', REPO / 'tools/sources/validate_inventory.py')",
        'audit_module': '_audit = importlib.util.module_from_spec(_spec)',
        'audit_exec': '_spec.loader.exec_module(_audit)',
    }
    matching = {ast.dump(ast.parse(text).body[0], include_attributes=False): key
                for key, text in wanted.items()}
    seen, body = [], []
    for node in tree.body:
        key = matching.get(ast.dump(node, include_attributes=False))
        if key is None:
            body.append(node)
        else:
            seen.append(key)
            if key == 'audit_module':
                replacement = ast.parse("_audit = sys.modules['pear_source_audit']").body[0]
                body.append(ast.copy_location(replacement, node))
    need(seen == ['path_insert', 'audit_spec', 'audit_module', 'audit_exec'],
         'fixture_provider_audit_seam')
    tree.body = body
    return ast.fix_missing_locations(tree)


def _recheck(root, refs, proof):
    _, _, current, current_proof = _capture(root)
    need(current == refs and current_proof == proof, 'fixture_provider_changed')


def _companion_namespace(root,captured):
    """Bind original script imports to captured bytes without global aliases."""
    common=ModuleType('pear_companion_common')
    common.__file__=str(root/'tools/wine/common.py')
    exec(compile(captured['tools/wine/common.py'],common.__file__,'exec',dont_inherit=True),common.__dict__)
    module=ModuleType('pear_companion_run_fixtures')
    module.__file__=str(root/'tools/wine/run_fixtures.py')
    def original_import(name,globals=None,locals=None,fromlist=(),level=0):
        if name=='common' and level==0:return common
        return builtins.__import__(name,globals,locals,fromlist,level)
    module.__dict__['__builtins__']={**vars(builtins),'__import__':original_import}
    exec(compile(captured['tools/wine/run_fixtures.py'],module.__file__,'exec',dont_inherit=True),module.__dict__)
    return module


@contextmanager
def companion_provider(provider_root,*,provider_ref,source_refs):
    """Child witness binding; importing original observers launches nothing."""
    root,captured,refs,proof=_capture(provider_root)
    need(proof==provider_ref and refs==source_refs,'game_companion_provider_binding')
    try:
        yield _companion_namespace(root,captured)
    except BaseException as primary:
        try:_recheck(root,refs,proof)
        except BaseException as secondary:
            primary.add_note('Companion provider recheck also failed: '+getattr(secondary,'code',type(secondary).__name__))
        raise
    else:_recheck(root,refs,proof)


@contextmanager
def supervision(root):
    """Yield the original (life, helpers) from one fully captured provider.

    No source is reopened by a dynamic loader. The unmodified APISession is the
    sole launcher available through helpers.api; entering this context launches
    nothing. All temporary aliases and sys.path are restored even on failures.
    """
    need(_ACTIVE.acquire(blocking=False), 'fixture_supervision_busy')
    aliases = (*WINE_HELPERS, AUDIT_ALIAS)
    previous = {name: (name in sys.modules, sys.modules.get(name)) for name in aliases}
    previous_path = list(sys.path)
    try:
        root, captured, refs, proof = _capture(root)

        def bound_read(repo, name, limit=8 * 1024**2):
            if Path(repo) == root:
                need(name in captured, 'fixture_provider_undeclared')
                raw = captured[name]
                need(len(raw) <= limit, 'input_size_limit')
                return raw
            return read_relative(repo, name, limit)

        namespace = {'ast': ast, 'importlib': importlib, 'sys': sys, 'Path': Path,
            'SimpleNamespace': SimpleNamespace, 'REPO': root, 'WINE_HELPERS': WINE_HELPERS,
            'Error': Error, 'need': need, 'relative': relative, 'read_relative': bound_read,
            'decode_json': decode_json, 'digest': _digest, 'encoded': encoded, 'fields': fields,
            'os': os, 'time': time, 'signal': signal, 'BOUNDS': dict(BOUNDS),
            'contextmanager': contextmanager}
        tree = ast.parse(captured[REUSE_PATH], filename=str(root / REUSE_PATH))
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in REUSE_FUNCTIONS]
        need(len(nodes) == len(REUSE_FUNCTIONS) and {node.name for node in nodes} == set(REUSE_FUNCTIONS)
             and all(not node.decorator_list or node.name == 'wine_helpers' and len(node.decorator_list) == 1
                     and isinstance(node.decorator_list[0], ast.Name)
                     and node.decorator_list[0].id == 'contextmanager' for node in nodes),
             'memory_wine_supervisor_functions')
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(root / REUSE_PATH), 'exec'), namespace)
        original_local = namespace['local']
        original_local(root / AUDIT_PATH, AUDIT_ALIAS, captured[AUDIT_PATH])

        def captured_local(path, alias, raw=None):
            need(alias in WINE_HELPERS and Path(path) == root / 'tools/wine' / (alias + '.py'),
                 'fixture_provider_module')
            expected = captured['tools/wine/' + alias + '.py']
            need(raw == expected, 'fixture_provider_capture')
            if alias == 'prepare':
                raw = _prepare_tree(raw, str(path))
            return original_local(path, alias, raw)

        namespace['local'] = captured_local
        with namespace['wine_helpers'](root, {name: ref['sha256'] for name, ref in refs.items()}) as helpers:
            helpers.base.STREAM_LIMIT = STREAM_LIMIT
            active=True
            def companion_factory():
                need(active,'game_companion_provider_inactive')
                return _companion_namespace(root,captured)
            # The frontend records these exact refs in its child witness config.
            companion_factory.provider_root=root
            companion_factory.provider_ref=proof
            companion_factory.source_refs=refs
            life = SimpleNamespace(**namespace, source_refs=refs, provenance_ref=proof,
                                   companion_factory=companion_factory)
            try:
                yield life, helpers
            except BaseException as primary:
                try:
                    _recheck(root, refs, proof)
                except BaseException as secondary:
                    primary.add_note('Provider recheck also failed: ' + getattr(secondary, 'code', type(secondary).__name__))
                raise
            else:
                _recheck(root, refs, proof)
            finally:
                active=False
    finally:
        for name, (present, value) in previous.items():
            if present:
                sys.modules[name] = value
            else:
                sys.modules.pop(name, None)
        sys.path[:] = previous_path
        _ACTIVE.release()


def integer(value,low=0,high=2**53-1):
    return type(value) is int and low <= value <= high


def fields(value, names, kind=None):
    need(type(value) is dict and set(value) == set(names), 'memory_wine_run_fields')
    if kind:
        need(type(value['schema_version']) is int and value['schema_version'] == 1
             and value['record_kind'] == kind, 'memory_wine_run_kind')


def environment(work,prefix,nonce,home):
    need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce) is not None,'memory_wine_nonce')
    need(home is None or type(home) is str and home.startswith('/') and '\0' not in home,
         'memory_wine_home')
    value={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TMPDIR':str(work/'tmp'),
        'WINEPREFIX':str(prefix),'WINEDEBUG':'-all','PEAR_BOOTSTRAP_NONCE':nonce,
        'PEAR_BOOTSTRAP_GENERATION':'0'}
    if home is not None:value['HOME']=home
    return value


def loader_environment(base,endpoint,server_pid,nonce):
    path=Path(endpoint)
    need(path.parent.parent==Path('/private/tmp') and '..' not in path.parts
         and path.name=='control' and path.parent.name.startswith('pear-stage3-')
         and integer(server_pid,2,2**31-1),'memory_wine_control_scope')
    return {**base,'PEAR_STAGE3_CONTROL':endpoint,'PEAR_WINE_ABI_FIXTURE':'1',
        'PEAR_BOOTSTRAP_SERVER_PID':str(server_pid),'WINEDLLOVERRIDES':'mscoree=',
        'PEAR_FEX_MEMORY_FIXTURE_NONCE':nonce,'PEAR_FEX_BITMAP_DIAGNOSTICS':'1'}


def assessment_packet(value):
    return {'entrypoints':{'loader':value['entrypoints']['loader'], 'server':value['entrypoints']['server'],
             'ntdll':value['entrypoints']['ntdll_native']},
            'native_images':value['native_images'],'code_publication_policy':'page-wx',
            'arena_capacity':value['baseline_loader_capacity']}
