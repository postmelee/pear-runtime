# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit complete fixture producer inputs and assess-compatible snapshots.

Manifest: {schema_version:1, scope:'fixture_producer_sources', roots:{runtime:
canonical repository[, fex:canonical repository]}, files:[{root,path,sha256,
size_bytes}]}. Completeness comes from the local Python import graph and named
capture inputs, never a broad historical tree glob or a saved completeness flag.
"""
from __future__ import annotations
import ast
from dataclasses import dataclass
import hashlib
import importlib.util
import os
from pathlib import Path
import sys

from pear_runtime.assembly import core
from pear_runtime.assembly._common import read_relative, relative, encoded
from pear_runtime.errors import need
from . import supervision

ENTRY_MODULES = ('pear_runtime.fixtures.__main__', 'pear_runtime.fixtures.driver', 'pear_runtime.fixtures.direct',
                 'pear_runtime.fixtures.checks', 'pear_runtime.fixtures.context')
DYNAMIC_PATHS = (
    'pear_runtime/assembly/_transport.py',
    'pear_runtime/fixtures/capabilities/d36.json',
    'provenance/assembly-import.json', 'provenance/fixture-provider-import.json',
    'provenance/fixture-context-import.json', 'provenance/fixture-parent-import.json',
    'provenance/fixture-direct-import.json', 'provenance/fixture-graphics-import.json',
    'provenance/fixture-assessment-import.json', 'provenance/fixture-checks-import.json',
)
PROVIDER_PREFIX = 'pear_runtime/providers/pear_legacy/'
FILE_LIMIT = 2 * 1024**2
TOTAL_LIMIT = 32 * 1024**2
MAX_FILES = 512


GAME_SCOPE = 'game_producer_sources'
GAME_ENTRY_MODULES = ('pear_runtime.fixtures.game_operation', 'pear_runtime.fixtures.game_observations', 'pear_runtime.fixtures.direct',
    'tools.development.runtime_candidate', 'tools.development.game.context',
    'tools.development.game.feedback', 'tools.development.game.witness')


def _root_map(roots, *, game=False):
    need(type(roots) is dict and 'runtime' in roots and set(roots) <= ({'runtime','fex','pear'} if game else {'runtime','fex'}) and
         (not game or 'pear' in roots),
         'fixture_producer_roots')
    result = {}
    for key, value in roots.items():
        need(type(value) is str, 'fixture_producer_root')
        path = Path(value)
        need(path.is_absolute() and path.is_dir() and path.resolve(strict=True) == path,
             'fixture_producer_root_alias')
        result[key] = path
    need(result['runtime'] == Path(__file__).resolve().parents[2], 'fixture_producer_runtime_root')
    if 'fex' in result:
        need(not result['fex'].is_relative_to(result['runtime']) and
             not result['runtime'].is_relative_to(result['fex']), 'fixture_producer_root_overlap')
    if 'pear' in result:
        need(all(not result['pear'].is_relative_to(root) and not root.is_relative_to(result['pear'])
                 for name,root in result.items() if name!='pear'),'fixture_producer_root_overlap')
    return result


def _read(root, path):
    target = root.joinpath(*relative(path))
    need(target.resolve(strict=True) == target and not target.is_symlink(), 'fixture_producer_alias')
    raw = read_relative(root, path, FILE_LIMIT)
    return raw, {'path': str(target), 'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)}


def _fex_module(module):
    return (module in ('Pear', 'Pear.Tools') or module == 'Pear.Diagnostics' or
            module.startswith('Pear.Diagnostics.') or module == 'Pear.Tools.CPU' or
            module.startswith('Pear.Tools.CPU.'))


def _pear_module(module):
    return (module in ('tools','tools.development','tools.development.game',
                       'tools.development.runtime_candidate') or
            module.startswith('tools.development.game.'))


def _module_location(module, roots, *, optional=False):
    if module == 'pear_runtime' or module.startswith('pear_runtime.'):
        owner = 'runtime'
    elif _fex_module(module):
        need('fex' in roots, 'fixture_producer_fex_root_required'); owner = 'fex'
    elif _pear_module(module) and 'pear' in roots:
        owner = 'pear'
    elif module=='tools' or module.startswith('tools.'):
        need('pear' not in roots,'game_producer_module_scope')
        return None
    else:
        return None
    name = module.replace('.', '/')
    candidates = [p for p in (name + '.py', name + '/__init__.py') if (roots[owner] / p).is_file()]
    need(len(candidates) <= 1, 'fixture_producer_ambiguous_module')
    if candidates: return owner, candidates[0]
    if owner == 'fex' and module in ('Pear', 'Pear.Diagnostics', 'Pear.Tools', 'Pear.Tools.CPU'): return None
    if owner=='pear' and module in ('tools','tools.development','tools.development.game'):return None
    need(optional, 'fixture_producer_module_missing')
    return None


SCOPES = frozenset(('fixture_producer_sources', 'fixture_controls_producer_sources',
                    'fixture_native_producer_sources', 'fixture_cpu_producer_sources',GAME_SCOPE))


def closure_options(entry_modules, dynamic_paths, scope='fixture_producer_sources'):
    """Code-owned closure entrypoints; descriptors cannot choose their own code."""
    need(type(entry_modules) is tuple and 0 < len(entry_modules) <= 32 and
         len(set(entry_modules)) == len(entry_modules) and
         all(type(name) is str and (name.startswith('pear_runtime.') or scope==GAME_SCOPE and _pear_module(name)) and
             all(part.isidentifier() for part in name.split('.')) for name in entry_modules),
         'fixture_producer_entrypoints')
    need(type(dynamic_paths) is tuple and len(dynamic_paths) <= 128 and
         len(set(dynamic_paths)) == len(dynamic_paths) and
         all(type(path) is str for path in dynamic_paths), 'fixture_producer_dynamic_paths')
    for path in dynamic_paths:
        if scope==GAME_SCOPE and path.startswith('pear:'):
            need(path=='pear:tools/development/game/import-provenance.json','game_producer_dynamic_scope')
            relative(path[5:])
        else:relative(path)
    if scope==GAME_SCOPE:need(entry_modules==GAME_ENTRY_MODULES,'game_producer_entrypoints')
    need(type(scope) is str and scope in SCOPES, 'fixture_producer_scope')


def required_sources(roots, *, entry_modules=ENTRY_MODULES, dynamic_paths=DYNAMIC_PATHS,
                     scope='fixture_producer_sources'):
    """Read the exact current local closure without importing source or writing."""
    closure_options(entry_modules, dynamic_paths, scope)
    roots = _root_map(roots,game=scope==GAME_SCOPE); refs, raw_files, visited = {}, {}, set()
    pending = list(entry_modules)
    while pending:
        module = pending.pop()
        if module in visited: continue
        visited.add(module)
        location = _module_location(module, roots)
        if location is None: continue
        owner, path = location
        raw, ref = _read(roots[owner], path); refs[location] = ref; raw_files[location] = raw
        parts = module.split('.')
        for index in range(1, len(parts)):
            parent = '.'.join(parts[:index])
            if _module_location(parent, roots) is not None: pending.append(parent)
        package = module if path.endswith('/__init__.py') else module.rpartition('.')[0]
        for node in ast.walk(ast.parse(raw, filename=ref['path'])):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if _module_location(alias.name, roots) is not None: pending.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                base = importlib.util.resolve_name('.' * node.level + (node.module or ''), package) if node.level else node.module
                if not base: continue
                if _module_location(base, roots) is not None: pending.append(base)
                if base == 'pear_runtime' or base.startswith('pear_runtime.') or _fex_module(base) or 'pear' in roots and _pear_module(base):
                    for alias in node.names:
                        need(alias.name != '*', 'fixture_producer_star_import')
                        child = base + '.' + alias.name
                        if _module_location(child, roots, optional=True) is not None: pending.append(child)
    dynamic = (*dynamic_paths, *(PROVIDER_PREFIX + p for p in supervision.SOURCE_PATHS))
    for path in dynamic:
        owner='pear' if scope==GAME_SCOPE and path.startswith('pear:') else 'runtime'
        if owner=='pear':path=path[5:]
        location = (owner, path)
        raw_files[location], refs[location] = _read(roots[owner], path)
    need(set(roots) == {owner for owner, _ in refs}, 'fixture_producer_unused_root')
    need(len(refs) <= MAX_FILES and sum(len(v) for v in raw_files.values()) <= TOTAL_LIMIT,
         'fixture_producer_budget')
    return roots, refs, raw_files


def manifest_for_roots(roots, *, entry_modules=ENTRY_MODULES, dynamic_paths=DYNAMIC_PATHS,
                       scope='fixture_producer_sources'):
    """Prepare a reviewable manifest; the caller must pin it before admission."""
    closure_options(entry_modules, dynamic_paths, scope)
    admitted, refs, _ = required_sources(roots, entry_modules=entry_modules, dynamic_paths=dynamic_paths,scope=scope)
    return {'schema_version': 1, 'scope': scope,
            'roots': {k: str(v) for k, v in admitted.items()},
            'files': [dict(root=k[0], path=k[1], sha256=v['sha256'], size_bytes=v['size_bytes'])
                      for k, v in sorted(refs.items())]}


def _loaded_sources(refs):
    allowed = {row['path'] for row in refs.values()}
    for name, module in tuple(sys.modules.items()):
        if name == 'pear_runtime' or name.startswith('pear_runtime.') or _fex_module(name) or any(k[0]=='pear' for k in refs) and _pear_module(name):
            path = getattr(module, '__file__', None)
            if path is not None:
                need(str(Path(path).resolve(strict=True)) in allowed, 'fixture_producer_loaded_source')


@dataclass
class CapturedSources:
    manifest_ref: dict
    roots: dict
    refs: dict
    raw_files: dict
    manifest_bytes: bytes
    entry_modules: tuple = ENTRY_MODULES
    dynamic_paths: tuple = DYNAMIC_PATHS
    scope: str = 'fixture_producer_sources'

    @property
    def logical_bytes(self):
        return sum(len(v) for v in self.raw_files.values()) + len(self.manifest_bytes)

    def recheck(self):
        current = capture(self.manifest_ref, self.roots['runtime'] / PROVIDER_PREFIX,
                          entry_modules=self.entry_modules, dynamic_paths=self.dynamic_paths, scope=self.scope)
        need(current.refs == self.refs and current.manifest_bytes == self.manifest_bytes,
             'direct_producer_changed_during_run')

    def preserve(self, output):
        self.recheck(); output = Path(output)
        need(output.is_absolute() and output.is_dir() and output.resolve(strict=True) == output and
             all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in self.roots.values()),
             'fixture_producer_output')
        target_root = output / 'producer-sources'; target_root.mkdir(mode=0o700)
        rows = []
        items = [(root + '/' + path, ref, self.raw_files[(root, path)]) for (root, path), ref in sorted(self.refs.items())]
        items.append(('manifest.json', self.manifest_ref, self.manifest_bytes))
        for name, original, raw in items:
            target = target_root.joinpath(*relative(name)); target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            need(target.parent.resolve(strict=True) == target.parent, 'fixture_producer_snapshot_alias')
            with target.open('xb') as stream: stream.write(raw)
            target.chmod(0o600)
            snapshot = {'path': str(target), 'sha256': hashlib.sha256(raw).hexdigest(), 'size_bytes': len(raw)}
            need(snapshot['sha256'] == original['sha256'] and snapshot['size_bytes'] == original['size_bytes'],
                 'direct_snapshot_changed')
            rows.append(dict(original=dict(original), snapshot=snapshot))
        with (output / 'producers.json').open('xb') as stream: stream.write(encoded(rows))
        self.recheck()
        return rows


def capture(manifest_ref, provider_root, *, entry_modules=ENTRY_MODULES, dynamic_paths=DYNAMIC_PATHS,
            scope='fixture_producer_sources'):
    closure_options(entry_modules, dynamic_paths, scope)
    value = core.read_ref(manifest_ref)
    need(type(value) is dict and set(value) == {'schema_version', 'scope', 'roots', 'files'} and
         type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['scope'] == scope and type(value['files']) is list and
         0 < len(value['files']) <= MAX_FILES, 'fixture_producer_manifest')
    roots, refs, raw_files = required_sources(value['roots'], entry_modules=entry_modules, dynamic_paths=dynamic_paths,scope=scope)
    need(Path(provider_root) == roots['runtime'] / PROVIDER_PREFIX, 'fixture_producer_provider_binding')
    expected = {}
    for row in value['files']:
        need(type(row) is dict and set(row) == {'root', 'path', 'sha256', 'size_bytes'} and
             row['root'] in roots and type(row['path']) is str, 'fixture_producer_row')
        relative(row['path']); key = (row['root'], row['path'])
        need(key not in expected, 'fixture_producer_duplicate')
        need(type(row['size_bytes']) is int and 0 <= row['size_bytes'] <= FILE_LIMIT and
             type(row['sha256']) is str and len(row['sha256']) == 64 and
             all(c in '0123456789abcdef' for c in row['sha256']), 'fixture_producer_identity')
        expected[key] = {'path': str(roots[row['root']] / row['path']), 'sha256': row['sha256'], 'size_bytes': row['size_bytes']}
    need(expected == refs, 'fixture_producer_incomplete_or_changed')
    # Capture the declared historical provider before execution as well.
    supervision.source_refs(provider_root)
    _loaded_sources(refs)
    manifest_path = core.checked_ref(manifest_ref)
    manifest_bytes = read_relative(manifest_path.parent, manifest_path.name, FILE_LIMIT)
    need(hashlib.sha256(manifest_bytes).hexdigest() == manifest_ref['sha256'] and
         len(manifest_bytes) == manifest_ref['size_bytes'], 'fixture_producer_manifest_changed')
    return CapturedSources(dict(manifest_ref), roots, refs, raw_files, manifest_bytes,
                           entry_modules, dynamic_paths, scope)
