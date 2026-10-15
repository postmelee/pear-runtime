# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded exact-input recovery; no build, signing or runtime execution.

Restore a complete, explicitly selected small immutable root and its local
bindings into a fresh output. Historical build provenance is checked separately
from the new binding; a relocated root does not rewrite an old build receipt.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

from . import build
from .assembly import core
from .assembly.driver import validate_recipe_reviews
from .errors import Error, need

MAX_BYTES = 64 * 1024**2
RESERVE_BYTES = 6 * 1024**3
METADATA_ALLOWANCE = 1024**2
REQUEST_KEYS = {'schema_version', 'scope', 'lock_ref', 'component', 'recipe_ref',
                'bindings_ref', 'build_ref', 'runtime_ref', 'operation_ref',
                'input_root', 'output', 'max_output_bytes'}


def _closed(value, keys, code):
    need(type(value) is dict and set(value) == keys, code)


def _identity(ref):
    return {key: ref[key] for key in ('sha256', 'size_bytes')}


def _json_bytes(ref):
    path = core.checked_ref(ref, limit=core.JSON_LIMIT)
    _, raw = build.load(path, with_bytes=True)
    need(len(raw) == ref['size_bytes'] and hashlib.sha256(raw).hexdigest() == ref['sha256']
         and build.fact(path) == ref, 'recovery_metadata_changed')
    return raw


def _sources():
    result = core.builder_sources()
    result['pear_runtime/recovery.py'] = build.fact(Path(__file__).resolve())
    return result


def _context(recipe, bindings, output):
    # No __enter__: this only reuses input admission, never acquires a build
    # lease, creates a build output, or starts a compiler/host child.
    return build.Context(recipe, bindings, output)


def selected_root(recipe, bindings, name, output):
    definitions = recipe.get('roots')
    need(type(name) is str and type(definitions) is dict and name in definitions
         and definitions[name] == {'kind': 'input'}, 'recovery_immutable_root')
    bound = bindings.get('roots', bindings)
    need(type(bound) is dict and name in bound, 'recovery_binding')
    rows = [deepcopy(row) for row in recipe['inputs'] if row['root'] == name]
    need(rows and all(row.get('kind', 'file') == 'file' for row in rows),
         'recovery_regular_root_only')
    # This operation intentionally has no symlink/SDK/toolchain/Git restoration
    # policy. Those complete roots require their own documented recovery path.
    for row in rows:
        need(type(row.get('mode')) is int and 0 <= row['mode'] <= 0o777,
             'recovery_file_mode_required')
    projection = {'schema_version': 1, 'name': 'bounded-input-recovery',
                  'roots': {name: deepcopy(definitions[name])}, 'inputs': rows,
                  'budget': {'additional_bytes': 0, 'floor_bytes': RESERVE_BYTES}}
    ctx = _context(projection, {name: bound[name]}, output)
    return projection, ctx, rows


def inspect(request_path):
    """Validate historical records and an exact small input root, without writes."""
    sources = _sources()
    request_path = Path(request_path)
    request_ref = build.fact(request_path)
    value = core.read_ref(request_ref)
    _closed(value, REQUEST_KEYS, 'recovery_request_shape')
    need(type(value['schema_version']) is int and value['schema_version'] == 1
         and value['scope'] == 'development_input_recovery', 'recovery_request_scope')
    need(value['component'] in ('wine', 'graphics'), 'recovery_component')
    need(type(value['max_output_bytes']) is int
         and 0 < value['max_output_bytes'] <= MAX_BYTES, 'recovery_budget_limit')
    lock = core.read_ref(value['lock_ref'])
    need(type(lock.get('schema_version')) is int and lock['schema_version'] == 1
         and lock.get('scope') == 'task56_development_reconstruction',
         'recovery_lock_scope')
    selected = lock['recipes'][value['component']]
    need(_identity(value['recipe_ref']) == _identity(selected), 'recovery_recipe_lock')
    recipe = core.read_ref(value['recipe_ref'])
    bindings = core.read_ref(value['bindings_ref'])
    pins = {name: row['commit'] for name, row in recipe['roots'].items() if row['kind'] == 'git'}
    need(pins == {name: row['commit'] for name, row in selected['source_roots'].items()},
         'recovery_source_pins')
    build_request = {'ref': value['build_ref'], 'recipe_sha256': selected['sha256'],
                     'source_commits': pins}
    receipt, build_operation_ref = core._build_artifacts(build_request)
    review = {'mode': 'file_sha256', 'public_recipe_ref': value['recipe_ref'],
              'bindings_ref': value['bindings_ref'], 'private_manifest_ref': None}
    validate_recipe_reviews({'inputs': {'builds': [{**build_request, 'recipe_review': review}]}},
                            {'builds': [receipt]})
    runtime = core.read_ref(value['runtime_ref'])
    need(_identity(value['runtime_ref']) == lock['assembly_receipt_identity'] and
         _identity(value['operation_ref']) == lock['operation_receipt_identity'],
         'recovery_candidate_lock')
    need(runtime.get('passed') is True and runtime.get('diagnostic_only') is True
         and runtime.get('runtime_qualified') is False and runtime.get('game_qualified') is False
         and runtime.get('execution_authorized_by_this_record') is False,
         'recovery_candidate_scope')
    core.completed_operation(value['runtime_ref'], runtime, value['operation_ref'])
    need(value['build_ref'] in runtime['development_assembly'].get('builds', []) and
         build_operation_ref in runtime['development_assembly'].get('component_operations', []),
         'recovery_candidate_build')
    candidate_artifacts = runtime['development_assembly']['artifacts']
    for role, ref in receipt['artifacts'].items():
        need(candidate_artifacts.get(role) == ref and _identity(ref) ==
             lock['artifact_identities_before_signing'][role], 'recovery_candidate_artifact')

    output = Path(value['output'])
    need(output.is_absolute() and not output.exists() and not output.is_symlink()
         and output.parent.resolve(strict=True) == output.parent, 'recovery_fresh_output')
    bound = bindings.get('roots', bindings)
    roots = [Path(row['path'] if type(row) is dict else row) for row in bound.values()]
    protected = roots + [Path(value[key]['path']).parent for key in (
        'lock_ref', 'recipe_ref', 'bindings_ref', 'build_ref', 'runtime_ref', 'operation_ref')]
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output)
             for root in protected), 'recovery_output_overlap')
    projection, ctx, rows = selected_root(recipe, bindings, value['input_root'], output)
    payload = sum(row['size_bytes'] for row in rows)
    planned = payload + value['bindings_ref']['size_bytes'] * 2 + request_ref['size_bytes'] + METADATA_ALLOWANCE
    need(planned <= value['max_output_bytes'], 'recovery_budget_exceeded')
    need(shutil.disk_usage(output.parent).free >= planned + RESERVE_BYTES, 'recovery_storage_unavailable')
    ctx.validate_inputs()
    source = {row['path']: build.fact(ctx.input(value['input_root'], row['path'])) for row in rows}
    need(build.fact(request_path) == request_ref, 'recovery_request_changed')
    need(_sources() == sources, 'recovery_producer_changed')
    plan = {'schema_version': 1, 'scope': 'development_input_recovery_plan',
            'request_ref': request_ref, 'component': value['component'],
            'input_root': value['input_root'], 'file_count': len(rows), 'payload_bytes': payload,
            'additional_peak_bytes': planned, 'max_output_bytes': value['max_output_bytes'],
            'reserve_bytes': RESERVE_BYTES, 'output': str(output),
            'historical_source_pins': pins, 'build_operation_ref': build_operation_ref,
            'producer_sources': sources,
            'candidate_runtime_ref': value['runtime_ref'], 'candidate_operation_ref': value['operation_ref'],
            'selected_input_refs': source, 'full_input_pack_restored': False,
            'full_recipe_admission_performed': False, 'current_authority_assessed': False,
            'build_or_runtime_execution_performed': False}
    return value, plan, projection, ctx, rows


def validate_rebound(recipe_ref, bindings_ref, name, unused_output):
    """Read-only exact-root check for a newly restored binding, never build replay."""
    recipe = core.read_ref(recipe_ref)
    bindings = core.read_ref(bindings_ref)
    _, ctx, rows = selected_root(recipe, bindings, name, unused_output)
    ctx.validate_inputs()
    return [build.fact(ctx.input(name, row['path'])) for row in rows]


def _write(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)


def _encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True)+'\n').encode()


def restore(request_path):
    """Copy exact regular input bytes into one fresh, bounded recovery output."""
    value, plan, projection, ctx, rows = inspect(request_path)
    output = Path(plan['output'])
    output.mkdir(mode=0o700)
    try:
        selected = output/'inputs'/value['input_root']
        selected.mkdir(parents=True)
        for row in rows:
            source = ctx.input(value['input_root'], row['path'])
            destination = selected/build.relative(row['path'])
            destination.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                need(stat.S_ISREG(os.fstat(fd).st_mode), 'recovery_input_regular')
                with os.fdopen(fd, 'rb', closefd=False) as stream:
                    raw = stream.read(row['size_bytes']+1)
            finally:
                os.close(fd)
            need(len(raw) == row['size_bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
                 'recovery_copy_identity')
            _write(destination, raw)
            destination.chmod(row['mode'])
        original_bindings = _json_bytes(value['bindings_ref'])
        _write(output/'original-bindings.json', original_bindings)
        need(build.fact(output/'original-bindings.json')['sha256'] == value['bindings_ref']['sha256'],
             'recovery_metadata_copy')
        rebound = deepcopy(core.read_ref(value['bindings_ref']))
        bound = rebound.get('roots', rebound)
        if type(bound[value['input_root']]) is dict:
            bound[value['input_root']]['path'] = str(selected)
        else:
            bound[value['input_root']] = str(selected)
        _write(output/'rebound-bindings.json', _encoded(rebound))
        rebound_ref = build.fact(output/'rebound-bindings.json')
        restored = validate_rebound(value['recipe_ref'], rebound_ref, value['input_root'], output/'unperformed-build')
        # Recheck original bytes and every reviewed metadata record before pass.
        ctx.validate_inputs()
        for key in ('lock_ref', 'recipe_ref', 'bindings_ref', 'build_ref', 'runtime_ref', 'operation_ref'):
            core.checked_ref(value[key])
        need(build.fact(request_path) == plan['request_ref'], 'recovery_request_changed')
        _write(output/'request.json', _json_bytes(plan['request_ref']))
        need(_sources() == plan['producer_sources'], 'recovery_producer_changed')
        result = {**plan, 'scope': 'development_input_recovery_result', 'status': 'passed',
                  'rebound_bindings_ref': rebound_ref, 'restored_input_refs': restored,
                  'original_bindings_copy_ref': build.fact(output/'original-bindings.json'),
                  'historical_build_binding_unchanged': True,
                  'limitation': 'Only this complete declared regular-file input root and exact binding metadata were restored. Rebound paths do not reinterpret historical receipts. A full build still requires clean fixed-commit Git roots and every other admitted input.'}
        raw = _encoded(result)
        need(len(raw) <= METADATA_ALLOWANCE, 'recovery_receipt_size')
        total = sum(path.lstat().st_size for path in output.rglob('*') if path.is_file()) + len(raw)
        need(total <= value['max_output_bytes'], 'recovery_output_budget')
        _write(output/'recovery.json', raw)
        return result
    except BaseException as error:
        failure = {'schema_version': 1, 'scope': 'development_input_recovery_result',
                   'status': 'failed', 'request_ref': plan['request_ref'],
                   'error': core.failure_details(error), 'build_or_runtime_execution_performed': False}
        try:
            _write(output/'recovery-failed.json', _encoded(failure))
        except BaseException as secondary:
            error.recovery_record_error = core.failure_details(secondary)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('inspect', 'restore'):
        child = sub.add_parser(name)
        child.add_argument('--request', type=Path, required=True)
    check = sub.add_parser('check-binding')
    check.add_argument('--recipe', type=Path, required=True)
    check.add_argument('--recipe-sha256', required=True)
    check.add_argument('--recipe-size', type=int, required=True)
    check.add_argument('--bindings', type=Path, required=True)
    check.add_argument('--root', required=True)
    check.add_argument('--unused-output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'inspect':
            result = inspect(args.request)[1]
        elif args.command == 'restore':
            result = restore(args.request)
        else:
            recipe_ref = {'path': str(args.recipe), 'sha256': args.recipe_sha256,
                          'size_bytes': args.recipe_size}
            rows = validate_rebound(recipe_ref, build.fact(args.bindings), args.root, args.unused_output)
            result = {'scope': 'development_input_binding_check', 'passed': True,
                      'selected_input_refs': rows, 'full_recipe_admission_performed': False,
                      'build_or_runtime_execution_performed': False}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Error, OSError, ValueError, KeyError) as error:
        print(json.dumps({'status': 'failed', 'error': core.failure_details(error),
                          'build_or_runtime_execution_performed': False}, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
