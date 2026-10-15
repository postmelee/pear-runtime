# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit-input development assembly preserving original signing/closure checks.

Planning does not grant permission. assemble() requires a current owned interval
and worker group, captures the supplied profile again, and writes a new candidate.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import copy
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import uuid

from pear_runtime import build
from pear_runtime.errors import Error, need
from . import _byte_readers
from .helpers import BUNDLE, MAIN, PAYLOAD, LIMIT, SourcePack, canonical_directory, signing_helpers

ROLE_PATHS = {
    'fex_pe': PAYLOAD + '/lib/wine/aarch64-windows/xtajit64.dll',
    'wine_pe': PAYLOAD + '/lib/wine/aarch64-windows/ntdll.dll',
    'wine_native': PAYLOAD + '/lib/wine/aarch64-unix/ntdll.so',
    'winemetal': PAYLOAD + '/lib/wine/aarch64-unix/winemetal.so',
    'winemac': PAYLOAD + '/lib/wine/aarch64-unix/winemac.so',
    'win32u': PAYLOAD + '/lib/wine/aarch64-unix/win32u.so',
}
PE_MACHINES = {'fex_pe': 0x8664, 'wine_pe': 0xaa64}
NATIVE_ROLES = frozenset(ROLE_PATHS) - {'fex_pe', 'wine_pe'}
JSON_LIMIT = 64 * 1024**2


def builder_sources():
    root = Path(__file__).resolve().parents[2]
    paths = ('pear_runtime/assembly/core.py', 'pear_runtime/assembly/helpers.py',
             'pear_runtime/assembly/_transport.py', 'pear_runtime/assembly/_common.py',
             'pear_runtime/assembly/_byte_readers.py', 'pear_runtime/build.py',
             'pear_runtime/errors.py', 'pear_runtime/assembly/driver.py',
             'pear_runtime/assembly/__main__.py', 'provenance/assembly-import.json')
    return {path: build.fact(root / path) for path in paths}


@contextmanager
def phase(phases, name):
    started = build.point()
    try: yield
    finally: phases.append(build.span(name, started))


def failure_details(error):
    value = dict(type=type(error).__name__, code=getattr(error, 'code', str(error)))
    if isinstance(error, OSError): value['errno'] = error.errno
    if getattr(error, 'native_error', None) is not None: value['native_error'] = error.native_error
    if getattr(error, 'bound_outcome', None) is not None: value['bound_outcome'] = error.bound_outcome
    if getattr(error, 'evidence_errors', None): value['evidence_errors'] = error.evidence_errors
    return value


def checked_ref(value, *, limit=2 * 1024**3):
    need(type(value) is dict and set(value) == {'path', 'sha256', 'size_bytes'}, 'assembly_reference_shape')
    need(type(value['size_bytes']) is int and 0 <= value['size_bytes'] <= limit and
         type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']),
         'assembly_reference_identity')
    need(type(value['path']) is str, 'assembly_reference_path')
    path = Path(value['path'])
    need(path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink(),
         'assembly_reference_alias')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'assembly_reference_regular_size')
    need(build.fact(path) == value, 'assembly_reference_changed')
    return path


def read_ref(value, *, limit=JSON_LIMIT):
    path = checked_ref(value, limit=limit)
    result = build.load(path)
    need(build.fact(path) == value, 'assembly_record_changed')
    return result


def _operation_record(path):
    """Capture a regular canonical operation record before decoding it."""
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink()
         and path.name == 'operation.json', 'assembly_operation_path')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= JSON_LIMIT, 'assembly_operation_size')
    ref = build.fact(path)
    return read_ref(ref), ref


def _bound_operation(binding, expected_ref=None):
    need(type(binding) is dict and set(binding) == {'path','operation_id'} and
         type(binding['path']) is str and type(binding['operation_id']) is str,
         'assembly_operation_binding')
    try: canonical = str(uuid.UUID(binding['operation_id']))
    except ValueError: raise Error('assembly_operation_binding') from None
    need(canonical == binding['operation_id'], 'assembly_operation_binding')
    if expected_ref is None:
        record, ref = _operation_record(binding['path'])
    else:
        need(type(expected_ref) is dict and expected_ref.get('path') == binding['path'],
             'assembly_operation_reference_binding')
        record, ref = read_ref(expected_ref), expected_ref
    need(type(record) is dict and record.get('schema_version') == 1 and
         record.get('scope') == 'development_candidate_assembly_operation' and
         record.get('operation_id') == binding['operation_id'], 'assembly_operation_identity')
    return record, ref


def completed_operation(runtime_ref, value, operation_ref):
    """Join the inner assembly receipt to its successful final worker record."""
    need(type(operation_ref) is dict, 'assembly_operation_reference_required')
    record, ref = _bound_operation(value.get('assembly_operation'), operation_ref)
    need(record.get('status') == 'passed' and record.get('runtime_ref') == runtime_ref and
         type(record.get('lock')) is dict and record['lock'].get('released') is True,
         'assembly_operation_not_complete')
    plan = record.get('plan')
    need(type(plan) is dict and plan.get('output') == str(Path(runtime_ref['path']).parent) and
         plan.get('operation_output') == str(Path(ref['path']).parent), 'assembly_operation_output_binding')
    return ref


def _build_artifacts(request):
    need(type(request) is dict and set(request) == {'ref', 'recipe_sha256', 'source_commits'},
         'assembly_build_request')
    value = read_ref(request['ref'])
    need(type(value) is dict, 'assembly_build_shape')
    need(value.get('schema_version') == 1 and type(value['schema_version']) is int and
         value.get('scope') == 'development_component_build' and value.get('status') == 'passed' and
         value.get('runtime_eligible') is False and value.get('game_qualified') is False,
         'assembly_build_scope')
    need(value.get('failure') is None and value.get('failure_code') is None,
         'assembly_build_failure')
    need(type(request['recipe_sha256']) is str and re.fullmatch('[0-9a-f]{64}', request['recipe_sha256'])
         and value.get('recipe_sha256') == request['recipe_sha256'], 'assembly_build_recipe')
    commits = {name: row['commit'] for name, row in value['roots'].items() if row['kind'] == 'git'}
    need(type(request['source_commits']) is dict and commits and commits == request['source_commits'],
         'assembly_build_sources')
    need(type(value['commands']) is list and value['commands'] and all(
        type(c['exit_code']) is int and c['exit_code'] == 0 and c.get('error') is None
        for c in value['commands']), 'assembly_build_commands')
    for command in value['commands']:
        need(set(command['logs']) == {'stdout', 'stderr'}, 'assembly_build_logs')
        for ref in command['logs'].values(): checked_ref(ref)
    artifacts = value.get('artifacts')
    need(type(artifacts) is dict and artifacts, 'assembly_build_artifacts')
    root = Path(request['ref']['path']).parent
    for ref in artifacts.values():
        path = checked_ref(ref)
        need(path.is_relative_to(root) and ref in value['outputs'].values(), 'assembly_artifact_output')
    operation, operation_ref = _operation_record(root / 'operation.json')
    need(type(operation) is dict and operation.get('scope') == 'task56_component_build' and
         type(value.get('operation_id')) is str and operation.get('operation_id') == value['operation_id'] and
         operation.get('released') is True, 'assembly_component_operation')
    return value, operation_ref


@dataclass(frozen=True)
class AssemblyInputs:
    parent_ref: dict
    builds: tuple
    roles: tuple
    profile_ref: dict
    helper_root: Path
    output_root: Path
    name: str
    disk_floor_bytes: int = 6 * 1024**3
    review_refs: tuple = ()


def inspect_inputs(inputs):
    """Read-only input and storage plan; no signing, copying or authority grant."""
    need(type(inputs) is AssemblyInputs, 'assembly_inputs_type')
    sources = builder_sources()
    need(type(inputs.review_refs) is tuple, 'assembly_review_refs')
    for ref in inputs.review_refs: checked_ref(ref, limit=JSON_LIMIT)
    output_root = canonical_directory(inputs.output_root)
    need(type(inputs.name) is str and re.fullmatch('[a-z0-9][a-z0-9_-]{0,95}', inputs.name),
         'assembly_output_name')
    output = output_root / inputs.name
    need(not output.exists() and not output.is_symlink(), 'assembly_output_exists')
    need(type(inputs.disk_floor_bytes) is int and inputs.disk_floor_bytes >= 6 * 1024**3,
         'assembly_disk_floor')
    parent = checked_ref(inputs.parent_ref, limit=JSON_LIMIT).parent
    old = read_ref(inputs.parent_ref)
    need(Path(inputs.parent_ref['path']).name == 'runtime.json' and old.get('passed') is True and
         old.get('diagnostic_only') is True and old.get('game_qualified') is False, 'assembly_parent_scope')
    profile = checked_ref(inputs.profile_ref, limit=LIMIT)
    source_pack = SourcePack(inputs.helper_root)
    helpers, reader = signing_helpers(source_pack)
    need(type(inputs.builds) is tuple and inputs.builds, 'assembly_builds_type')
    admitted = [_build_artifacts(request) for request in inputs.builds]
    builds = [row[0] for row in admitted]
    component_operations = [row[1] for row in admitted]
    need(builds and type(inputs.roles) is tuple and inputs.roles and len(set(inputs.roles)) == len(inputs.roles)
         and set(inputs.roles) <= set(ROLE_PATHS), 'assembly_replacement_roles')
    artifacts = {}
    for role in inputs.roles:
        matches = [value['artifacts'][role] for value in builds if role in value['artifacts']]
        need(len(matches) == 1, 'assembly_artifact_owner')
        artifacts[role] = matches[0]
    input_roots = [parent, source_pack.root, profile.parent,
                   *(Path(request['ref']['path']).parent for request in inputs.builds),
                   *(Path(ref['path']).parent for ref in inputs.review_refs)]
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in input_roots),
         'assembly_output_overlaps_input')
    actual = reader.inventory(parent / BUNDLE)
    need(actual == old['bundle_inventory'], 'assembly_parent_inventory')
    before = {BUNDLE + '/' + row['path']: row for row in actual}
    native = [row['path'] for row in old['native_images']]
    need(native and len(set(native)) == len(native) and MAIN in native, 'assembly_native_set')
    for role, ref in artifacts.items():
        path = ROLE_PATHS[role]
        need(path in before and before[path]['kind'] == 'file', 'assembly_replacement_target')
        need((path in native) == (role in NATIVE_ROLES), 'assembly_replacement_kind')
        if role in NATIVE_ROLES:
            need(_byte_readers.inspect_macho(ref['path'])['architectures'] == [_byte_readers.MACH_ARM64],
                 'assembly_replacement_architecture')
        else:
            # Outer machine is only a layout guard; the pinned component recipe
            # owns ARM64EC/ARM64X metadata and paired byte-equivalence checks.
            need(helpers.pe_machine(Path(ref['path']).read_bytes()) == PE_MACHINES[role],
                 'assembly_replacement_pe_machine')
    verify_closure(parent, old, reader)
    bundle_bytes = sum(row['size_bytes'] for row in actual if row['kind'] == 'file')
    growth = sum(max(0, ref['size_bytes'] - before[ROLE_PATHS[role]]['size_bytes']) for role, ref in artifacts.items())
    largest_native = max([before[path]['size_bytes'] for path in native] +
                         [ref['size_bytes'] for role, ref in artifacts.items() if role in NATIVE_ROLES])
    command_count = 5 * (len(native) - 1) + 9 + 3 + 1
    # Bound full logical copy, signed-file rewrite, every command's aggregate
    # stream budget, maximum extracted certificate set and small metadata.
    certificate_bound = (len(native) + 1) * 8 * 128 * 1024
    peak = (bundle_bytes + growth + largest_native + command_count * (LIMIT + 65536)
            + 2 * certificate_bound + (bundle_bytes + growth) // 64 + 4 * 1024**2)
    need(builder_sources() == sources, 'assembly_builder_changed')
    return dict(output=output, parent=parent, old=old, artifacts=artifacts, builds=builds, component_operations=component_operations, builder_sources=sources,
                source_pack=source_pack, helpers=helpers, reader=reader,
                storage=dict(parent_bundle_logical_bytes=bundle_bytes, additional_peak_bytes=peak,
                             disk_floor_bytes=inputs.disk_floor_bytes, signing_command_bound=command_count,
                             size_semantics='Conservative logical estimate for the recorded signing recipe; APFS physical recovery/sharing is not assumed'),
                input_refs=[inputs.parent_ref, inputs.profile_ref, *(r['ref'] for r in inputs.builds), *artifacts.values(), *component_operations, *inputs.review_refs])


def verify_closure(root, value, reader):
    """Original direct_prepare_v1 closure checks with an explicit layout root."""
    actual = reader.inventory(root / BUNDLE)
    need(actual == value['bundle_inventory'], 'direct_inventory')
    files = {BUNDLE + '/' + row['path'] for row in actual if row['kind'] == 'file'}
    paths = [r['path'] for r in value['native_images']]
    need(paths and MAIN in paths and len(set(paths)) == len(paths) and all(
        p in files and str(build.relative(p)) == p and p.startswith(BUNDLE + '/') for p in paths),
        'assembly_closure_paths')
    need([r['path'] for r in value['dependency_closure']] == [r['path'] for r in value['native_images']],
         'assembly_closure_native_set')
    for row in value['dependency_closure']:
        need(_byte_readers.inspect_closure(root / row['path'], root / BUNDLE) == row['images'], 'direct_closure')
        need(all(x['architectures'] == [_byte_readers.MACH_ARM64] for x in row['images']), 'direct_architecture')


def projection(parent, root, old, new, reader, artifacts):
    """Retain the old complete inventory/code-origin projection for declared roles."""
    before = {r['path']: r for r in old['bundle_inventory']}
    after = {r['path']: r for r in reader.inventory(root / BUNDLE)}
    need(set(before) == set(after), 'early_wait_inventory')
    native = {r['path'] for r in old['native_images']}
    replacements = {ROLE_PATHS[role]: ref for role, ref in artifacts.items()}
    changed = []
    for path, row in before.items():
        full = BUNDLE + '/' + path
        if full in replacements:
            need(row['kind'] == after[path]['kind'] == 'file', 'early_wait_file_type')
            if full in native: reader.verify_code_origin(Path(replacements[full]['path']), root / full)
            else: need(build.fact(root / full)['sha256'] == replacements[full]['sha256'], 'early_wait_fex_bytes')
        if row == after[path]: continue
        need(row['kind'] == after[path]['kind'] == 'file', 'early_wait_file_type')
        if full in native:
            reader.verify_code_origin(Path(replacements[full]['path']) if full in replacements else parent / full, root / full)
        elif full in replacements:
            need(build.fact(root / full)['sha256'] == replacements[full]['sha256'], 'early_wait_fex_bytes')
        else: need(path == 'Contents/_CodeSignature/CodeResources', 'early_wait_other_change')
        changed.append(path)
    need([r['path'] for r in old['native_images']] == [r['path'] for r in new['native_images']], 'early_wait_native_set')
    return dict(changed_files=changed, declared_replacements=sorted(replacements),
                replacement_identity_verified=True, undeclared_native_code_unchanged=True,
                note='A deterministic rebuilt input may be byte-identical; every declared replacement is still verified.')


def signing_plan(inputs):
    """Create a reviewable exact recipe after current profile capture at execution.

    The identity comes from a new profile check; this function deliberately does
    not invent an identity from an old authorization record.
    """
    plan = inspect_inputs(inputs)
    return dict(output=str(plan['output']), replacements={role: ref for role, ref in plan['artifacts'].items()},
                storage=plan['storage'], profile_ref=inputs.profile_ref,
                signing_identity='unperformed: resolve by current profile/identity/device capture',
                execution_performed=False, permission_admitted=False)


def assemble(inputs, *, interval, expected_signing_recipe, operation_binding=None):
    """Explicit native operation; caller owns the live interval and worker group."""
    need(callable(interval) and type(expected_signing_recipe) is list and expected_signing_recipe
         and all(type(c) is dict and set(c) == {'id', 'argv'} and type(c['id']) is str
                 and type(c['argv']) is list and all(type(a) is str for a in c['argv'])
                 for c in expected_signing_recipe), 'assembly_execution_bindings')
    need(os.getpgrp() == os.getpid(), 'signing_worker_group_required')
    started = build.point(); phases = []
    with phase(phases, 'prepare_input_admission'):
        plan = inspect_inputs(inputs)
    expected_sources = plan['builder_sources']
    operation, running_operation_ref = _bound_operation(operation_binding)
    need(operation.get('status') == 'running' and operation.get('runtime_ref') is None and
         operation.get('plan', {}).get('output') == str(plan['output']) and
         operation.get('plan', {}).get('operation_output') == str(Path(running_operation_ref['path']).parent) and
         operation.get('worker') == {'pid':os.getpid(), 'process_group':os.getpgrp()} and
         operation.get('lock', {}).get('released') is False, 'assembly_operation_not_live')
    out, parent, old = plan['output'], plan['parent'], plan['old']
    need(shutil.disk_usage(out.parent).free >= plan['storage']['additional_peak_bytes'] + inputs.disk_floor_bytes,
         'assembly_storage')
    value = copy.deepcopy(old)
    value.update(passed=False, commands=[], runtime_eligible=False, runtime_qualified=False,
                 game_qualified=False, execution_authorized_by_this_record=False,
                 builder_sources=expected_sources, assembly_phases=phases, assembly_operation=operation_binding)
    with interval('assembly-sign', out):
        with phase(phases, 'locked_input_admission'):
            plan = inspect_inputs(inputs)
            need(plan['builder_sources'] == expected_sources, 'assembly_builder_changed')
            helpers, reader = plan['helpers'], plan['reader']
            need(shutil.disk_usage(out.parent).free >= plan['storage']['additional_peak_bytes'] + inputs.disk_floor_bytes,
                 'assembly_storage_after_lock')
        out.mkdir(mode=0o700)
        try:
            with phase(phases, 'copy_parent_bundle'):
                copy_argv = ['/bin/cp', '-cRp', str(parent / BUNDLE), str(out / BUNDLE)]
                copy_logs = out / 'logs/bundle-copy'; copy_logs.mkdir(parents=True, mode=0o700)
                value['copy_command'] = dict(argv=copy_argv, logs={}, exit_code=None)
                try:
                    copied = helpers.run_bounded(copy_argv, cwd=out, timeout=60, limit=LIMIT,
                                                 env=helpers.clean_env(), log_directory=copy_logs)
                    value['copy_command'].update({k:copied[k] for k in ('exit_code','timed_out','output_limit','elapsed_ms')})
                    need(copied['exit_code'] == 0, 'assembly_copy_failed')
                finally:
                    value['copy_command']['logs'] = {name:build.fact(copy_logs/name) for name in ('stdout','stderr')
                                                     if (copy_logs/name).is_file()}
            with phase(phases, 'replace_declared_products'):
                for role, ref in plan['artifacts'].items(): shutil.copy2(checked_ref(ref), out / ROLE_PATHS[role])
            with phase(phases, 'current_authorization'):
                authorization, private, raw = helpers.capture_authorization(checked_ref(inputs.profile_ref, limit=LIMIT), out, reader, [])
                need(raw == (out / BUNDLE / 'Contents/embedded.provisionprofile').read_bytes(), 'mismatch_profile')
                entitlement = out / 'authorized-entitlements.plist'
                entitlement.write_bytes(plistlib.dumps(authorization['claims'])); entitlement.chmod(0o600)
            images = copy.deepcopy(old['native_images'])
            replacements = {ROLE_PATHS[role]: ref for role, ref in plan['artifacts'].items()}
            for row in images:
                row['origin'] = replacements[row['path']] if row['path'] in replacements else build.fact(parent / row['path'])
                row['signature'] = None
            with phase(phases, 'sign_and_verify'):
                recipe = helpers.signing_recipe(out, images, private['identity'])
                need(all(c['argv'][:2] == ['/usr/bin/arch', '-arm64'] for c in expected_signing_recipe) and
                     recipe == [(c['id'], c['argv'][2:]) for c in expected_signing_recipe], 'attach_sign_exact_recipe')
                for ident, args in recipe: helpers.native(args, out, ident, value['commands'])
                for row in images:
                    reader.verify_code_origin(Path(row['origin']['path']), out / row['path'])
                    row.update(sha256=build.fact(out / row['path'])['sha256'], size_bytes=(out / row['path']).stat().st_size)
                logs = helpers.verify_commands(out, value['commands'], recipe)
                value['native_images'] = helpers.signatures_from_logs(out, images, logs, authorization['claims'], private, reader, raw)
            with phase(phases, 'final_validation'):
                value['bundle_inventory'] = reader.inventory(out / BUNDLE)
                value['dependency_closure'] = [dict(path=r['path'], images=_byte_readers.inspect_closure(out / r['path'], out / BUNDLE)) for r in images]
                value['authorization_sha256'] = build.fact(out / 'authorization.json')['sha256']
                value['source_ledger'] = [dict(runtime_path=BUNDLE + '/' + row['path'],
                    origin=replacements.get(BUNDLE + '/' + row['path'],
                        dict(path=str(parent / BUNDLE / row['path']), sha256=row['sha256'], size_bytes=row['size_bytes'])))
                    for row in old['bundle_inventory'] if row['kind'] == 'file']
                value['development_assembly'] = dict(schema_version=1, input_runtime=inputs.parent_ref,
                    builds=[request['ref'] for request in inputs.builds], component_operations=plan['component_operations'],
                    profile_ref=inputs.profile_ref, review_refs=list(inputs.review_refs),
                    artifacts=plan['artifacts'], helper_sources=plan['source_pack'].pins,
                    projection=projection(parent, out, old, value, reader, plan['artifacts']),
                    inherited_history='Preserved historical fields; this new artifact is admitted only by development_assembly, not an old candidate grant.',
                    game_qualified=False, execution_performed=False)
                verify_closure(out, value, reader)
                need(reader.inventory(parent / BUNDLE) == old['bundle_inventory'], 'assembly_parent_changed')
                for ref in [*plan['input_refs'], running_operation_ref]: checked_ref(ref)
                plan['source_pack'].capture()
                need(builder_sources() == expected_sources, 'assembly_builder_changed')
                need(shutil.disk_usage(out.parent).free >= inputs.disk_floor_bytes, 'assembly_final_storage')
                value['passed'] = True
        except BaseException as error:
            value['assembly_error'] = failure_details(error)
            raise
        finally:
            value['assembly_timing'] = build.span('assembly_before_receipt_write', started)
            value['receipt_write_started'] = build.point()
            try: build.write_json(out / 'runtime.json', value)
            except BaseException:
                # Preserve the primary failure if the filesystem also refuses
                # its receipt; a successful operation still fails on write error.
                if value.get('assembly_error') is None: raise
    return build.fact(out / 'runtime.json')


def verify_current_authority(runtime_ref, profile_ref, helper_root, output, *, operation_ref=None):
    """Fresh current authorization and signatures; no historical permission replay.

    The caller owns the live fixture interval. Failures after fresh output
    admission retain the original error, completed/failed command logs and times.
    """
    started = build.point(); phases = []
    root = checked_ref(runtime_ref, limit=JSON_LIMIT).parent
    value = read_ref(runtime_ref)
    need(value.get('passed') is True and value.get('diagnostic_only') is True and
         value.get('runtime_qualified') is False and value.get('execution_authorized_by_this_record') is False and
         value.get('game_qualified') is False and 'development_assembly' in value, 'assembly_current_scope')
    operation_ref = completed_operation(runtime_ref, value, operation_ref)
    source_pack = SourcePack(helper_root)
    helpers, reader = signing_helpers(source_pack)
    need(value['development_assembly']['profile_ref'] == profile_ref, 'assembly_current_profile_binding')
    profile = checked_ref(profile_ref, limit=LIMIT)
    output = Path(output)
    need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent
         and not output.exists() and not output.is_symlink()
         and all(not output.is_relative_to(p) and not p.is_relative_to(output)
                 for p in (root, profile.parent, source_pack.root)), 'assembly_authority_output')
    need(os.getpgrp() == os.getpid(), 'signing_worker_group_required')
    output.mkdir(mode=0o700)
    commands = []
    result = dict(passed=False, runtime_sha256=runtime_ref['sha256'], operation_ref=operation_ref, commands=commands, phases=phases,
                  scope='current artifact-specific authority; no runtime or game execution performed')
    try:
        with phase(phases, 'current_input_admission'):
            need(builder_sources() == value['builder_sources'], 'assembly_builder_changed')
            need(source_pack.pins == value['development_assembly']['helper_sources'], 'assembly_helper_binding')
            verify_closure(root, value, reader)
            authorization = read_ref(dict(path=str(root / 'authorization.json'), sha256=value['authorization_sha256'],
                                          size_bytes=(root / 'authorization.json').stat().st_size))
        with phase(phases, 'current_authorization'):
            current, private, raw = helpers.capture_authorization(profile, output, reader, commands)
            need(current['capture']['sha256'] == authorization['capture']['sha256'] and current['claims'] == authorization['claims'],
                 'integration_current_profile_changed')
        with phase(phases, 'current_signatures'):
            recipe = helpers.profile_recipe(output)
            for i, row in enumerate(value['native_images']): recipe += helpers.signature_recipe(root / row['path'], 'current.' + str(i), output)
            recipe += helpers.signature_recipe(root / BUNDLE, 'current.bundle', output)
            for ident, args in recipe[len(helpers.profile_recipe(output)):]: helpers.native(args, output, ident, commands)
            logs = helpers.verify_commands(output, commands, recipe)
            for i, row in enumerate(value['native_images']):
                restricted = row['path'] == MAIN; ident = 'current.' + str(i)
                observed = helpers.signature_from_logs(logs, ident, current['claims'] if restricted else {}, private, reader,
                    helpers.BUNDLE_ID if restricted else helpers.BUNDLE_ID + '.native.' + str(i))
                need(observed == row['signature'], 'integration_signature_changed')
                helpers.signer_leaf(output, ident, private, raw)
            helpers.signature_from_logs(logs, 'current.bundle', current['claims'], private, reader, helpers.BUNDLE_ID)
            helpers.signer_leaf(output, 'current.bundle', private, raw)
        with phase(phases, 'current_final_validation'):
            checked_ref(runtime_ref); checked_ref(profile_ref); checked_ref(operation_ref, limit=JSON_LIMIT); source_pack.capture()
            need(builder_sources() == value['builder_sources'], 'assembly_builder_changed')
            verify_closure(root, value, reader)
        result['passed'] = True
    except BaseException as error:
        result['error'] = failure_details(error)
        raise
    finally:
        result['timing'] = build.span('authority_before_receipt_write', started)
        result['receipt_write_started'] = build.point()
        try: build.write_json(output / 'control.json', result)
        except BaseException:
            if result.get('error') is None: raise
    return result
