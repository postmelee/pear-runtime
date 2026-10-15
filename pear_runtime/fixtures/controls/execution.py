# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later AND MIT
"""Original owned Wine session seam for four exact development controls.

Native pairing retains its ordinary ARM64 exit-0 protocol and 39+23 oracles.
Device/presentation retain their translated exit-42 protocol. No saved grant,
ambient historical checkout, game input or runtime qualification is accepted.
"""
from pathlib import Path
from types import SimpleNamespace
from contextlib import contextmanager, redirect_stdout, redirect_stderr
import argparse
import ast
import copy
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid

from pear_runtime.assembly import core
from pear_runtime import build
from pear_runtime.assembly.driver import lease, deadline, BoundedLog, LogBudget
from pear_runtime.assembly._common import decode_json, encoded, read_relative, relative
from pear_runtime.assembly.helpers import PAYLOAD
from pear_runtime.errors import Error, need
from pear_runtime.fixtures import supervision as supervisor
from pear_runtime.fixtures.admission import prefix_inventory
from pear_runtime.fixtures.graphics.backend import backend
from pear_runtime.fixtures.graphics.render import validation
from pear_runtime.fixtures.inputs import fact, read, save, digest
from pear_runtime.fixtures.types import Selection
from pear_runtime.fixtures.driver import interrupts
from .context import ControlsContext, CASES, ARENA_BYTES, descriptor, completed_control_operation
from . import capture as capture_module
from . import pairing, presentation

STREAM_LIMIT = 2*1024**2
METAL_ENV = {'MTL_DEBUG_LAYER': '1', 'MTL_DEBUG_LAYER_ERROR_MODE': 'assert',
             'MTL_DEBUG_LAYER_WARNING_MODE': 'nslog', 'MTL_SHADER_VALIDATION': '1',
             'MTL_SHADER_VALIDATION_FAIL_MODE': 'zerofill',
             'MTL_SHADER_VALIDATION_REPORT_TO_STDERR': '1'}
PIPELINE_ENV = dict(PEAR_METAL_PIPELINE_OBSERVE='1', MTL_SHADER_VALIDATION_DUMP_PIPELINES='1',
                    MTL_SHADER_VALIDATION_DEFAULT_STATE='all', MTL_SHADER_VALIDATION_ENABLE_ERROR_REPORTING='1',
                    MTL_SHADER_VALIDATION_GLOBAL_MEMORY='1', MTL_SHADER_VALIDATION_TEXTURE_USAGE='1')
integer = supervisor.integer
fields = supervisor.fields
digest_bytes = digest


def write_new(path, value):
    path = Path(path)
    need(not path.is_symlink() and not path.exists(), 'destination_exists')
    with path.open('xb') as stream:
        stream.write(encoded(value))


def _nodes(raw, names, label, *, constants=()):
    """Select original definitions from already captured provider bytes only."""
    tree = ast.parse(raw, filename=label)
    selected = []
    found = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            need(not node.decorator_list, 'controls_provider_decorator')
            selected.append(node)
            found.append(node.name)
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in constants:
                selected.append(node)
                found.append(node.targets[0].id)
    need(len(found) == len(names)+len(constants) and set(found) == set(names)|set(constants),
         'controls_provider_function_set')
    return ast.Module(body=selected, type_ignores=[])


def pairing_reader(life, provider):
    path = supervisor.REUSE_PATH
    raw = life.read_relative(provider, path)
    ref = life.source_refs[path]
    need(digest(raw) == ref['sha256'] and len(raw) == ref['size_bytes'], 'controls_pairing_provider_changed')
    namespace = dict(Path=Path, os=os, signal=signal, time=time, uuid=uuid, SimpleNamespace=SimpleNamespace,
                     Error=Error, need=need, decode_json=decode_json, encoded=encoded, digest=digest,
                     fields=pairing.fields, integer=pairing.integer, relative=relative,
                     read_relative=read_relative, write_new=write_new, native_rows=pairing.native_rows,
                     pe_rows=pairing.pe_rows, cleanup_session=life.cleanup_session,
                     validate_launches=life.validate_launches, assessment_packet=supervisor.assessment_packet)
    names = ('environment', 'verify_logs', 'passive_dynamic_observations', 'assess_case', 'run_case')
    constants = ('METAL_ENV', 'TIMEOUT_MS', 'CASE_FIELDS')
    exec(compile(_nodes(raw, names, str(provider/path), constants=constants), str(provider/path), 'exec'), namespace)
    return namespace


def current_helpers(helpers, life, provider):
    """Original translated_pairing mapping-only adapter on captured definitions.

ControlsContext separately binds the selected Wine source header and exact
integrated geometry. No file is reopened through an old repository constant.
"""
    def function(name, function_name, namespace, transform=None):
        path = 'tools/wine/'+name+'.py'
        raw = life.read_relative(provider, path)
        need(digest(raw) == life.source_refs[path]['sha256'], 'controls_pairing_provider_changed')
        tree = _nodes(raw, (function_name,), str(provider/path))
        if transform:
            transform(tree.body[0])
        exec(compile(ast.fix_missing_locations(tree), str(provider/path), 'exec'), namespace)
        return namespace[function_name]

    def mapping_total(node):
        matches = [n for n in ast.walk(node) if isinstance(n, ast.Assign) and len(n.targets) == 1 and
                   isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'total']
        need(len(matches) == 1 and ast.unparse(matches[0].value) == "limits['interior_bytes'] + LIMITS['bytes'] + 65536",
             'translated_dynamic_mapping_expression')
        matches[0].value = ast.Constant(ARENA_BYTES)

    def arena_total(node):
        matches = [(n, i) for n in ast.walk(node) if isinstance(n, ast.Dict)
                   for i, key in enumerate(n.keys) if isinstance(key, ast.Constant) and key.value == 'mapping_bytes']
        need(len(matches) == 1, 'translated_arena_mapping_expression')
        node, index = matches[0]
        need(ast.unparse(node.values[index]) == "limits['interior_bytes'] + limits['alignment'] + dynamic_bytes",
             'translated_arena_mapping_original')
        node.values[index] = ast.Constant(ARENA_BYTES)

    dynamic = dict(vars(helpers.dynamic))
    function('dynamic_evidence', 'validate_budget', dynamic, mapping_total)
    function('dynamic_evidence', '_process', dynamic)
    api = dict(vars(helpers.api))
    api['validate_budget'] = dynamic['validate_budget']
    function('api_runner', 'assess_arena_events', api, arena_total)
    return SimpleNamespace(**{**vars(helpers), 'api': SimpleNamespace(**api), 'dynamic': SimpleNamespace(**dynamic)})


def selected_value(value, case_id):
    need(case_id in CASES, 'controls_case_selection')
    result = copy.deepcopy(value)
    fixture, _ = CASES[case_id]
    result['entrypoints']['fixture_pe'] = result['fixtures'][fixture]['path']
    if case_id == 'native-pairing':
        result['entrypoints']['winemac_native'] = PAYLOAD+'/lib/wine/aarch64-unix/winemac.so'
    return result


def clone_prefix(context, prefix):
    """Original finite copy plus exactly the two admitted module replacements."""
    need(prefix.is_dir() and not prefix.is_symlink() and not list(prefix.iterdir()), 'controls_prefix_not_empty')
    template = context.seed/'run/prefix'
    inventory = context.base['seed_inventory']
    need(prefix_inventory(template) == inventory, 'controls_seed_changed')
    core.checked_ref(context.value['tool_refs']['copy'])
    subprocess.run([context.value['tool_refs']['copy']['path'], '-cRp', str(template)+'/.', str(prefix)],
                   check=True, timeout=30)
    need(prefix_inventory(prefix) == inventory, 'controls_prefix_clone')
    allowed = set()
    for name, row in context.base['modules'].items():
        relative_path = 'drive_c/windows/system32/'+name
        target = prefix/relative_path
        source = core.checked_ref(row['selected_ref'])
        need(fact(target)['sha256'] == row['seed_sha256'], 'controls_module_preimage')
        target.write_bytes(source.read_bytes())
        need(fact(target)['sha256'] == row['selected_ref']['sha256'], 'controls_module_copy')
        allowed.add(relative_path)
    after = prefix_inventory(prefix)
    need([row for row in after if row['path'] not in allowed] ==
         [row for row in inventory if row['path'] not in allowed], 'controls_module_copy_scope')
    need(prefix_inventory(template) == inventory, 'controls_seed_changed')
    return dict(seed_ref=context.base['seed_ref'], inventory_sha256=digest(encoded(inventory)),
                cold_prefix_initialization=False, staged_modules=context.base['modules'])


def _native_pairing(context, runtime, value, output):
    verify_device_input(context)
    work = output/'run'
    work.mkdir(mode=0o700)
    with supervisor.supervision(context.provider_root) as (life, helpers):
        namespace = pairing_reader(life, context.provider_root)
        original_environment = namespace['environment']

        def seeded_environment(folder, prefix, nonce):
            origin = clone_device_prefix(context, prefix)
            registry = prefix/'system.reg'
            before = registry.read_bytes()
            after = without_desktop_menu(before)
            registry.write_bytes(after)
            save(output/'prefix-configuration.json', dict(scope='synthetic_native_pairing_prefix_only',
                 operation='disable_optional_XDG_desktop_menu_autorun', before_sha256=digest(before),
                 after_sha256=digest(after), original_seed_unchanged=digest(encoded(prefix_inventory(
                     Path(context.value['device_ref']['path']).parent/'run/prefix'))) == origin['inventory_sha256'],
                 prefix_origin=origin))
            return original_environment(folder, prefix, nonce)

        namespace['environment'] = seeded_environment
        result, observed = namespace['run_case'](runtime, value, work, current_helpers(helpers, life, context.provider_root))
    return result, observed


def clone_device_prefix(context, prefix):
    device = verify_device_input(context)
    template = Path(context.value['device_ref']['path']).parent/'run/prefix'
    inventory = device['observations']['synthetic_prefix_inventory']
    need(prefix.is_dir() and not prefix.is_symlink() and not list(prefix.iterdir()), 'controls_prefix_not_empty')
    need(prefix_inventory(template) == inventory, 'controls_device_prefix_changed')
    for name,row in context.base['modules'].items():
        need(fact(template/'drive_c/windows/system32'/name)['sha256'] == row['selected_ref']['sha256'],
             'controls_device_selected_module')
    core.checked_ref(context.value['tool_refs']['copy'])
    subprocess.run([context.value['tool_refs']['copy']['path'], '-cRp', str(template)+'/.', str(prefix)],
                   check=True, timeout=30)
    need(prefix_inventory(prefix) == inventory and prefix_inventory(template) == inventory,
         'controls_device_prefix_clone')
    return dict(seed_ref=context.value['device_ref'], inventory_sha256=digest(encoded(inventory)),
                cold_prefix_initialization=False, module_replacement_performed=False,
                selected_modules={name:row['selected_ref'] for name,row in context.base['modules'].items()})


def _authority(output, side, runtime_ref, operation_ref):
    ref = fact(output/side/'control.json')
    value = core.read_ref(ref)
    need(value['passed'] is True and value['runtime_sha256'] == runtime_ref['sha256'] and
         value['operation_ref'] == operation_ref, 'controls_current_authority')
    core.checked_ref(operation_ref)
    return ref


def _error(exc):
    return dict(type=type(exc).__name__, code=getattr(exc, 'code', str(exc)))


def run(context, case_id, output):
    need(type(context) is ControlsContext and callable(context.execution_interval), 'controls_execution_context')
    need(case_id in CASES, 'controls_case_selection')
    with context.execution_interval(output):
        budget = context.storage_admission(output)
        runtime, value = context.begin(case_id, output)
        output = Path(output)
        output.mkdir(mode=0o700)
        save(output/'storage.json', budget)
        control = dict(schema_version=1, scope='development_runtime_controls_run', case_id=case_id,
                       expected_exit=CASES[case_id][1], context_ref=context.ref, runtime_ref=context.base['runtime_ref'],
                       operation_ref=context.base['operation_ref'], profile_ref=context.base['profile_ref'],
                       fixture_ref=context.value['fixture_refs'][case_id], producer_manifest_ref=context.value['producer_manifest_ref'],
                       device_ref=context.value['device_ref'] if case_id == 'native-pairing' else None,
                       status='started', error=None, secondary_errors=[], case_ref=None, before_ref=None, after_ref=None,
                       diagnostic_only=True, runtime_eligible=False, runtime_qualified=False, game_qualified=False)
        save(output/'control.json', control)
        primary = None
        try:
            context.preserve_sources(output)
            context.current_authority(output/'before')
            control['before_ref'] = _authority(output, 'before', context.base['runtime_ref'], context.base['operation_ref'])
            selected = selected_value(value, case_id)
            if case_id == 'native-pairing':
                _native_pairing(context, runtime, selected, output)
            else:
                work = output/'run'
                work.mkdir(mode=0o700)
                prefix = work/'prefix'
                prefix.mkdir(mode=0o700)
                origin = clone_prefix(context, prefix)
                for path in (work/'work', work/'work/tmp'):
                    path.mkdir(mode=0o700)
                result = _translated_session(context, runtime, selected, output, case_id, origin)
                if result['error'] is not None:
                    raise Error(result['error']['code'])
            control['status'] = 'executed'
        except BaseException as exc:
            primary = exc
            control['status'], control['error'] = 'failed', _error(exc)
        finally:
            try:
                context.current_authority(output/'after')
                control['after_ref'] = _authority(output, 'after', context.base['runtime_ref'], context.base['operation_ref'])
            except BaseException as exc:
                if primary is None:
                    primary = exc
                    control['status'], control['error'] = 'failed', _error(exc)
                else:
                    primary.add_note('Current authority after control also failed: '+str(_error(exc)))
                    control['secondary_errors'].append(_error(exc))
            try:
                context.finish()
            except BaseException as exc:
                if primary is None:
                    primary = exc
                    control['status'], control['error'] = 'failed', _error(exc)
                else:
                    primary.add_note('Final control input validation also failed: '+str(_error(exc)))
                    control['secondary_errors'].append(_error(exc))
            try:
                case_path = output/'run/case.json' if case_id == 'native-pairing' else output/'case.json'
                if case_id != 'native-pairing' and case_path.is_file() and not case_path.is_symlink():
                    case = read(case_path)
                    case['authorization_before_after_passed'] = control['before_ref'] is not None and control['after_ref'] is not None
                    save(case_path, case)
                if case_path.is_file() and not case_path.is_symlink():
                    control['case_ref'] = fact(case_path)
            except BaseException as exc:
                if primary is None:
                    primary = exc
                    control['status'], control['error'] = 'failed', _error(exc)
                else:
                    primary.add_note('Control case evidence also failed: '+str(_error(exc)))
                    control['secondary_errors'].append(_error(exc))
            try:
                save(output/'control.json', control)
            except BaseException as exc:
                if primary is None:
                    primary = exc
                else:
                    primary.add_note('Control receipt write also failed: '+str(_error(exc)))
        if primary is not None:
            try:
                save(output/'controls-assessment.json', dict(passed=False, error=_error(primary), game_qualified=False))
            except BaseException as exc:
                primary.add_note('Failure assessment write also failed: '+str(_error(exc)))
            raise primary
        try:
            result = assess(context, output)
        except BaseException as exc:
            save(output/'controls-assessment.json', dict(passed=False, error=_error(exc), game_qualified=False))
            raise
        save(output/'controls-assessment.json', result)
        return result


def verify_device_input(context):
    ref = context.value['device_ref']
    need(ref is not None, 'controls_current_device_required')
    saved = core.read_ref(ref)
    need(saved.get('passed') is True and saved.get('case_id') == 'device' and
         saved.get('scope') == 'development_runtime_control_assessment' and
         saved.get('runtime_ref') == context.base['runtime_ref'], 'controls_current_device_binding')
    output = Path(ref['path']).parent
    need(ref['path'] == str(output/'controls-assessment.json'), 'controls_current_device_path')
    record = read(output/'control.json')
    previous = ControlsContext(record['context_ref'], context.candidate)
    need(previous.value['device_ref'] is None and
         previous.value['producer_manifest_ref'] == context.value['producer_manifest_ref'] and
         previous.base['operation_ref'] == context.base['operation_ref'] and
         previous.base['profile_ref'] == context.base['profile_ref'], 'controls_current_device_input_set')
    previous.admit_record(output, record, context.value['device_operation_ref'], ref)
    actual = assess(previous, output)
    need(actual == saved, 'controls_current_device_changed')
    core.checked_ref(ref)
    return actual


def _native_assessment(context, runtime, value, output):
    device = verify_device_input(context)
    configuration = read(output/'prefix-configuration.json')
    seed = Path(context.value['device_ref']['path']).parent
    registry = (seed/'run/prefix/system.reg').read_bytes()
    need(configuration == dict(scope='synthetic_native_pairing_prefix_only',
         operation='disable_optional_XDG_desktop_menu_autorun', before_sha256=digest(registry),
         after_sha256=digest(without_desktop_menu(registry)), original_seed_unchanged=True,
         prefix_origin=dict(seed_ref=context.value['device_ref'],
                            inventory_sha256=digest(encoded(device['observations']['synthetic_prefix_inventory'])),
                            cold_prefix_initialization=False, module_replacement_performed=False,
                            selected_modules={name:row['selected_ref'] for name,row in context.base['modules'].items()})),
         'translated_pairing_configuration')
    case = read(output/'run/case.json')
    with supervisor.supervision(context.provider_root) as (life, helpers):
        namespace = pairing_reader(life, context.provider_root)
        raw = namespace['verify_logs'](output/'run', case)
        actual = namespace['assess_case'](case, raw, runtime, value, current_helpers(helpers, life, context.provider_root))
    native, diagnostics = pairing.native_rows(raw[('loader', 'stderr')])
    surface = pairing.controls(raw[('loader', 'stderr')])
    pid = case['processes']['loader']['identity']['pid']
    for marker in ('Metal API Validation Enabled', 'Metal GPU Validation Enabled'):
        need(re.search(rb'wine\['+str(pid).encode()+rb':\d+\] '+marker.encode(), diagnostics) is not None,
             'translated_pairing_validation')
    need(not re.search(rb'failed assertion|validation error|Exception c0000005|err:', diagnostics, re.I),
         'translated_pairing_diagnostic_error')
    need(actual['case_count'] == 39 and native['case_count'] == 39 and surface['case_count'] == 23,
         'controls_pairing_complete')
    retained = read(output/'run/assessment.json')
    need(retained == dict(passed=True, error=None, observations=actual), 'translated_pairing_observations')
    return dict(native=actual, surface=surface, diagnostics_sha256=digest(diagnostics), expected_exit=0)


def _translated_assessment(context, runtime, value, output, case_id):
    case, raw = translated_boundary(output, runtime, value, operation_ref=context.base['operation_ref'])
    fixture, expected_exit = CASES[case_id]
    need(case['fixture_id'] == fixture and case['fixture_sha256'] == value['fixtures'][fixture]['sha256'] and
         case['expected_exit'] == expected_exit == 42, 'controls_translated_fixture_binding')
    stderr = raw[('loader', 'stderr')]
    if case_id == 'device':
        modules = device_terminal(raw[('loader', 'stdout')])
        backend(output, runtime, value, case, raw, modules)
        inventory = prefix_inventory(output/'run/prefix')
        for name,row in context.base['modules'].items():
            need(fact(output/'run/prefix/drive_c/windows/system32'/name)['sha256'] == row['selected_ref']['sha256'],
                 'controls_device_selected_module')
        return dict(device_cases=1, expected_exit=42, no_rosetta_in_observed_processes_and_images=True,
                    synthetic_prefix_inventory=inventory)
    parsed = presentation.terminal(raw[('loader', 'stdout')])
    if case_id == 'presentation-original':
        # Original stage_three admits the unreplaced fixture by terminal,
        # backend, exit and scalar-repair marker. The separate frames control
        # owns visible-frame and physical-teardown qualification.
        backend(output, runtime, value, case, raw, parsed['modules'])
        need(b'Unaligned.repaired' in stderr, 'present_original_recovery_missing')
        return dict(frames=parsed['frames'], cycles=parsed['cycles'], expected_exit=42,
                    scalar_repair_observed=True, visible_frame_assessment='unperformed',
                    physical_teardown_assessment='unperformed')
    producer = Path(capture_module.__file__)
    core.checked_ref(context.value['tool_refs']['capture'])
    if case_id == 'presentation-frames':
        windows = [int(w) for w in re.findall(rb'^PEAR_PRESENT_WINDOW window=(\d+) width=\d+ height=\d+ visible=1 title=1 main=1\r?$', stderr, re.M)]
        need(len(windows) == 18, 'present_frame_windows')
        captures = presentation.visible_frames(output, windows, producer)
        observed = presentation.native(stderr, visible_sequences=[row['sequence'] for row in captures])
    else:
        observed = presentation.native(stderr)
        captures = presentation.visible(output, parsed['ready'], observed['window_ids'], producer)
    backend(output, runtime, value, case, raw, parsed['modules'])
    loader = next(row for row in case['launches'] if row['role'] == 'loader')
    for key in ('PEAR_PRESENT_OBSERVE', 'PEAR_METAL_PIPELINE_OBSERVE', 'MTL_SHADER_VALIDATION'):
        need(loader['environment'].get(key) == '1', 'present_observation_policy')
    return dict(native=observed, visible=captures, callbacks=parsed['callbacks'], expected_exit=42)


def assess(context, output):
    need(type(context) is ControlsContext, 'controls_assessment_context')
    output = Path(output)
    control_ref = fact(output/'control.json')
    record = core.read_ref(control_ref)
    runtime, value = context.assessed_runtime(output, record)
    need(record['scope'] == 'development_runtime_controls_run' and record['status'] == 'executed' and
         record['error'] is None and record['secondary_errors'] == [] and record['diagnostic_only'] is True and
         all(record[key] is False for key in ('runtime_eligible', 'runtime_qualified', 'game_qualified')),
         'controls_execution_failed')
    case_id = record['case_id']
    need(record['expected_exit'] == CASES[case_id][1], 'controls_exit_protocol')
    case_path = output/'run/case.json' if case_id == 'native-pairing' else output/'case.json'
    need(record['case_ref'] == fact(case_path), 'controls_case_ref')
    for side in ('before', 'after'):
        need(record[side+'_ref'] == _authority(output, side, context.base['runtime_ref'], context.base['operation_ref']),
             'controls_authority_ref')
    value = selected_value(value, case_id)
    observed = (_native_assessment(context, runtime, value, output) if case_id == 'native-pairing' else
                _translated_assessment(context, runtime, value, output, case_id))
    sources = context.finalize_assessment(output)
    for ref in (control_ref, record['case_ref'], record['before_ref'], record['after_ref']):
        core.checked_ref(ref)
    return dict(passed=True, scope='development_runtime_control_assessment', case_id=case_id,
                context_ref=context.ref, runtime_ref=context.base['runtime_ref'],
                operation_ref=context.base['operation_ref'], profile_ref=context.base['profile_ref'],
                control_ref=control_ref, case_ref=record['case_ref'],
                producer_manifest_ref=context.value['producer_manifest_ref'], producers_ref=sources,
                observations=observed, diagnostic_only=True, full_graphics_qualification=False,
                complete_late_load_coverage=False, runtime_eligible=False, runtime_qualified=False,
                game_qualified=False, distribution_qualified=False)


def device_terminal(raw):
    lines=raw.decode('utf-8').splitlines()
    need(lines and json.loads(lines[0]).get('record_kind')=='pear_bootstrap_helper','translated_bootstrap_record')
    graphics=lines[1:]
    need(graphics and graphics[0]=='PEAR_GRAPHICS_BEGIN suite=device version=1' and
         graphics[-1]=='PEAR_GRAPHICS_END suite=device cases=1 passed=1','translated_terminal_incomplete')
    devices=[r for r in graphics if r.startswith('PEAR_GRAPHICS_DEVICE ')]
    need(len(devices)==1 and re.fullmatch(r'PEAR_GRAPHICS_DEVICE hr=00000000 level=b000 device=0*[1-9a-fA-F][0-9a-fA-F]* context=0*[1-9a-fA-F][0-9a-fA-F]*',devices[0]),'translated_device_failed')
    modules={}
    for line in graphics:
        if not line.startswith('PEAR_GRAPHICS_MODULE '):continue
        m=re.fullmatch(r'PEAR_GRAPHICS_MODULE name=(\S+) base=([0-9a-fA-F]+) path=(.+)',line)
        need(m is not None and m[1] not in modules and int(m[2],16)>0,'translated_module_record')
        modules[m[1].lower()]=dict(base=int(m[2],16),path=m[3])
    need(set(modules)=={'d3d11.dll','dxgi.dll','winemetal.dll'},'translated_module_set')
    need(len([r for r in graphics if r.startswith('PEAR_GRAPHICS_ADAPTER ')])==1 and len(graphics)==7,'translated_device_record_set')
    return modules


def without_desktop_menu(raw):
    """Disable only Wine's optional XDG desktop integration in synthetic tests.

    The original initialized prefix remains unchanged. This is test setup,
    never a waiver of a started process's failure or of the native 39 cases.
    """
    lines=raw.splitlines(keepends=True)
    section=None;removed=[];kept=[]
    for line in lines:
        if line.startswith(b'['):section=line.split(b']',1)[0]+b']'
        if line.startswith(b'"winemenubuilder"='):
            need(section==b'[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices]',
                        'translated_menu_registry_scope')
            need(line.rstrip()==b'"winemenubuilder"="C:\\\\windows\\\\system32\\\\winemenubuilder.exe -a -r"',
                        'translated_menu_registry_value')
            removed.append(line)
        else:kept.append(line)
    need(len(removed)==1,'translated_menu_registry_count')
    return b''.join(kept)


def _translated_logs(root,result):
    observed={};total=0
    need(type(result['logs']) is list and 6<=len(result['logs'])<=70,'memory_wine_log_count')
    for row in result['logs']:
        fields(row,('role','channel','path','sha256','bytes','observed_bytes','eof','write_error'))
        need(type(row['role']) is str and re.fullmatch('(loader|server|sentinel|process-[0-9]{2})',row['role'])
             and row['channel'] in ('stdout','stderr','events'),'memory_wine_log_role')
        key=(row['role'],row['channel'])
        need(key not in observed and row['path']=='.'.join(key)+'.log','memory_wine_log_set')
        raw=read_relative(root,row['path'],STREAM_LIMIT)
        need(integer(row['bytes'],0,STREAM_LIMIT) and integer(row['observed_bytes'],0,STREAM_LIMIT)
             and row['bytes']==row['observed_bytes']==len(raw) and row['eof'] is True
             and row['write_error'] is None and digest_bytes(raw)==row['sha256'],'memory_wine_log_changed')
        if row['channel']=='events':
            need(not raw or raw.endswith(b'\n'),'memory_wine_event_truncation');total+=len(raw)
        observed[key]=raw
    wanted={(role,channel) for role in ('loader','server','sentinel') for channel in ('stdout','stderr')}
    wanted|={(role,'events') for role in result['events']}
    need(set(observed)==wanted and total<=32*1024**2,'memory_wine_log_coverage')
    return observed


def translated_boundary(run,runtime,value,*,operation_ref):
    r=read(run/'case.json')
    need(r['kind']=='translated_graphics_observation' and r['runtime_sha256']==digest((runtime/'runtime.json').read_bytes()),'translated_run_runtime')
    need(r.get('diagnostic_only') is True and r.get('qualification_scope') == 'development_runtime_controls', 'controls_translated_scope')
    need(r['outcome']=='exited' and r['processes']['loader']['exit_code']==42 and
         r['error'] is None and r['stream_error'] is None and r['cleanup_errors']==[],'translated_execution_failed')
    for key in ('cleanup','sentinel_cleanup'):
        c=r[key];need(c['complete'] is True and c['errors']==[] and not c['observation_gap'] and all(c['reaped'].values()),'translated_cleanup_incomplete')
    need(r['sentinel_survived'] is True and r['processes']['sentinel']['exit_code']==0 and r['authorization_before_after_passed'] is True,'translated_ownership_failed')
    for side in ('before','after'):
        c=core.read_ref(fact(run/side/'control.json'))
        need(c['passed'] is True and c['runtime_sha256']==r['runtime_sha256'] and
             c['operation_ref']==operation_ref,'translated_authorization_pair')
    raw=_translated_logs(run/'run',r)
    for role,events in r['events'].items():
        need([json.loads(line) for line in raw[(role,'events')].splitlines()]==events,'translated_events_changed')
    events=[e for rows in r['events'].values() for e in rows]
    native=[e for e in events if 'translation_value' in e]
    need(native and all(e['cpu_type']==16777228 and e['translation_value']==0 and e['translation_error']==0 for e in native),'translated_host_not_native')
    images=[e for e in events if e['event']=='image']
    need(images and all(e['cpu_type']==16777228 for e in images),'translated_image_not_arm64')
    need(any(e['event']=='stage3_guest_exit' and e['exit_code']==42 for e in r['events']['loader']),'translated_guest_exit_missing')
    return r,raw


def _translated_session(context, runtime, value, output, case_id, prefix_origin):
    reuse = context.provider_root
    work = output/'run'
    prefix = work/'prefix'
    sync_diagnostic = memory_diagnostic = False
    fixture = value['fixtures'][case_id]
    result = dict(scope='translated_graphics', kind='translated_graphics_observation',
                  fixture_id=case_id, fixture_sha256=fixture['sha256'], passed=False,
                  runtime_sha256=context.base['runtime_ref']['sha256'], diagnostic_only=True,
                  qualification_scope='development_runtime_controls', expected_exit=42,
                  guest_execution_qualified=False, stage3_complete=False, prefix_origin=prefix_origin)
    with supervisor.supervision(reuse) as (life,helpers):
        nonce=uuid.uuid4().hex;packet=supervisor.assessment_packet(value)
        session=helpers.api.APISession(work,runtime,packet,nonce,suite='api-abi',case_id='first-dispatch')
        env=supervisor.environment(work/'work',prefix,nonce,os.environ.get('HOME'))
        env['WINEDEBUG']='-all,+loaddll,+seh,+module'
        env.update(METAL_ENV)
        if case_id in ('rendering','presentation','rendering-original','presentation-original','presentation-frames'):
            env.update(PEAR_METAL_PIPELINE_OBSERVE='1',MTL_SHADER_VALIDATION_DUMP_PIPELINES='1',MTL_SHADER_VALIDATION_DEFAULT_STATE='all',
                       MTL_SHADER_VALIDATION_ENABLE_ERROR_REPORTING='1',MTL_SHADER_VALIDATION_GLOBAL_MEMORY='1',
                       MTL_SHADER_VALIDATION_TEXTURE_USAGE='1')
        if case_id in ('presentation','presentation-original','presentation-frames'):env['PEAR_PRESENT_OBSERVE']='1'
        if sync_diagnostic:env['WINEDEBUG']='-all,+loaddll,+seh,+sync,+thread'
        if memory_diagnostic:env['WINEDEBUG']='-all,+virtual,+module,+seh'
        paths={k:runtime/v for k,v in value['entrypoints'].items()}
        read_fd=control=None;error=None;outcome='not_started';start=time.monotonic();deadline=start+(30 if sync_diagnostic or memory_diagnostic else 180)
        remaining=lambda cap:max(0,min(cap,deadline-time.monotonic()))
        launches=[]
        capture_diagnostics=None
        def launch(role,args,environment,**kwargs):
            child=session.launch(role,args,environment,**kwargs)
            launches.append({'role':role,'argv':args,'environment':environment,'pid':child.pid});return child
        try:
            graphical=helpers.api.graphical_session()
            need(graphical=={'status':0,'available':True},'translated_graphical_session')
            result['graphical_session']=graphical
            read_fd,control=os.pipe()
            sentinel=launch('sentinel',[str(paths['sentinel']),str(read_fd)],env,pass_fds=(read_fd,))
            os.close(read_fd);read_fd=None
            need(session.wait_for(lambda:b'\n' in session.streams[('sentinel','stdout')]['data'],remaining(5)),'integration_sentinel_start')
            helpers.base.validate_helper(helpers.base.parse_lines(session,'sentinel')[0],'pear_sentinel_ready',sentinel)
            server=launch('server',[str(paths['server']),'-f','-p'],env,event_pipe=True)
            need(session.wait_for(lambda:any(r.get('event')=='server_ready' for r in session.events['server']) or server.exited,remaining(30)) and not server.exited,'integration_server_start')
            loader_env={**env,'PEAR_STAGE3_CONTROL':session.endpoint,'PEAR_WINE_ABI_FIXTURE':'1',
                        'PEAR_BOOTSTRAP_SERVER_PID':str(server.pid),'WINEDLLOVERRIDES':'d3d11,dxgi,d3d10core,winemetal=b;mscoree='}
            session.output=work/'work'
            try:loader=launch('loader',[str(paths['bootstrap_helper']),'--exec-4k',str(paths['loader']),str(paths['fixture_pe'])],loader_env,allowed_paths=[paths['bootstrap_helper'],paths['loader']])
            finally:session.output=work
            # A definitive owner refusal already disproves this fixture. Stop
            # waiting for the known failing unwind path; retain the exact log
            # and use the same owned cleanup/sentinel/authorization checks.
            refusal=None
            capture=None
            if case_id in ('presentation','presentation-original','presentation-frames'):
                from .capture import Capture,FrameCapture
                from .capture_diagnostics import CaptureDiagnostics
                capture=FrameCapture(output) if case_id=='presentation-frames' else Capture(output)
                capture_diagnostics=CaptureDiagnostics(output,loader.pid)
            def finished():
                nonlocal refusal
                stream=session.streams.get(('loader','stderr'),{})
                match=re.search(rb'Pear FEX init (?:ECGate\.(?:enter|fill|exit)|GuestSyscall\.exit): status=(?!00000000)[0-9a-fA-F]{8} domain=\d+ code=-?\d+',
                                bytes(stream.get('data',b''))[-65536:])
                if match: refusal=match.group().decode('ascii')
                if not match:
                    guard=re.search(rb'[^\n]*(?:Pear source guard refused|Pear FEX assertion:)[^\n]*',bytes(stream.get('data',b''))[-65536:])
                    if guard: refusal=guard.group().decode('utf-8',errors='replace')
                if capture is not None:
                    capture_diagnostics.poll(capture,bytes(session.streams.get(('loader','stdout'),{}).get('data',b'')),bytes(stream.get('data',b'')))
                return loader.exited or refusal is not None
            completed=session.wait_for(finished,remaining(180))
            outcome='owner_refused' if refusal else 'exited' if completed else 'timeout'
            result['observed_owner_refusal']=refusal
        except BaseException as exc:error={'type':type(exc).__name__,'code':getattr(exc,'code',str(exc))};outcome='error'
        finally:
            before,cleanup,sentinel_cleanup,logs,survived,cleanup_errors=life.cleanup_session(session,control,read_fd,work)
        result.update(outcome=outcome,error=error,stream_error=session.failure,events=session.events,logs=logs,
                      cleanup=cleanup,sentinel_cleanup=sentinel_cleanup,sentinel_survived=survived,cleanup_errors=cleanup_errors,
                      pre_cleanup=before,elapsed_ms=round((time.monotonic()-start)*1000),launches=launches,
                      registrations=list(session.observer.registrations.values()),signal_observations=session.observer.signal_observations,
                      processes={role:{'identity':child.identity,'exit_code':child.exit_code,'reaped':child.reaped,'allowed_paths':sorted(child.allowed_paths)} for role,child in session.children.items()})
        if capture_diagnostics is not None and (output/'capture-diagnostics.json').is_file():
            result['capture_diagnostics_ref']=fact(output/'capture-diagnostics.json')
        (output/'case.json').write_text(json.dumps(result,indent=2)+'\n')
    result['authorization_before_after_passed'] = False
    save(output/'case.json', result)
    return result


REQUEST_FIELDS = {'schema_version', 'scope', 'descriptor_ref', 'case_id', 'output_name', 'limits'}


def request(path):
    ref = build.fact(Path(path))
    value = core.read_ref(ref)
    need(set(value) == REQUEST_FIELDS and type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['scope'] == 'development_control_verification', 'controls_request_shape')
    need(type(value['case_id']) is str and value['case_id'] in CASES, 'controls_request_case')
    name = value['output_name']
    need(type(name) is str and name and name not in ('.', '..') and
         all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in name), 'controls_request_output')
    limits = value['limits']
    need(type(limits) is dict and set(limits) == {'whole_timeout_seconds', 'worker_log_bytes'} and
         type(limits['whole_timeout_seconds']) is int and 180 <= limits['whole_timeout_seconds'] <= 1800 and
         type(limits['worker_log_bytes']) is int and 1024 <= limits['worker_log_bytes'] <= 16*1024**2,
         'controls_request_limits')
    manifest, base = descriptor(value['descriptor_ref'])
    candidate = Selection(base['candidate'], Path(base['runtime_ref']['path']).parent)
    core.checked_ref(ref)
    return value, ref, manifest, candidate


def review(path):
    value, ref, manifest, candidate = request(path)
    @contextmanager
    def no_execution(output):
        need(False, 'controls_inspection_cannot_execute')
        yield
    context = ControlsContext(value['descriptor_ref'], candidate, no_execution)
    output = context.fresh_output(Path(manifest['output_root'])/value['output_name'])
    operation = output.with_name(output.name+'.controls-operation')
    need(not operation.exists() and not operation.is_symlink(), 'controls_operation_exists')
    if value['case_id'] == 'native-pairing':
        verify_device_input(context)
    storage = context.storage_admission(output)
    plan = dict(schema_version=1, scope='development_control_plan', request_ref=ref,
                descriptor_ref=value['descriptor_ref'], runtime_ref=context.base['runtime_ref'],
                assembly_operation_ref=context.base['operation_ref'], case_id=value['case_id'],
                output=str(output), operation_output=str(operation), limits=value['limits'], storage=storage,
                current_authority_assessed=False, runtime_execution_performed=False, game_qualified=False)
    return value, ref, context, plan


def execute(path):
    """Original lease/deadline/log supervision, with a controls-specific receipt."""
    need(os.getpgrp() == os.getpid(), 'controls_worker_group_required')
    initial, initial_ref, _, _ = request(path)
    started = build.point()
    operation = record = error = None
    entered = False
    try:
        with interrupts(), deadline(initial['limits']['whole_timeout_seconds']), lease() as held:
            value, ref, context, plan = review(path)
            need(ref == initial_ref and value == initial, 'controls_request_changed')
            output, operation = Path(plan['output']), Path(plan['operation_output'])
            operation.mkdir(mode=0o700)
            record = dict(schema_version=1, scope='development_controls_operation', operation_id=str(uuid.uuid4()),
                          status='running', request_ref=ref, plan=plan,
                          worker=dict(pid=os.getpid(), process_group=os.getpgrp(),
                                      interpreter_ref=build.fact(Path(sys.executable).resolve(strict=True)),
                                      interpreter_version=sys.version, argv=list(sys.argv)),
                          lock={**held, 'released':False}, intervals=[], runtime_execution_attempted=False,
                          runtime_execution_performed=False, game_qualified=False)
            build.write_json(operation/'operation.json', record)
            @contextmanager
            def interval(actual):
                nonlocal entered
                need(not entered and Path(actual) == output, 'controls_live_interval_scope')
                core.checked_ref(ref)
                core.checked_ref(value['descriptor_ref'])
                entered = True
                point = build.point()
                try:
                    yield
                finally:
                    record['intervals'].append(build.span('current_authority_owned_execution_cleanup', point))
            context.execution_interval = interval
            budget = LogBudget(value['limits']['worker_log_bytes'])
            with (operation/'stdout.log').open('xb') as stdout, (operation/'stderr.log').open('xb') as stderr:
                with redirect_stdout(BoundedLog(stdout, budget)), redirect_stderr(BoundedLog(stderr, budget)):
                    record['runtime_execution_attempted'] = True
                    result = run(context, value['case_id'], output)
            need(entered and result['passed'] is True, 'controls_operation_incomplete')
            context.finalize_assessment(output)
            core.checked_ref(ref)
            core.checked_ref(value['descriptor_ref'])
            record.update(status='passed', result_ref=build.fact(output/'controls-assessment.json'), timings=context.timings)
    except BaseException as failure:
        error = failure
        if record is not None:
            record.update(status='failed', error=core.failure_details(failure))
        raise
    finally:
        if record is not None:
            evidence_failure = None
            def evidence_error(failure):
                nonlocal evidence_failure
                record.setdefault('evidence_errors', []).append(core.failure_details(failure))
                if error is None and evidence_failure is None:
                    evidence_failure = failure
                    record.update(status='failed', error=core.failure_details(failure))
            record['lock'].update(released=True, release_observed=build.point())
            record['timing'] = build.span('controls_worker_before_final_receipt', started)
            control_path = Path(record['plan']['output'])/'control.json'
            if control_path.is_file():
                try:
                    control = core.read_ref(build.fact(control_path))
                    if control['case_ref'] is not None:
                        case = core.read_ref(control['case_ref'])
                        record['case_ref'] = control['case_ref']
                        record['runtime_execution_performed'] = bool(case.get('launches'))
                        record['cleanup'] = case.get('cleanup')
                        record['sentinel_survived'] = case.get('sentinel_survived')
                    elif entered:
                        record['runtime_execution_performed'] = 'unknown'
                except BaseException as failure:
                    evidence_error(failure)
                    record['runtime_execution_performed'] = 'unknown'
            elif entered:
                record['runtime_execution_performed'] = 'unknown'
            record['logs'] = {}
            for name in ('stdout', 'stderr'):
                log = operation/(name+'.log')
                if log.is_file():
                    try:
                        record['logs'][name] = build.fact(log)
                    except BaseException as failure:
                        evidence_error(failure)
            try:
                build.write_json(operation/'operation.json', record)
            except BaseException as write_error:
                if error is None and evidence_failure is None:
                    raise
                (error if error is not None else evidence_failure).add_note(
                    'Final controls operation receipt write also failed: '+getattr(write_error, 'code', type(write_error).__name__))
            if error is None and evidence_failure is not None:
                raise evidence_failure
    return dict(status='passed', operation_ref=build.fact(operation/'operation.json'),
                result_ref=record['result_ref'], runtime_execution_performed=record['runtime_execution_performed'], game_qualified=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('inspect', 'execute'))
    parser.add_argument('--request', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'inspect':
            result = review(args.request)[3]
        else:
            if os.getpgrp() != os.getpid():
                os.setpgid(0, 0)
            result = execute(args.request)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Exception, KeyboardInterrupt) as failure:
        print(json.dumps(dict(status='failed', error=core.failure_details(failure))), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
