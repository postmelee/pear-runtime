# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Four exact controls on an explicit development candidate and synthetic seed.

The seven-fixture descriptor supplies immutable inputs only. This context owns
its case identity, current authority interval, producer closure and assessment.
It requires the common producer API extension; it never falls back to the
seven-fixture admission or a historical worktree.
"""
from pathlib import Path
import inspect
import shutil
import time

from pear_runtime import build
from pear_runtime.assembly import core
from pear_runtime.assembly._common import encoded
from pear_runtime.assembly.helpers import PAYLOAD, SourcePack, signing_helpers
from pear_runtime.errors import need
from pear_runtime.fixtures import producers
from pear_runtime.fixtures.admission import current, prefix_inventory
from pear_runtime.fixtures.context import FIELDS as BASE_FIELDS, capability_binding, inventory_shape
from pear_runtime.fixtures.direct import read_sources
from pear_runtime.fixtures.inputs import fact, read, save
from pear_runtime.fixtures.types import Selection

CASES = {'device': ('device', 42), 'native-pairing': ('pairing', 0),
         'presentation-original': ('presentation-original', 42),
         'presentation-frames': ('presentation-frames', 42)}
FIELDS = {'schema_version', 'scope', 'candidate_context_ref', 'producer_manifest_ref',
          'fixture_refs', 'arena_header_ref', 'arena_source_ref', 'device_ref', 'device_operation_ref',
          'tool_refs', 'output_root'}
ENTRY_MODULES = (*producers.ENTRY_MODULES, 'pear_runtime.fixtures.controls.context',
                 'pear_runtime.fixtures.controls.execution', 'pear_runtime.fixtures.controls.capture')
DYNAMIC_PATHS = (*producers.DYNAMIC_PATHS, 'provenance/fixture-controls-import.json',
                 'provenance/fixture-controls-execution-import.json')
PRODUCER_SCOPE = 'fixture_controls_producer_sources'
ARENA_PATH = 'dlls/ntdll/unix/pear_pe_arena.h'
ARENA_BYTES = 1588985856


def capture(ref, provider):
    """One common closure implementation, with fixed controls-owned options."""
    need('entry_modules' in inspect.signature(producers.capture).parameters,
         'controls_shared_producer_api_pending')
    return producers.capture(ref, provider, entry_modules=ENTRY_MODULES,
                             dynamic_paths=DYNAMIC_PATHS, scope=PRODUCER_SCOPE)


def canonical_directory(path):
    need(type(path) is str, 'controls_directory')
    result = Path(path)
    need(result.is_absolute() and result.is_dir() and result.resolve(strict=True) == result,
         'controls_directory_alias')
    return result


def _arena(value, runtime):
    header = core.checked_ref(value['arena_header_ref'])
    source = core.read_ref(value['arena_source_ref'])
    source_path = core.checked_ref(value['arena_source_ref'])
    need(source_path.name == 'source-manifest.json' and source_path.parent.name == 'pear' and
         header == source_path.parent.parent / ARENA_PATH and source['component'] == 'pear-wine',
         'controls_arena_source_binding')
    selected = [row for row in source['selected_files'] if row['path'] == ARENA_PATH]
    need(len(selected) == 1 and selected[0]['sha256'] == value['arena_header_ref']['sha256'] and
         selected[0]['size_bytes'] == value['arena_header_ref']['size_bytes'] and
         '_Static_assert(PEAR_ARENA_MAPPING_BYTES == UINT64_C(1588985856)' in header.read_text() and
         runtime['baseline_loader_capacity']['integrated_jit_mapping_bytes'] == ARENA_BYTES,
         'controls_arena_mapping_source')
    # The selected header is an oracle geometry input, not a claim that the
    # historical baseline capacity record names this newer source revision.
    wine = [core.read_ref(ref) for ref in runtime['development_assembly']['builds']]
    wine = [row for row in wine if 'wine_native' in row.get('artifacts', {})]
    need(len(wine) == 1 and wine[0]['status'] == 'passed' and
         wine[0]['roots']['wine']['kind'] == 'git' and
         Path(wine[0]['roots']['wine']['path']) == source_path.parent.parent and
         wine[0]['artifacts']['wine_native'] == runtime['development_assembly']['artifacts']['wine_native'],
         'controls_arena_owner')


def descriptor(ref):
    value = core.read_ref(ref)
    need(set(value) == FIELDS and type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['scope'] == 'development_runtime_controls', 'controls_context_shape')
    base = core.read_ref(value['candidate_context_ref'])
    need(set(base) == BASE_FIELDS and type(base['schema_version']) is int and base['schema_version'] == 1 and
         base['scope'] == 'redistributable_runtime_fixtures' and base['candidate'] == 'd25-game',
         'controls_candidate_input_shape')
    # The old producer manifest remains an origin record, never current code
    # authority. The controls closure separately captures the current producers.
    for name in ('runtime_ref', 'operation_ref', 'profile_ref', 'capabilities_ref',
                 'producer_manifest_ref', 'seed_ref'):
        core.checked_ref(base[name])
    for name in ('producer_manifest_ref', 'arena_header_ref', 'arena_source_ref'):
        core.checked_ref(value[name])
    if value['device_ref'] is not None:
        core.checked_ref(value['device_ref'])
        core.checked_ref(value['device_operation_ref'])
    else:
        need(value['device_operation_ref'] is None, 'controls_device_operation_binding')
    need(type(value['fixture_refs']) is dict and set(value['fixture_refs']) == set(CASES),
         'controls_fixture_set')
    for row in value['fixture_refs'].values():
        core.checked_ref(row)
    need(type(value['tool_refs']) is dict and set(value['tool_refs']) == {'copy', 'capture'},
         'controls_tool_set')
    for role, path in (('copy', '/bin/cp'), ('capture', '/usr/sbin/screencapture')):
        need(value['tool_refs'][role]['path'] == path, 'controls_tool_path')
        core.checked_ref(value['tool_refs'][role])
    for key in ('seed_root', 'provider_root'):
        canonical_directory(base[key])
    output = canonical_directory(value['output_root'])
    inventory_shape(base['seed_inventory'])
    need(type(base['modules']) is dict and set(base['modules']) == {'ntdll.dll', 'xtajit64.dll'},
         'controls_modules')
    for row in base['modules'].values():
        need(type(row) is dict and set(row) == {'seed_sha256', 'selected_ref'} and
             type(row['seed_sha256']) is str and len(row['seed_sha256']) == 64 and
             all(c in '0123456789abcdef' for c in row['seed_sha256']), 'controls_module_shape')
        core.checked_ref(row['selected_ref'])
    runtime_root = Path(base['runtime_ref']['path']).parent
    roots = (Path(base['seed_root']), Path(base['provider_root']), runtime_root,
             Path(base['profile_ref']['path']).parent, Path(value['arena_source_ref']['path']).parent.parent)
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in roots),
         'controls_output_overlap')
    return value, base


def completed_control_operation(ref, assessment_ref, context_ref, case_id, output):
    operation = core.read_ref(ref)
    path = Path(ref['path'])
    output = Path(output)
    need(path == output.with_name(output.name+'.controls-operation')/'operation.json' and
         operation.get('scope') == 'development_controls_operation' and operation.get('status') == 'passed' and
         operation.get('result_ref') == assessment_ref and operation.get('lock', {}).get('released') is True and
         operation.get('runtime_execution_performed') is True and operation.get('game_qualified') is False,
         'controls_operation_not_complete')
    plan = operation['plan']
    request = core.read_ref(operation['request_ref'])
    need(plan['request_ref'] == operation['request_ref'] and plan['descriptor_ref'] == context_ref and
         plan['case_id'] == case_id and plan['output'] == str(output) and
         plan['operation_output'] == str(path.parent) and
         request['scope'] == 'development_control_verification' and request['descriptor_ref'] == context_ref and
         request['case_id'] == case_id and request['output_name'] == output.name,
         'controls_operation_binding')
    worker = operation['worker']
    need(type(worker['pid']) is int and worker['pid'] > 1 and worker['pid'] == worker['process_group'] and
         len(operation['intervals']) == 1 and operation['runtime_execution_attempted'] is True,
         'controls_operation_worker')
    result = core.read_ref(assessment_ref)
    need(result.get('passed') is True and result.get('scope') == 'development_runtime_control_assessment' and
         result.get('context_ref') == context_ref and result.get('case_id') == case_id and
         result.get('runtime_ref') == plan['runtime_ref'] and result.get('case_ref') == operation['case_ref'] and
         result.get('control_ref', {}).get('path') == str(output/'control.json'), 'controls_operation_result')
    core.checked_ref(result['case_ref'])
    core.checked_ref(result['control_ref'])
    core.checked_ref(worker['interpreter_ref'])
    need(set(operation['logs']) == {'stdout', 'stderr'}, 'controls_operation_log_set')
    for log in operation['logs'].values():
        target = core.checked_ref(log)
        need(target.parent == path.parent, 'controls_operation_log_path')
    core.checked_ref(ref)
    return operation


class ControlsContext:
    def __init__(self, context_ref, candidate, execution_interval=None):
        self.ref = dict(context_ref)
        self.value, self.base = descriptor(self.ref)
        need(type(candidate) is Selection and candidate.name == self.base['candidate'] and
             Path(candidate.runtime) == Path(self.base['runtime_ref']['path']).parent and
             (execution_interval is None or callable(execution_interval)), 'controls_context_binding')
        self.candidate = candidate
        self.execution_interval = execution_interval
        self._producers = capture(self.value['producer_manifest_ref'], self.base['provider_root'])
        output = Path(self.value['output_root'])
        need(all(not output.is_relative_to(root) and not root.is_relative_to(output)
                 for root in self._producers.roots.values()), 'controls_output_source_overlap')
        self._active = self._completed = self._validated_end = False
        self._output = self._case = self._runtime = self._runtime_value = None
        self._source_rows = None
        self._replay_operation = None
        self.timings = []
        self._clock = time.monotonic()
        self._admit()

    def mark(self, name):
        now = time.monotonic()
        self.timings.append(dict(name=name, seconds=now-self._clock, **build.point()))
        self._clock = now

    @property
    def seed(self):
        return Path(self.base['seed_root'])

    @property
    def provider_root(self):
        return Path(self.base['provider_root'])

    def _admit(self):
        value, base = descriptor(self.ref)
        need(value == self.value and base == self.base, 'controls_inputs_changed')
        self._producers.recheck()
        runtime = Path(base['runtime_ref']['path']).parent
        packet = core.read_ref(base['runtime_ref'])
        core.completed_operation(base['runtime_ref'], packet, base['operation_ref'])
        need(packet.get('passed') is True and packet.get('diagnostic_only') is True and
             all(packet.get(key) is False for key in ('runtime_qualified', 'runtime_eligible',
                 'game_qualified', 'execution_authorized_by_this_record')) and
             packet['development_assembly']['profile_ref'] == base['profile_ref'], 'controls_runtime_scope')
        capability_binding(base['capabilities_ref'], packet)
        _, reader = signing_helpers(SourcePack(self.provider_root))
        core.verify_closure(runtime, packet, reader)
        for name, row in base['modules'].items():
            need(build.fact(runtime/PAYLOAD/'lib/wine/aarch64-windows'/name) == row['selected_ref'],
                 'controls_selected_module')
        for case_id, (fixture, _) in CASES.items():
            row = packet['fixtures'][fixture]
            path = runtime/row['path']
            need(path.resolve(strict=True).is_relative_to(runtime) and
                 build.fact(path) == value['fixture_refs'][case_id] and
                 row['sha256'] == value['fixture_refs'][case_id]['sha256'], 'controls_fixture_binding')
        need(base['seed_ref']['path'] == str(self.seed/'case.json'), 'controls_seed_path')
        origin = core.read_ref(base['seed_ref'])
        need(origin['scope'] == 'translated_graphics' and origin['fixture_id'] == 'device' and
             origin['outcome'] == 'exited' and origin['error'] is None and
             origin['cleanup']['complete'] is True and origin['sentinel_survived'] is True and
             origin['cleanup_errors'] == [], 'controls_synthetic_seed_origin')
        template = self.seed/'run/prefix'
        need(template.is_dir() and template.resolve(strict=True) == template and
             prefix_inventory(template) == base['seed_inventory'], 'controls_seed_changed')
        for name, row in base['modules'].items():
            need(build.fact(template/'drive_c/windows/system32'/name)['sha256'] == row['seed_sha256'],
                 'controls_seed_module')
        inf = runtime/PAYLOAD/'share/wine/wine.inf'
        need((template/'.update-timestamp').read_text().strip() == str(int(inf.stat().st_mtime)),
             'controls_prefix_update')
        _arena(value, packet)
        return runtime, packet

    def fresh_output(self, output):
        path = Path(output)
        need(path.is_absolute() and path.parent == Path(self.value['output_root']) and
             path.parent.resolve(strict=True) == path.parent and not path.exists() and not path.is_symlink(),
             'controls_fresh_output')
        return path

    def storage_admission(self, output):
        output = self.fresh_output(output)
        self._producers.recheck()
        inventory = self.base['seed_inventory']
        seed_origin = 'historical_synthetic_initialization'
        if self.value['device_ref'] is not None:
            device = core.read_ref(self.value['device_ref'])
            need(device.get('passed') is True and device.get('case_id') == 'device' and
                 device.get('scope') == 'development_runtime_control_assessment' and
                 device.get('runtime_ref') == self.base['runtime_ref'], 'controls_current_device_binding')
            inventory = device['observations']['synthetic_prefix_inventory']
            inventory_shape(inventory)
            seed_origin = 'current_device_post_run_prefix'
        files = {row['path']: row for row in inventory if row['kind'] == 'file'}
        seed_bytes = sum(row['size'] for row in files.values())
        growth = 0
        for name, row in self.base['modules'].items():
            prior = files.get('drive_c/windows/system32/'+name)
            expected = row['seed_sha256'] if self.value['device_ref'] is None else row['selected_ref']['sha256']
            need(prior is not None and prior['sha256'] == expected, 'controls_seed_module')
            growth += max(0, row['selected_ref']['size_bytes']-prior['size'])
        copied = [self.ref, self.value['candidate_context_ref'], self.value['arena_header_ref'],
                  self.value['arena_source_ref']]
        source_bytes = self._producers.logical_bytes + sum(row['size_bytes'] for row in copied)
        allowance = 1024**3
        additional = max(seed_bytes, 842557436) + growth + source_bytes + allowance
        reserve = 6*1024**3
        free = shutil.disk_usage(output.parent).free
        need(free >= additional+reserve, 'controls_storage_capacity')
        return dict(schema_version=1, scope='single_owned_control_run', output=str(output),
                    seed_origin=seed_origin,
                    seed_inventory_logical_bytes=seed_bytes, positive_module_growth_bytes=growth,
                    producer_snapshot_bytes=source_bytes, logs_capture_authority_allowance_bytes=allowance,
                    additional_peak_bytes=additional, reserve_bytes=reserve, observed_free_bytes=free,
                    apfs_clone_savings_assumed=False, execution_authorized_by_this_record=False)

    def begin(self, case_id, output):
        need(case_id in CASES and not self._active and not self._completed and
             callable(self.execution_interval), 'controls_single_execution')
        need(case_id != 'native-pairing' or self.value['device_ref'] is not None,
             'controls_current_device_required')
        self._case, self._output = case_id, self.fresh_output(output)
        try:
            self._runtime, self._runtime_value = self._admit()
        except BaseException:
            self._completed = True
            raise
        self._active = True
        return self._runtime, self._runtime_value

    def preserve_sources(self, output):
        need(self._active and Path(output) == self._output, 'controls_source_output')
        rows = self._producers.preserve(output)
        extra = Path(output)/'control-input-sources'
        extra.mkdir(mode=0o700)
        inputs = {'context.json': self.ref, 'candidate-inputs.json': self.value['candidate_context_ref'],
                  'pear_pe_arena.h': self.value['arena_header_ref'], 'wine-source-manifest.json': self.value['arena_source_ref']}
        for name, ref in inputs.items():
            source = core.checked_ref(ref)
            target = extra/name
            with target.open('xb') as stream:
                stream.write(source.read_bytes())
            target.chmod(0o600)
            snapshot = fact(target)
            need(snapshot['sha256'] == ref['sha256'] and snapshot['size_bytes'] == ref['size_bytes'],
                 'controls_snapshot_changed')
            rows.append(dict(original=ref, snapshot=snapshot))
        save(Path(output)/'controls-producers.json', {'files': rows})
        self._source_rows = encoded(rows)
        return rows

    def current_authority(self, output):
        need(self._active, 'controls_not_active')
        return current(self.base['runtime_ref'], self.base['operation_ref'], self.base['profile_ref'],
                       self.provider_root, output)

    def finish(self):
        need(self._active and not self._completed, 'controls_not_active')
        try:
            runtime, value = self._admit()
            need(runtime == self._runtime and value == self._runtime_value, 'controls_runtime_changed')
            self._validated_end = True
        finally:
            self._active = False
            self._completed = True

    def admit_record(self, output, record, operation_ref, assessment_ref):
        """Read-only replay admission; no execution interval or saved grant."""
        need(self.execution_interval is None and not self._active and not self._completed,
             'controls_replay_scope')
        path = Path(output)
        need(path.is_absolute() and path.parent == Path(self.value['output_root']) and
             path.is_dir() and path.resolve(strict=True) == path, 'controls_replay_output')
        need(record['case_id'] in CASES, 'controls_replay_case')
        completed_control_operation(operation_ref, assessment_ref, self.ref, record['case_id'], path)
        self._replay_operation = (dict(operation_ref), dict(assessment_ref))
        self._case, self._output = record['case_id'], path
        self._runtime, self._runtime_value = self._admit()
        self._completed = self._validated_end = True

    def assessed_runtime(self, output, record):
        need(self._completed and self._validated_end and not self._active and
             Path(output) == self._output and record['case_id'] == self._case and
             record['context_ref'] == self.ref and record['runtime_ref'] == self.base['runtime_ref'] and
             record['operation_ref'] == self.base['operation_ref'] and
             record['profile_ref'] == self.base['profile_ref'] and
             record['fixture_ref'] == self.value['fixture_refs'][self._case] and
             record['producer_manifest_ref'] == self.value['producer_manifest_ref'], 'controls_assessment_binding')
        runtime, value = self._admit()
        return runtime, value

    def finalize_assessment(self, output):
        need(self._completed and self._validated_end and not self._active and
             Path(output) == self._output, 'controls_final_assessment_scope')
        self._admit()
        if self._replay_operation is not None:
            completed_control_operation(*self._replay_operation, self.ref, self._case, output)
        rows = read(Path(output)/'controls-producers.json')['files']
        original_rows = read_sources(Path(output)/'producers.json')
        need(rows[:len(original_rows)] == original_rows and len(rows) == len(original_rows)+4,
             'controls_snapshot_coverage')
        need(self._source_rows is None or encoded(rows) == self._source_rows, 'controls_snapshot_rows_changed')
        expected = {str(Path(ref['path'])): ref for ref in self._producers.refs.values()}
        expected[self._producers.manifest_ref['path']] = self._producers.manifest_ref
        for ref in (self.ref, self.value['candidate_context_ref'], self.value['arena_header_ref'], self.value['arena_source_ref']):
            need(ref['path'] not in expected, 'controls_duplicate_source_input')
            expected[ref['path']] = ref
        need(len(rows) == len(expected) and {row['original']['path']: row['original'] for row in rows} == expected,
             'controls_snapshot_coverage')
        for row in rows:
            core.checked_ref(row['original'])
            target = core.checked_ref(row['snapshot'])
            need(target.is_relative_to(Path(output)) and row['snapshot']['sha256'] == row['original']['sha256'] and
                 row['snapshot']['size_bytes'] == row['original']['size_bytes'], 'controls_snapshot_changed')
        return fact(Path(output)/'controls-producers.json')
