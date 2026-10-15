#!/usr/bin/env python3
"""Finite instrumented Wine PE/API execution with registered native descendants.

Reuses the reviewed Stage 2 signed-byte, stream and reserved-group primitives.
The diagnostic Wine patch preserves real prefix initialization and CreateProcess,
while retaining descendants in the owned root group. This is not a product
supervisor, an ordinary-user launch, or complete arbitrary-process observation.
"""
from __future__ import annotations

import array
import ctypes
import hashlib
import os
from pathlib import Path
import re
import select
import selectors
import signal
import socket
import struct
import tempfile
import time
from types import SimpleNamespace
import uuid

from common import Error, decode_json, load_json, need, open_relative, read_relative, record as json_record, relative, sha256
import run_fixtures as base
from modules import MAX_PE, PE
from dynamic_evidence import DYNAMIC_EVENTS, validate_budget, assess_events as assess_dynamic_events
from exception_evidence import NATIVE_EVENTS as STAGE4_EVENTS, validate_native_scope as validate_stage4_native_scope

REPO = base.REPO
CASES = REPO / 'tests/wine/cases-stage3.json'
STAGE4_SUITE = 'threads-memory-exceptions'
STAGE5_SUITE = 'mac-driver'
STAGE5_EVENTS = frozenset({'stage5_window', 'stage5_window_images'})
PE_SUITES = ('api-abi', STAGE4_SUITE, STAGE5_SUITE)


def cases_path(suite):
    need(suite in PE_SUITES, 'unsupported_api_suite')
    return {'api-abi': CASES, STAGE4_SUITE: REPO / 'tests/wine/cases-stage4.json',
            STAGE5_SUITE: REPO / 'tests/wine/cases-stage5.json'}[suite]

MAX_PROCESSES = 64
TOTAL_EVENTS = 32 * 1024 * 1024
# Finite case-reader envelope; not proof every theoretical event stream fits.
CASE_JSON_BYTES = 16 * 1024 * 1024
CASE_JSON_NODES = 1_000_000
WINDOW_EVENT_LIMIT = 12 * 1024 * 1024
WINDOW_CASE_JSON_BYTES = 32 * 1024 * 1024
WINDOW_CASE_JSON_NODES = 2_000_000
WINDOW_CASE = {'id': 'window', 'entrypoint': 'window_pe', 'args': [],
               'timeout_ms': 180000, 'expected_exit': 0}
# Wine's documented empty DLL override disables CLR loading and registration in
# these disposable native fixtures. It is not a runtime/game default or CLR test.
ENVIRONMENT_POLICY = {'id': 'native-api-abi-no-mono-v1',
                      'scope': 'owned-api-abi-loader-and-descendants',
                      'prefix_initialization': 'fresh-wineboot',
                      'WINEDLLOVERRIDES': 'mscoree=', 'mono_support': 'not-exercised',
                      'clr_support': 'disabled-for-native-fixtures'}
LOADER_ENVIRONMENT = {'WINEDLLOVERRIDES': 'mscoree='}
SENTINEL_WAIT_MS = 3000
CLEANUP_OVERHEAD_MS = 2000
ARENA_EVENTS = {'arena_reserve', 'arena_publish', 'arena_retire', 'arena_failure'}
EVENTS = ARENA_EVENTS | DYNAMIC_EVENTS | STAGE4_EVENTS | STAGE5_EVENTS | base.PHASES | {'stage3_fork', 'stage3_pe_continue', 'stage3_guest_exit', 'stage3_process_exit'}
API_ARGS = ['space argument', 'Ω한글🚀']
API_ENV = 'pear value Ω한글🚀'
ABI_EXPECTED = {'version': 1, 'record_kind': 'pear_abi_result', 'passed': True, 'error_step': 0,
                'roundtrips': 64, 'callbacks': 32, 'nested_calls': 32, 'error_returns': 16,
                'gateway_calls': 128, 'native_calls': 128, 'teb_checks': 128, 'frame_checks': 32,
                'host_checks': 256, 'register_failure_mask': 0, 'inactive_callback_status': 3221226072}


SECURITY_COOKIE_DEFAULT = 0x00002b992ddfa232


RELOCATION_EXPECTED = {'version': 1, 'record_kind': 'pear_relocation_result', 'passed': True,
                       'error_step': 0, 'win32_error': 0, 'copies': 2, 'loads': 2, 'probe_calls': 4,
                       'code_pointer_checks': 4, 'data_pointer_checks': 4, 'value_checks': 4, 'retirements': 2}


LIFETIME_EXPECTED = {'version': 1, 'record_kind': 'pear_lifetime_result', 'passed': True, 'error_step': 0,
                     'loads': 32, 'callback_unload_attempts': 32, 'held_mapping_checks': 32,
                     'callback_holds': 32, 'continuation_holds': 32, 'callback_releases': 32,
                     'continuation_releases': 32, 'retirements': 32, 'compatible_reuses': 31, 'named_import_status': 3221225785,
                     'ordinal_import_status': 3221225784, 'rejected_imports': 2, 'failed_load_cleanup_checks': 2}


IMPORT_EXPECTED = [{'version': 1, 'record_kind': 'pear_import_rejection', 'event': event,
                    'status': status, 'handle_null': True, 'provider_absent': True}
                   for event, status in [('name', 3221225785), ('ordinal', 3221225784)]]


def case_json_limits(*, suite='api-abi', case_id=None):
    """Select limits from the caller's validated manifest, never decoded data."""
    need(suite in PE_SUITES, 'unsupported_api_suite')
    if suite == STAGE5_SUITE and case_id == 'window':
        return WINDOW_CASE_JSON_BYTES, WINDOW_CASE_JSON_NODES
    return CASE_JSON_BYTES, CASE_JSON_NODES


def event_limit(role, *, suite='api-abi', case_id=None):
    need(suite in PE_SUITES, 'unsupported_api_suite')
    return (WINDOW_EVENT_LIMIT if suite == STAGE5_SUITE and case_id == 'window' and role == 'loader'
            else base.EVENT_LIMIT)


def decode_case(data, *, suite='api-abi', case_id=None):
    byte_limit, node_limit = case_json_limits(suite=suite, case_id=case_id)
    return json_record(decode_json(data, byte_limit, max_nodes=node_limit), 'wine_api_case')


def validate_environment_policy(value):
    need(value == ENVIRONMENT_POLICY, 'api_environment_policy')


def cleanup_allowance_ms(bounds):
    """Bound three cleanups, exit-notification barrier and final pipe drain."""
    keys = ('grace_ms', 'terminate_ms', 'kill_ms', 'drain_ms')
    need(isinstance(bounds, dict) and all(type(bounds.get(key)) is int and
         0 <= bounds[key] <= 60000 for key in keys), 'api_cleanup_budget')
    return (3 * sum(bounds[key] for key in keys[:3]) + SENTINEL_WAIT_MS +
            2 * bounds['drain_ms'] + CLEANUP_OVERHEAD_MS)


def validate_duration(elapsed_ms, timeout_ms, bounds):
    need(type(timeout_ms) is int and 0 < timeout_ms <= 24 * 60 * 60 * 1000,
         'api_timeout_budget')
    need(type(elapsed_ms) is int and 0 <= elapsed_ms <= timeout_ms + cleanup_allowance_ms(bounds),
         'api_case_duration')


def fixture_loader_environment(home, prefix, nonce, endpoint, server_pid, *, stage4=False, stage5=False):
    """Build the fixed fixture environment, without inheriting caller settings."""
    env = base.environment(home, prefix, nonce)
    need(set(env) == {'PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'WINEPREFIX', 'WINEDEBUG',
                      'PEAR_BOOTSTRAP_NONCE', 'PEAR_BOOTSTRAP_GENERATION'} and
         env['WINEDEBUG'] == '-all' and env['WINEPREFIX'] == str(prefix), 'api_environment_changed')
    env.update({'PEAR_STAGE3_CONTROL': endpoint, 'PEAR_API_INPUT': API_ENV,
                'PEAR_WINE_ABI_FIXTURE': '1', 'PEAR_BOOTSTRAP_SERVER_PID': str(server_pid),
                **LOADER_ENVIRONMENT})
    if stage4:
        env['PEAR_WINE_STAGE4_FIXTURE'] = '1'
    if stage5:
        env['PEAR_WINE_STAGE5_FIXTURE'] = '1'
    return env


def graphical_session():
    """Read the same Security.framework session capability used by winemac."""
    try:
        security = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
        function = security.SessionGetInfo
        function.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
        function.restype = ctypes.c_int32
        attributes = ctypes.c_uint32()
        status = function(ctypes.c_uint32(0xffffffff), None, ctypes.byref(attributes))
        return {'status': status, 'available': status == 0 and bool(attributes.value & 0x10)}
    except (OSError, AttributeError):
        return {'status': None, 'available': False}


def expected_fixture_rows(kind):
    if kind == 'window':
        from window_evidence import expected_results
        return expected_results()
    if kind == 'threads':
        from exception_evidence import expected_results
        return expected_results()
    need(kind in ('api', 'abi'), 'unsupported_fixture_kind')
    return expected_api_rows() if kind == 'api' else [RELOCATION_EXPECTED, LIFETIME_EXPECTED, ABI_EXPECTED]


def lifetime_events(rows):
    """Validate the original fixture's private, observed DLL-address timeline."""
    need(len(rows) == 64, 'lifetime_event_count')
    keys = {'version', 'record_kind', 'round', 'event', 'module_base', 'callback_address'}
    for index, row in enumerate(rows):
        need(set(row) == keys and type(row.get('version')) is int and row['version'] == 1 and
             row.get('record_kind') == 'pear_lifetime_event' and
             type(row.get('round')) is int and row['round'] == index // 2 and
             row.get('event') == ('loaded' if index % 2 == 0 else 'retired'), 'lifetime_event_order')
        need(all(type(row.get(key)) is int and 0 < row[key] < 2**64
                 for key in ('module_base', 'callback_address')) and
             row['module_base'] % 65536 == 0 and row['callback_address'] % 4 == 0,
             'lifetime_event_address')
        if index % 2:
            need(all(row[key] == rows[index - 1][key] for key in ('module_base', 'callback_address')),
                 'lifetime_retirement_identity')
        elif index:
            need(row['module_base'] == rows[0]['module_base'], 'lifetime_compatible_reuse')
    return rows


def relocation_events(rows):
    """Check the finite private guest timeline without qualifying its addresses."""
    need(len(rows) == 6, 'relocation_event_count')
    common = {'version', 'record_kind', 'event', 'copy', 'module_base'}
    pointers = {'code_slot', 'code_pointer', 'code_address', 'data_slot', 'data_pointer', 'data_address'}
    pointers.add('security_cookie_address')
    probe = common | pointers | {'round', 'status', 'before', 'after', 'call_result', 'peer_value', 'security_cookie'}
    values, cookies = [0x13579bdf, 0x13579bdf], [None, None]
    for index, row in enumerate(rows):
        need(isinstance(row, dict) and set(row) == (probe if index < 4 else common) and
             type(row.get('version')) is int and row['version'] == 1 and
             row.get('record_kind') == 'pear_relocation_event' and
             row.get('event') == ('probe' if index < 4 else 'retired') and
             type(row.get('copy')) is int and row['copy'] == index % 2,
             'relocation_event_order')
        need(type(row['module_base']) is int and 0 < row['module_base'] < 2**64 and
             row['module_base'] % 65536 == 0, 'relocation_event_address')
        copy = row['copy']
        if index >= 2:
            need(row['module_base'] == rows[copy]['module_base'], 'relocation_module_identity')
        if index >= 4:
            continue
        need(all(type(row[key]) is int and 0 < row[key] < 2**64 for key in pointers) and
             all(row[key] % (8 if key.endswith('_slot') or key == 'security_cookie_address' else 4) == 0 for key in pointers),
             'relocation_event_address')
        need(all(type(row[key]) is int for key in ('round', 'status', 'before', 'after', 'call_result', 'peer_value')) and
             row['round'] == index // 2 and row['status'] == 0, 'relocation_probe_status')
        cookie = row['security_cookie']
        need(type(cookie) is int and 0 < cookie < 2**48 and cookie != SECURITY_COOKIE_DEFAULT,
             'relocation_security_cookie_uninitialized')
        need(cookies[copy] is None or cookie == cookies[copy], 'relocation_security_cookie_changed')
        cookies[copy] = cookie
        desired = (0x10203040 if index < 2 else 0x50607080) + copy
        need(row['before'] == values[copy] and row['after'] == desired and
             row['call_result'] == (desired ^ 0xa5c31f27) and row['peer_value'] == values[1 - copy],
             'relocation_data_isolation')
        values[copy] = desired
    need(rows[0]['module_base'] != rows[1]['module_base'], 'relocation_distinct_bases')
    return rows


def relocation_image(data):
    """Reuse the component PE reader; inspect fixture exports and real DIR64 cells.

    This is byte inspection only. Host execution is established separately by
    guest observations bound to the registered publisher's actual slot events.
    """
    pe = PE(data)
    size = pe.u('I', pe.opt + 56)
    need(pe.machine == 0xaa64 and pe.u('H', pe.pe + 22) & 0x2000 and
         size > 0 and size % 4096 == 0 and 0 < pe.base < 2**64 - size and pe.base % 65536 == 0,
         'relocation_fixture_architecture')

    def section(rva, count, executable=None):
        need(type(rva) is int and 0 < count <= size and 0 <= rva <= size - count,
             'relocation_rva_bounds')
        pe.offset(rva, count)
        hits = [row for row in pe.sections if row['rva'] <= rva and
                rva + count <= row['rva'] + row['virtual_size']]
        need(len(hits) == 1, 'relocation_section_coverage')
        flags = hits[0]['characteristics']
        if executable is not None:
            need(bool(flags & 0x20000000) == executable and
                 (not executable or not flags & 0x80000000) and
                 (executable or flags & 0x80000000), 'relocation_section_policy')
        return flags

    exports = pe.exports()
    named = [row for row in exports if row['name']]
    need(len({row['name'] for row in named}) == len(named), 'relocation_duplicate_export')
    by_name = {row['name']: row for row in named}
    names = {'code_address': 'PearRelocationCode', 'data_address': 'PearRelocationData',
             'code_slot': 'PearRelocationCodePointer', 'data_slot': 'PearRelocationDataPointer',
             'security_cookie_address': 'PearSecurityCookie'}
    rvas = {}
    for key, name in names.items():
        row = by_name.get(name)
        need(row is not None and 'forwarder' not in row, 'relocation_export_missing_or_forwarded')
        rva = row['rva']
        extent = 8 if key.endswith('_slot') or key == 'security_cookie_address' else 4
        need(rva % extent == 0, 'relocation_export_alignment')
        section(rva, extent, key == 'code_address')
        rvas[key] = rva
    extents = sorted((rva, 8 if key.endswith('_slot') or key == 'security_cookie_address' else 4)
                     for key, rva in rvas.items())
    need(all(first + count <= second for (first, count), (second, _) in zip(extents, extents[1:])),
         'relocation_export_overlap')
    for kind in ('code', 'data'):
        need(pe.u('Q', pe.offset(rvas[kind + '_slot'], 8)) == pe.base + rvas[kind + '_address'],
             'relocation_original_pointer')
    need(pe.u('I', pe.offset(rvas['data_address'], 4)) == 0x13579bdf, 'relocation_original_data')
    # The fixture starts with Wine's documented source default. The load-config
    # VA is a separate DIR64 cell pointing to an ordinary writable cookie.
    cookie_rva = rvas['security_cookie_address']
    need(pe.u('Q', pe.offset(cookie_rva, 8)) == SECURITY_COOKIE_DEFAULT,
         'relocation_security_cookie_default')
    load_config, config_length = pe.dirs[10]
    need(load_config > 0 and load_config % 8 == 0 and 96 <= config_length <= size,
         'relocation_security_cookie_load_config')
    need(not section(load_config, config_length) & 0x20000000, 'relocation_security_cookie_load_config')
    config_size = pe.u('I', pe.offset(load_config, 4))
    need(96 <= config_size <= config_length and
         pe.u('Q', pe.offset(load_config + 88, 8)) == pe.base + cookie_rva,
         'relocation_security_cookie_destination')
    need(all(start + count <= load_config or load_config + config_length <= start
             for start, count in extents), 'relocation_security_cookie_config_overlap')
    cookie_field_rva = load_config + 88
    directory, length = pe.dirs[5]
    need(directory > 0 and 8 <= length <= len(data) and directory % 4 == 0,
         'relocation_directory')
    start = pe.offset(directory, length)
    cursor, targets = 0, []
    while cursor < length:
        need(length - cursor >= 8, 'relocation_block_header')
        page, block_size = pe.unpack('II', start + cursor)
        need(page % 4096 == 0 and 8 <= block_size <= length - cursor and block_size % 2 == 0,
             'relocation_block_bounds')
        for index in range(cursor + 8, cursor + block_size, 2):
            item = pe.u('H', start + index)
            kind, target = item >> 12, page + (item & 0xfff)
            if not kind:
                continue
            need(kind == 10, 'relocation_unsupported_type')
            section(target, 8)
            need(target >= pe.headers_size and (target + 8 <= directory or directory + length <= target),
                 'relocation_directory_overlap')
            targets.append(target)
        cursor += block_size
    targets.sort()
    need(all(first + 8 <= second for first, second in zip(targets, targets[1:])),
         'relocation_target_overlap')
    need(rvas['code_slot'] in targets and rvas['data_slot'] in targets, 'relocation_pointer_fixups_missing')
    need(cookie_field_rva in targets, 'relocation_security_cookie_fixup_missing')
    need(all(target + 8 <= cookie_rva or cookie_rva + 8 <= target for target in targets),
         'relocation_security_cookie_value_relocated')
    return {'original_base': pe.base, 'size': size, 'relocations': len(targets), 'rvas': rvas,
            'security_cookie': {'load_config_rva': load_config, 'field_rva': cookie_field_rva,
                                'default': SECURITY_COOKIE_DEFAULT}}


def relocation_file(root, name):
    """Reuse no-follow descriptor traversal and retain the read file's identity."""
    with os.fdopen(open_relative(root, name), 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(before.st_size <= MAX_PE, 'relocation_file_size')
        data = stream.read(MAX_PE + 1)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(data) == before.st_size <= MAX_PE and
             all(getattr(before, key) == getattr(after, key) for key in fields), 'relocation_file_changed')
        return data, (before.st_dev, before.st_ino)


def assess_relocation_events(result, private, runtime, signed, case_root):
    """Bind two real, simultaneously live PE placements to exact fixture bytes.

    Native event identity, sequence, bounds and all slot transitions have already
    been checked by assess_native_events and assess_arena_events. Raw addresses
    stay private; only the finite completed checks are returned to the exporter.
    """
    need(result['case']['id'] == 'abi' and case_root is not None, 'relocation_case_scope')
    relocation_events(private)
    raw_requirements = read_relative(runtime, 'requirements.json')
    need(hashlib.sha256(raw_requirements).hexdigest() == signed.get('requirements_sha256'),
         'changed_signing_requirements')
    requirements = decode_json(raw_requirements)
    item = requirements.get('guest_fixtures', {}).get('lifetime_dll', {})
    need(requirements.get('fixture_suite') in PE_SUITES and type(item.get('machine')) is int and item['machine'] == 0xaa64 and
         item.get('execution_permitted') is True, 'relocation_signed_fixture')
    original, original_identity = relocation_file(runtime, signed['entrypoints']['lifetime_dll'])
    digest = hashlib.sha256(original).hexdigest()
    need(item.get('sha256') == digest, 'relocation_fixture_changed')
    facts = relocation_image(original)
    identities = {original_identity}
    for name in ('pear-relocation-a.dll', 'pear-relocation-b.dll'):
        data, identity = relocation_file(case_root, 'work/' + name)
        need(data == original, 'relocation_copy_changed')
        need(identity not in identities, 'relocation_file_alias')
        identities.add(identity)
    for observed in private[:4]:
        address = observed['module_base']
        need(address != facts['original_base'], 'relocation_zero_delta')
        for key, rva in facts['rvas'].items():
            need(observed[key] == address + rva, 'relocation_guest_rva_binding')
        need(observed['code_pointer'] == observed['code_address'] and
             observed['data_pointer'] == observed['data_address'], 'relocation_guest_pointer_binding')
    events = result['events']['loader']
    # The original fixture performs this experiment before import rejection and
    # the 32-round reuse test. Match its first relevant generation, retaining all
    # later publications for the independent lifetime checks.
    pairs = []
    for observed in private[:2]:
        candidates = [row for row in events if row['event'] == 'arena_publish' and
                      row['base'] == observed['module_base'] and
                      all(row.get(key) == facts[key] for key in ('original_base', 'size', 'relocations'))]
        need(candidates, 'relocation_publication_missing')
        publish = candidates[0]
        retired = [row for row in events if row['event'] == 'arena_retire' and
                   row['slot'] == publish['slot'] and row['slot_generation'] == publish['slot_generation']]
        need(len(retired) == 1 and all(retired[0][key] == publish[key] for key in
             ('base', 'size', 'capacity')) and publish['arena_sequence'] < retired[0]['arena_sequence'],
             'relocation_retirement_missing')
        pairs.append((publish, retired[0]))
    need(pairs[0][0]['slot'] != pairs[1][0]['slot'], 'relocation_distinct_slots')
    need(pairs[0][0]['arena_sequence'] < pairs[1][0]['arena_sequence'] <
         pairs[0][1]['arena_sequence'] < pairs[1][1]['arena_sequence'], 'relocation_simultaneous_lifetimes')
    return {'fixture_sha256': digest, 'placements': 2, 'copied_files_verified': 2,
            'relocated_pointer_slots': 4, 'probe_calls_verified': 4, 'retirements_verified': 2,
            'simultaneous_live': True, 'distinct_bases': True, 'distinct_slots': True,
            'nonzero_deltas': True, 'original_pointer_rvas_verified': True,
            'code_targets_verified': True, 'data_isolation_verified': True,
            'security_cookie_images': 2, 'security_cookie_observations': 4,
            'security_cookie_initialized': True, 'security_cookie_stable': True,
            'security_cookie_destination_verified': True, 'security_cookie_load_config_verified': True}


def validate_cases(value, suite='api-abi'):
    need(suite in PE_SUITES, 'unsupported_api_suite')
    validate_environment_policy(value.get('environment_policy'))
    expected = [{'id': 'api', 'entrypoint': 'api_pe', 'args': API_ARGS,
                 'timeout_ms': 180000, 'expected_exit': 0},
                {'id': 'abi', 'entrypoint': 'abi_pe', 'args': [],
                 'timeout_ms': 180000, 'expected_exit': 0}]
    if suite in (STAGE4_SUITE, STAGE5_SUITE):
        expected.append({'id': 'threads', 'entrypoint': 'stage4_pe', 'args': [],
                         'timeout_ms': 180000, 'expected_exit': 0})
    if suite == STAGE5_SUITE:
        expected.append(dict(WINDOW_CASE))
    bounds = {'stdout_bytes': base.STREAM_LIMIT, 'stderr_bytes': base.STREAM_LIMIT,
              'event_bytes_per_process': base.EVENT_LIMIT, 'total_event_bytes': TOTAL_EVENTS,
              'max_processes': MAX_PROCESSES, 'registration_ms': 30000,
              'grace_ms': 3000, 'terminate_ms': 2000, 'kill_ms': 5000, 'drain_ms': 1000}
    if suite == STAGE5_SUITE:
        bounds['window_loader_event_bytes'] = WINDOW_EVENT_LIMIT
        bounds['window_case_json_bytes'] = WINDOW_CASE_JSON_BYTES
        bounds['window_case_json_nodes'] = WINDOW_CASE_JSON_NODES
    need(set(value) == {'schema_version', 'record_kind', 'suite', 'qualification', 'environment_policy',
                        'cases', 'controls', 'bounds', 'provenance'} and
         type(value.get('schema_version')) is int and value['schema_version'] == 1 and
         value.get('record_kind') == 'wine_fixture_cases' and
         value.get('qualification') == ('instrumented-arm64-pe-api-abi-only' if suite == 'api-abi'
             else 'instrumented-arm64-thread-memory-exception-only' if suite == STAGE4_SUITE
             else 'instrumented-arm64-mac-driver-only') and
         value.get('suite') == suite and value.get('cases') == expected and
         all(type(row.get(key)) is int for row in value['cases'] for key in ('timeout_ms', 'expected_exit')) and
         value.get('bounds') == bounds and value.get('controls') == ['x64_control', 'i386_control'],
         'unsupported_api_cases')
    return value


def producers(suite='api-abi'):
    need(suite in PE_SUITES, 'unsupported_api_suite')
    names = ('tools/wine/dynamic_evidence.py', 'tools/wine/exception_evidence.py', 'tools/wine/abi_review.py',
             'tools/wine/api_runner.py', 'tools/wine/modules.py', 'tools/wine/run_fixtures.py', 'tests/wine/cases-stage3.json',
             'tests/wine/fixtures/api_launch.c', 'tests/wine/fixtures/api_pe.c',
             'tests/wine/fixtures/abi_pe.c', 'tests/wine/fixtures/abi_native.c',
             'tests/wine/fixtures/abi_gateway.S', 'tests/wine/fixtures/sentinel.c',
             'tests/wine/fixtures/lifetime_pe.c', 'tests/wine/fixtures/lifetime_pe.h',
             'tests/wine/fixtures/missing_import_pe.c', 'tests/wine/fixtures/missing_name.def',
             'tests/wine/fixtures/missing_ordinal.def')
    if suite in (STAGE4_SUITE, STAGE5_SUITE):
        from build import STAGE4_FIXTURES
        names += ('tests/wine/cases-stage4.json',) + tuple(
            'tests/wine/fixtures/' + name for name in STAGE4_FIXTURES)
    if suite == STAGE5_SUITE:
        from build import STAGE5_FIXTURES
        names += ('tools/wine/window_evidence.py', 'tests/wine/cases-stage5.json') + tuple(
            'tests/wine/fixtures/' + name for name in STAGE5_FIXTURES)
    return {name: sha256(REPO / name) for name in names}


def snapshot_producers(output, suite='api-abi'):
    """Preserve exact source identities before launching any owned process."""
    hashes = producers(suite)
    for name, expected in hashes.items():
        data = read_relative(REPO, name)
        need(hashlib.sha256(data).hexdigest() == expected, 'api_producer_changed')
        path = output.joinpath('producer', *relative(name))
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open('xb') as stream: stream.write(data)
    need(producers(suite) == hashes, 'api_producer_changed')
    return hashes


def validate_registration(hello, peer_pid, actual, root, registered, executable, loader_path, nonce):
    """Assess authenticated live facts before sending a child its continuation FD."""
    need(isinstance(hello, dict) and hello.get('version') == 1 and hello.get('nonce') == nonce and
         hello.get('kind') in ('loader', 'fork'), 'registration_scope')
    need(hello.get('pid') == peer_pid and all(type(hello.get(key)) is int and hello[key] == value
                                           for key, value in actual.items()), 'registration_identity')
    need(hello.get('pgid') == root.pid and type(hello.get('pgid')) is int,
         'descendant_group_escape')
    need(str(Path(executable).resolve()) == str(Path(loader_path).resolve()), 'unapproved_descendant_executable')
    base.native_snapshot(hello, 4096)
    if hello['kind'] == 'loader':
        need(peer_pid == root.pid and actual == root.identity and not registered, 'unexpected_root_registration')
    else:
        parent = registered.get(actual['ppid'])
        need(parent is not None and not parent['exited'] and peer_pid not in registered,
             'unregistered_native_parent')
    need(len(registered) < MAX_PROCESSES, 'native_process_limit')


class APIObserver(base.DarwinObserver):
    """Kqueue retains each registered process instance; only the owned group is signaled."""
    def __init__(self):
        super().__init__()
        self.registrations = {}
        self.signal_observations = []

    def refresh(self):
        for event in self.queue.control(None, max(1, len(self.handles) * 3), 0):
            child = self.handles.get(event.ident)
            need(child is not None, 'unknown_process_event')
            child.exited |= bool(event.fflags & select.KQ_NOTE_EXIT)
            if event.fflags & select.KQ_NOTE_EXEC and not child.exited:
                need(self.executable(child.pid) in child.allowed_paths, 'unapproved_observed_exec')
            if event.fflags & select.KQ_NOTE_FORK:
                child.observed_fork = True
                need(child.role == 'loader' or child.role.startswith('process-'), 'unexpected_native_fork')
            if event.fflags & select.KQ_NOTE_EXIT:
                if child.pid in self.registrations:
                    row = self.registrations[child.pid]
                    row['exited'] = True
                    # NOTE_EXITSTATUS carries wait status; no inferred zero exit.
                    row['exit_observed_ns'] = time.monotonic_ns()
                    row['exit_status'] = int(event.data)
                    row['exit_code'] = os.waitstatus_to_exitcode(int(event.data) & 0xffff)

    def signal_owned(self, child, number):
        need(not child.reaped and self.handles.get(child.pid) is child, 'ownership_not_retained')
        self.refresh()
        members = self.group_members(child)
        if child.exited and not members:
            return False
        if not child.exited:
            need(self.identity(child.pid) == child.identity, 'owned_generation_changed')
            need(self.executable(child.pid) in child.allowed_paths, 'unexpected_owned_executable')
        self.refresh()
        observation = {'role': child.role, 'signal': int(number), 'at_ns': time.monotonic_ns(),
                       'live_registered_roles': sorted(row['role'] for row in self.registrations.values()
                                                       if not row['exited'])}
        try:
            os.killpg(child.pid, number)
        except ProcessLookupError:
            return False
        self.signal_observations.append(observation)
        return True

    def add_registered(self, child):
        self.handles[child.pid] = child
        self.queue.control([select.kevent(child.pid, filter=select.KQ_FILTER_PROC,
                           flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                           fflags=select.KQ_NOTE_EXIT | select.KQ_NOTE_FORK | select.KQ_NOTE_EXEC | 0x04000000)], 0, 0)

    def group_members(self, child):
        previous_gap = child.fork_seen
        members = super().group_members(child)
        # Coverage failure must not suppress safe termination of the reserved
        # owned group. Unknown children remain failed observations after cleanup.
        unknown = [pid for pid in members if child.role != 'loader' or pid not in self.registrations]
        child.fork_seen = previous_gap or bool(unknown)
        return members


class APISession(base.Session):
    def __init__(self, output, runtime, signed, nonce, *, suite='api-abi', case_id=None):
        case_json_limits(suite=suite, case_id=case_id)
        self.suite, self.case_id = suite, case_id
        super().__init__(output, observer=APIObserver())
        self.runtime, self.signed, self.nonce = runtime, signed, nonce
        self.control_dir = tempfile.TemporaryDirectory(prefix='pear-stage3-', dir='/private/tmp')
        self.endpoint = str(Path(self.control_dir.name) / 'control')
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.endpoint)
        self.listener.listen(MAX_PROCESSES)
        self.listener.setblocking(False)
        self.pending = {}

    def cleanup(self, roles, bounds):
        """Drain the owned loader group while its server remains available.

        Wine clients can turn SIGINT into an unclassified native exit. Give
        them a bounded natural-exit grace period, then use the existing owned
        SIGTERM/SIGKILL path. Server teardown follows even a failed loader
        cleanup, with every earlier error and signal preserved in order.
        """
        roles = tuple(roles)
        if roles != ('loader', 'server'):
            return super().cleanup(roles, bounds)
        loader = super().cleanup(('loader',), bounds, allow_interrupt=False)
        barrier_error = self.registered_exit_barrier(bounds['drain_ms'])
        server = super().cleanup(('server',), bounds)
        report = {'signals': loader['signals'] + server['signals'],
                  'errors': loader['errors'] +
                      ([{'role': 'observer', 'code': barrier_error}] if barrier_error else []) + server['errors'],
                  'observation_gap': loader['observation_gap'] or bool(barrier_error) or server['observation_gap'],
                  'reaped': {**loader['reaped'], **server['reaped']}, 'complete': False}
        report['complete'] = (loader['complete'] and server['complete'] and not report['errors'] and
                              not report['observation_gap'] and all(report['reaped'].values()))
        return report

    def registered_exit_barrier(self, drain_ms):
        """Await actual registered exit receipts after kernel group drain.

        A zombie is absent from live group enumeration before its NOTE_EXIT
        receipt necessarily arrives. Keep the server, registration checks and
        raw pipes available until every receipt is observed, without inferring
        successful termination from that absence.
        """
        try:
            need(type(drain_ms) is int and 0 <= drain_ms <= 60000, 'api_cleanup_budget')
            deadline = time.monotonic() + drain_ms / 1000
            while True:
                self.pump(min(0.02, max(0, deadline - time.monotonic())))
                if self.failure:
                    return self.failure
                if all(row.get('exited') is True and type(row.get('exit_status')) is int and
                       type(row.get('exit_code')) is int and type(row.get('exit_observed_ns')) is int and
                       row['exit_observed_ns'] > 0 for row in self.observer.registrations.values()):
                    return None
                if time.monotonic() >= deadline:
                    return 'registered_exit_barrier_timeout'
        except (Error, OSError, KeyboardInterrupt) as exc:
            return getattr(exc, 'code', 'registered_exit_barrier_observation_failed')

    def registration_pump(self):
        while True:
            try:
                connection, _ = self.listener.accept()
            except BlockingIOError:
                break
            need(len(self.pending) < MAX_PROCESSES, 'registration_connection_limit')
            connection.setblocking(False)
            self.pending[connection] = {'data': bytearray(), 'deadline': time.monotonic() + 30}
        for connection, state in list(self.pending.items()):
            need(time.monotonic() <= state['deadline'], 'registration_timeout')
            try:
                data = connection.recv(4096)
            except BlockingIOError:
                continue
            need(data, 'registration_eof')
            state['data'].extend(data)
            need(len(state['data']) <= 2048, 'registration_output_limit')
            if b'\n' not in state['data']:
                continue
            need(state['data'].endswith(b'\n') and state['data'].count(b'\n') == 1, 'registration_shape')
            hello = decode_json(bytes(state['data']))
            peer = connection.getsockopt(0, 2)  # Darwin SOL_LOCAL / LOCAL_PEERPID.
            actual = self.observer.identity(peer)
            root = self.children['loader']
            self.observer.refresh()
            ledger = self.observer.registrations
            loader_path = self.runtime / self.signed['entrypoints']['loader']
            validate_registration(hello, peer, actual, root, ledger,
                                  self.observer.executable(peer), loader_path, self.nonce)
            role = 'loader' if peer == root.pid else f'process-{len(ledger):02d}'
            child = root if peer == root.pid else SimpleNamespace(
                role=role, pid=peer, identity=actual, exited=False, fork_seen=False, reaped=False,
                allowed_paths={str(loader_path.resolve())}, observed_fork=False)
            ledger[peer] = {'role': role, 'hello': hello, 'identity': actual,
                            'parent_role': None if role == 'loader' else ledger[actual['ppid']]['role'],
                            'exited': False, 'exit_status': None, 'exit_code': None, 'exit_observed_ns': None,
                            'observation': 'authenticated-register-before-further-fork-or-exec'}
            self.observer.add_registered(child)
            self.events[role] = []
            read_fd, write_fd = os.pipe()
            try:
                self.add_stream(role, 'events', os.fdopen(read_fd, 'rb', buffering=0))
                sent = connection.sendmsg([b'G'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                   array.array('i', [write_fd]))])
                need(sent == 1, 'registration_ack_failed')
            finally:
                os.close(write_fd)
            connection.close()
            del self.pending[connection]

    def pump(self, wait=0.02):
        try:
            self.registration_pump()
        except (Error, OSError, KeyError, TypeError) as exc:
            self.failure = self.failure or getattr(exc, 'code', 'registration_failed')
        self.observer.refresh()
        for key, _ in self.selector.select(wait):
            item = key.data
            try:
                block = os.read(item['stream'].fileno(), 16384)
            except BlockingIOError:
                continue
            except OSError:
                self.failure = self.failure or 'pipe_read_error'
                block = b''
            if not block:
                item['eof'] = True
                self.selector.unregister(item['stream'])
                item['stream'].close()
                if item['channel'] == 'events' and item['pending']:
                    self.failure = self.failure or 'truncated_event'
                continue
            item['total_bytes'] += len(block)
            limit = (event_limit(item['role'], suite=self.suite, case_id=self.case_id)
                     if item['channel'] == 'events' else base.STREAM_LIMIT)
            item['data'].extend(block[:max(0, limit + 1 - len(item['data']))])
            if item['channel'] == 'events':
                self.event_bytes += len(block)
            if item['total_bytes'] > limit or self.event_bytes > TOTAL_EVENTS:
                self.failure = self.failure or 'output_limit'
                continue
            if item['channel'] == 'events':
                item['pending'].extend(block)
                while b'\n' in item['pending']:
                    line, _, remainder = item['pending'].partition(b'\n')
                    item['pending'] = bytearray(remainder)
                    try:
                        self.events[item['role']].append(decode_json(bytes(line), 32768))
                    except Error:
                        self.failure = self.failure or 'invalid_event'
                if len(item['pending']) > 32768:
                    self.failure = self.failure or 'event_line_limit'

    def finish_logs(self, drain_ms):
        result = super().finish_logs(drain_ms)
        for connection in self.pending:
            connection.close()
        self.pending.clear()
        self.listener.close()
        self.control_dir.cleanup()
        return result


def expected_api_rows():
    common = {'version': 1, 'record_kind': 'pear_api_result', 'error_step': 0, 'win32_error': 0}
    return [{'version': 1, 'record_kind': 'pear_architecture_result', 'status': 0, 'returned_bytes': 8,
             'machines': [43620], 'flags': [7], 'terminator': 0},
            {**common, 'role': 'child', 'checks_bitmask': 15, 'fnv1a64': '0000000000000000', 'child_exit': 0},
            {**common, 'role': 'parent', 'checks_bitmask': 255, 'fnv1a64': 'eb776cf97e933998', 'child_exit': 37}]


def fixture_observations(raw, kind, loader):
    lines = raw.splitlines()
    need(lines, 'missing_fixture_output')
    helper = decode_json(lines[0], 32768)
    base.validate_helper(helper, 'pear_bootstrap_helper', loader)
    if kind == 'window':
        from window_evidence import decode_stdout_row, fixture_rows
        return fixture_rows([decode_stdout_row(line) for line in lines[1:]]), [], []
    if kind == 'threads':
        from exception_evidence import decode_stdout_row, fixture_rows
        return fixture_rows([decode_stdout_row(line) for line in lines[1:]]), [], []
    need(kind in ('api', 'abi'), 'unsupported_fixture_kind')
    rows = [helper, *[decode_json(line, 32768) for line in lines[1:]]]
    expected = expected_fixture_rows(kind)
    if kind == 'abi':
        need(rows[7:9] == IMPORT_EXPECTED and all(
             type(row[key]) is type(value) for row, wanted in zip(rows[7:9], IMPORT_EXPECTED)
             for key, value in wanted.items()), 'import_rejection_observations')
    private = lifetime_events(rows[9:-3]) if kind == 'abi' else []
    relocated = relocation_events(rows[1:7]) if kind == 'abi' else []
    observed = rows[-3:] if kind == 'abi' else rows[1:]
    need(observed == expected, 'fixture_result_mismatch')
    # JSON booleans must not stand in for numeric counters.
    need(all(type(row[key]) is type(value) for row, wanted in zip(observed, expected)
             for key, value in wanted.items()), 'fixture_result_type')
    if kind == 'api':
        need(all(type(value) is int for key in ('machines', 'flags') for value in observed[0][key]),
             'architecture_result_type')
    return expected, private, relocated


def fixture_output(raw, kind, loader):
    return fixture_observations(raw, kind, loader)[0]


def image_inventories(rows):
    inventory = []
    for row in rows:
        if row.get('event') == 'image':
            need(row.get('index') == len(inventory) and type(row.get('index')) is int, 'image_order')
            inventory.append(row)
        elif row.get('event') == 'images_end':
            need(inventory and row.get('count') == len(inventory), 'image_count')
            yield inventory
            inventory = []
    need(not inventory, 'unfinished_image_inventory')


def assess_native_events(result, runtime, signed):
    nonce, prefix = result['nonce'], result['prefix']
    server = result['processes']['server']
    ledger = result['registrations']
    need(1 <= len(ledger) <= MAX_PROCESSES and len({row['identity']['pid'] for row in ledger}) == len(ledger),
         'registration_coverage')
    by_role = {row['role']: row for row in ledger}
    need(len(by_role) == len(ledger) and 'loader' in by_role, 'registration_role_coverage')
    need(by_role['loader'].get('identity') == result['processes']['loader']['identity'] and
         by_role['loader'].get('parent_role') is None and
         by_role['loader'].get('hello', {}).get('kind') == 'loader', 'root_registration_identity')
    seen_roles = set()
    for registration in ledger:
        role = registration['role']
        need(role == 'loader' if not seen_roles else role != 'loader' and
             registration.get('parent_role') in seen_roles and registration.get('hello', {}).get('kind') == 'fork',
             'unanchored_registration_chain')
        seen_roles.add(role)
    need(set(result['events']) == {'server', *by_role}, 'process_event_coverage')
    server_handshakes = []
    executed = []
    for role, rows in result['events'].items():
        record = server if role == 'server' else by_role[role]
        identity = record['identity']
        generation = 0
        need(rows, 'missing_native_events')
        for row in rows:
            need(row.get('version') == 1 and row.get('nonce') == nonce and row.get('event') in EVENTS and
                 row.get('role') == ('server' if role == 'server' else 'loader') and
                 row.get('identity_error') == 0, 'native_event_scope')
            need(all(type(row.get(key)) is int and row[key] == identity[key]
                     for key in ('pid', 'start_sec', 'start_usec')), 'native_event_identity')
            need(type(row.get('ppid')) is int and row['ppid'] in (identity['ppid'], 1), 'unexpected_reparenting')
            need(type(row.get('generation')) is int and row['generation'] == generation, 'native_generation')
            if row['event'] == 'loader_reexec':
                need(role != 'server' and generation == 0 and row.get('next_generation') == 1,
                     'invalid_reexecution')
                generation = 1
            if row['event'] == 'image':
                need(type(row.get('cpu_type')) is int and row['cpu_type'] == base.MACH_ARM64 and
                     isinstance(row.get('uuid'), str) and re.fullmatch('[0-9a-fA-F-]{32,36}', row['uuid']),
                     'observed_native_image_architecture')
            if row['event'] in base.SNAPSHOTS | {'stage3_fork', 'stage5_window_images'}:
                base.native_snapshot(row, 16384 if role == 'server' else 4096)
                need(row.get('prefix_error') == 0 and row.get('prefix_dev') == prefix['device'] and
                     row.get('prefix_ino') == prefix['inode'], 'native_prefix_mismatch')
            need(row['event'] != 'failure', 'native_execution_failure')
        inventories = list(image_inventories(rows))
        need(inventories, 'missing_native_image_inventory')
        for inventory in inventories:
            # Reuse UUID/hash/origin validation, independently for each snapshot.
            key = 'server' if role == 'server' else 'loader'
            fake = {'server': inventory if key == 'server' else result['events']['server'],
                    'loader': inventory if key == 'loader' else []}
            if key == 'server':
                base.validate_native_images(fake, runtime, signed, 'server_refused')
            else:
                base.validate_native_images(fake, runtime, signed, 'bootstrap_stop')
        if role == 'server':
            need(any(row['event'] == 'server_ready' for row in rows), 'missing_server_ready')
            server_handshakes = [row for row in rows if row['event'] == 'server_handshake']
            continue
        registration = record['hello']
        base.native_snapshot(registration, 4096)
        need(registration.get('nonce') == nonce and registration.get('pgid') == by_role['loader']['identity']['pid'] and
             all(registration.get(key) == value for key, value in identity.items()), 'registration_record_binding')
        if role != 'loader':
            parent = by_role.get(record.get('parent_role'))
            need(parent is not None and identity['ppid'] == parent['identity']['pid'], 'registration_parent_binding')
        need(record.get('exited') is True and type(record.get('exit_status')) is int and
             record.get('exit_code') == os.waitstatus_to_exitcode(record['exit_status'] & 0xffff),
             'descendant_exit_unobserved')
        continuation = [row for row in rows if row['event'] == 'stage3_pe_continue']
        if continuation:
            need(len(continuation) == 1 and generation == 1, 'pe_startup_sequence')
            order = [row['event'] for row in rows if row['event'] not in {'image', 'images_end', *ARENA_EVENTS, *DYNAMIC_EVENTS}]
            until = order[:order.index('stage3_pe_continue') + 1]
            initial = ['loader_entry', 'ntdll_entry'] if role == 'loader' else ['stage3_fork']
            need(until == initial + ['loader_reexec', 'loader_entry', 'ntdll_entry', 'server_peer',
                 'server_handshake', 'bootstrap_native', 'memory', 'stage3_pe_continue'], 'pe_loader_route')
            memory = [row for row in rows if row['event'] == 'memory']
            need(len(memory) == 1, 'pe_memory_observation')
            expected_memory = {'pagezero_address': 0, 'pagezero_size': 65536, 'low_address': 0x7ffe0000,
                               'region_address': 0x7ffe0000, 'region_size': 4096,
                               'region_protection': 1, 'region_error': 0}
            need(all(type(memory[0].get(key)) is int and memory[0][key] == value
                     for key, value in expected_memory.items()) and
                 all(type(memory[0].get(key)) is int and memory[0][key] > 0
                     for key in ('null_read_error', 'guard_end_read_error')), 'pe_memory_geometry')
            peer = [row for row in rows if row['event'] == 'server_peer']
            handshake = [row for row in rows if row['event'] == 'server_handshake']
            need(len(peer) == len(handshake) == 1 and peer[0].get('peer_pid') == server['identity']['pid'] and
                 peer[0].get('peer_error') == 0 and handshake[0].get('peer_pid') == server['identity']['pid'],
                 'pe_server_peer')
            executed.append((role, handshake[0]))
        else:
            need(role != 'loader' and registration.get('kind') == 'fork' and
                 all(row['event'] in ('stage3_fork', 'image', 'images_end') for row in rows) and
                 record['exit_code'] == 0, 'unexplained_native_intermediate')
    need(len(server_handshakes) == len(executed), 'server_handshake_coverage')
    for role, handshake in executed:
        matches = [row for row in server_handshakes if row.get('peer_pid') == by_role[role]['identity']['pid']]
        need(len(matches) == 1 and matches[0].get('server_start') == handshake.get('server_start') and
             isinstance(handshake.get('server_start'), str) and re.fullmatch('[1-9][0-9]{0,19}', handshake['server_start']),
             'reciprocal_server_handshake')
    return len(executed)


def assess_arena_events(result, signed, private_lifetime):
    """Reconstruct actual native arena generations in every PE-owning loader.

    Caller first binds every event to a registered PID, birth, nonce and raw
    pipe. These checks establish the finite diagnostic timeline, not safety
    against arbitrary dangling guest pointers or concurrent modification.
    """
    need(signed.get('code_publication_policy') == 'page-wx', 'api_publication_policy')
    capacity_record = signed.get('arena_capacity', {})
    limits = capacity_record.get('limits', {})
    need(capacity_record.get('policy') == 'page-wx' and capacity_record.get('wine_execution') is False and
         isinstance(capacity_record.get('header_sha256'), str) and
         re.fullmatch('[0-9a-f]{64}', capacity_record['header_sha256']) and
         set(limits) == {'interior_bytes', 'alignment', 'max_image_bytes', 'max_slots', 'page_bytes'} and
         all(type(value) is int and 0 < value < 2**40 for value in limits.values()) and
         limits['alignment'] == 65536 and limits['page_bytes'] == 4096 and
         limits['interior_bytes'] % limits['alignment'] == 0, 'arena_build_capacity')
    public, root_pairs, root_publications = [], [], []
    for role, rows in result['events'].items():
        events = [row for row in rows if row['event'] in ARENA_EVENTS]
        executes = any(row['event'] == 'stage3_pe_continue' for row in rows)
        if not executes:
            need(not events, 'arena_unexpected_process')
            continue
        need(events and events[0]['event'] == 'arena_reserve', 'arena_reservation_missing')
        reserve = events[0]
        dynamic_bytes = validate_budget(rows, capacity_record, reserve)
        constants = {'mapping_bytes': limits['interior_bytes'] + limits['alignment'] + dynamic_bytes,
                     **{key: limits[key] for key in ('interior_bytes', 'page_bytes', 'max_slots')}}
        need(all(type(reserve.get(key)) is int and reserve[key] == value
                 for key, value in constants.items()), 'arena_capacity_contract')
        mapping, interior = reserve.get('mapping_base'), reserve.get('interior_base')
        need(type(mapping) is int and type(interior) is int and 0 < mapping <= interior and
             mapping % 4096 == 0 and interior % 65536 == 0 and interior - mapping < 65536 and
             interior + reserve['interior_bytes'] <= mapping + reserve['mapping_bytes'] < 2**64,
             'arena_reservation_bounds')
        slots, completed, publications = {}, [], []
        totals = {'publications': 0, 'retirements': 0, 'compatible_reuses': 0,
                  'published_code_pages': 0, 'published_data_pages': 0, 'relocations': 0}
        for sequence, row in enumerate(events, 1):
            need(row.get('policy') == 'page-wx' and type(row.get('arena_sequence')) is int and
                 row['arena_sequence'] == sequence and row.get('generation') == 1,
                 'arena_policy_sequence')
            event = row['event']
            need(event != 'arena_failure', 'arena_operation_failed')
            if event == 'arena_reserve':
                need(sequence == 1, 'arena_multiple_reservations')
                continue
            slot, generation = row.get('slot'), row.get('slot_generation')
            need(type(slot) is int and 0 <= slot < reserve['max_slots'] and
                 type(generation) is int and 1 <= generation <= 2**64 - 1,
                 'arena_slot_identity')
            size, capacity, address = row.get('size'), row.get('capacity'), row.get('base')
            need(all(type(value) is int for value in (size, capacity, address)) and
                 0 < size <= capacity <= limits['max_image_bytes'] and size % 4096 == 0 and capacity % 65536 == 0 and
                 address % 65536 == 0 and interior <= address and
                 address + capacity <= interior + reserve['interior_bytes'], 'arena_slot_bounds')
            previous = slots.get(slot)
            if event == 'arena_publish':
                need(type(row.get('original_base')) is int and 0 <= row['original_base'] < 2**64 and
                     row['original_base'] % 65536 == 0, 'arena_original_image_base')
                need(type(row.get('reused')) is bool, 'arena_reuse_type')
                if previous:
                    need(not previous['live'] and generation == previous['slot_generation'] + 1 and
                         address == previous['base'] and capacity == previous['capacity'] and row['reused'],
                         'arena_unsafe_reuse')
                else:
                    need(generation == 1 and row['reused'] is False and all(
                         address + capacity <= known['base'] or known['base'] + known['capacity'] <= address
                         for known in slots.values()), 'arena_overlapping_or_unknown_slot')
                need(all(type(row.get(key)) is int and 0 <= row[key] <= size // 4096
                         for key in ('code_pages', 'data_pages')) and
                     0 < row['code_pages'] + row['data_pages'] <= size // 4096 and
                     type(row.get('relocations')) is int and 0 <= row['relocations'] <= size // 8,
                     'arena_publication_counts')
                slots[slot] = {**row, 'live': True}
                publications.append(row)
                totals['publications'] += 1
                totals['compatible_reuses'] += int(row['reused'])
                for source, target in [('code_pages', 'published_code_pages'),
                                       ('data_pages', 'published_data_pages'), ('relocations', 'relocations')]:
                    totals[target] += row[source]
            else:
                need(event == 'arena_retire' and previous is not None and previous['live'] and
                     all(row[key] == previous[key] for key in
                         ('slot_generation', 'base', 'size', 'capacity')), 'arena_retirement_identity')
                completed.append((previous, row))
                previous['live'] = False
                totals['retirements'] += 1
        need(totals['publications'] > 0 and totals['published_code_pages'] > 0, 'arena_publication_missing')
        public.append({'role': role, 'policy': 'page-wx', **totals,
                       'live_images_at_last_observation': sum(row['live'] for row in slots.values())})
        if role == 'loader':
            root_pairs, root_publications = completed, publications
    need(public, 'arena_observations_missing')
    if result['case']['id'] == 'abi':
        need(private_lifetime, 'lifetime_native_binding_missing')
        expected = private_lifetime[::2]
        publications = [row for row in root_publications if row['base'] == expected[0]['module_base']]
        need(len(expected) == 32 and len(publications) >= len(expected), 'lifetime_native_retirement_count')
        # The earlier rejected imports may load and retire this provider at the
        # same slot. The pinned fixture performs no further DLL loads after its
        # 32 rounds; every one of those final published generations must retire.
        retired = {(publish['slot'], publish['slot_generation']): retire for publish, retire in root_pairs}
        publications = publications[-len(expected):]
        need(all((row['slot'], row['slot_generation']) in retired for row in publications),
             'lifetime_native_retirement_missing')
        pairs = [(row, retired[row['slot'], row['slot_generation']]) for row in publications]
        for index, (observed, pair) in enumerate(zip(expected, pairs)):
            publish, retire = pair
            need(publish['base'] == observed['module_base'] and
                 publish['base'] <= observed['callback_address'] < publish['base'] + publish['size'] and
                 publish['arena_sequence'] < retire['arena_sequence'] and
                 (not index or publish['reused'] and
                  publish['slot'] == pairs[index - 1][0]['slot'] and
                  publish['slot_generation'] == pairs[index - 1][0]['slot_generation'] + 1),
                 'lifetime_native_generation_binding')
    return public


def assess_descendant_exits(result, controlled_exits=None):
    """Unexpected native crashes never become passing cleanup side effects.

    A post-cleanup signal exit is accepted only for a registered process alive
    at an observed owned-group signal of that exact number. This classifies a
    bounded cleanup window, not proof of an arbitrary signal's external cause.
    """
    controlled_exits = controlled_exits or {}
    need(not controlled_exits or result['case']['id'] == 'threads' and len(controlled_exits) == 1 and
         all(value == {'native_exit': 5, 'windows_exit': 0xc0000005, 'native_reported_status': -1073741819}
             for value in controlled_exits.values()), 'controlled_exit_scope')
    snapshot = result.get('pre_cleanup', {})
    need(type(snapshot.get('at_ns')) is int and snapshot['at_ns'] > 0 and
         isinstance(snapshot.get('processes'), dict), 'pre_cleanup_snapshot_missing')
    registrations = {row['role']: row for row in result['registrations']}
    need(set(controlled_exits).issubset(set(registrations) - {'loader'}), 'controlled_exit_registration')
    need(set(snapshot['processes']) == set(registrations), 'late_or_unobserved_registration')
    signals = result.get('signal_observations')
    need(isinstance(signals, list) and len(signals) <= 9, 'cleanup_signal_observation')
    actual = [(entry['role'], entry['signal']) for name in ('cleanup', 'sentinel_cleanup')
              for entry in result[name]['signals']]
    need([(row.get('role'), row.get('signal')) for row in signals] == actual, 'cleanup_signal_binding')
    previous_signal_ns = snapshot['at_ns']
    for signal_row in signals:
        need(type(signal_row.get('at_ns')) is int and signal_row['at_ns'] >= previous_signal_ns and
             isinstance(signal_row.get('live_registered_roles'), list) and
             set(signal_row['live_registered_roles']).issubset(registrations), 'cleanup_signal_time')
        previous_signal_ns = signal_row['at_ns']
        if signal_row['role'] == 'server':
            need(not signal_row['live_registered_roles'] and
                 all(type(row.get('exit_observed_ns')) is int and
                     0 < row['exit_observed_ns'] <= signal_row['at_ns'] for row in registrations.values()),
                 'server_shutdown_before_descendants')
    for role, row in registrations.items():
        before = snapshot['processes'][role]
        need(type(before.get('exited')) is bool and type(row.get('exit_observed_ns')) is int and
             row['exit_observed_ns'] > 0, 'descendant_exit_observation')
        exit_code = row['exit_code']
        allowed_normal = (0, 37) if result['case']['id'] == 'api' and role != 'loader' else (0,)
        if role in controlled_exits:
            allowed_normal += (controlled_exits[role]['native_exit'],)
        if before['exited']:
            need(before['exit_code'] == exit_code and before['exit_status'] == row['exit_status'] and
                 row['exit_observed_ns'] <= snapshot['at_ns'] and exit_code in allowed_normal,
                 'unexpected_pre_cleanup_descendant_exit')
        else:
            need(before.get('exit_code') is None and before.get('exit_status') is None and
                 row['exit_observed_ns'] >= snapshot['at_ns'], 'descendant_exit_timing')
            if exit_code not in allowed_normal:
                need(exit_code in (-int(signal.SIGINT), -int(signal.SIGTERM), -int(signal.SIGKILL)) and
                     any(signal_row['role'] == 'loader' and signal_row['signal'] == -exit_code and
                         role in signal_row['live_registered_roles'] and
                         signal_row['at_ns'] <= row['exit_observed_ns'] for signal_row in signals),
                     'unexpected_cleanup_window_exit')
        if exit_code in allowed_normal and before['exited']:
            # A complete PE process that exited before shutdown must report its
            # actual guest termination status. Intermediates never enter PE.
            rows = result['events'][role]
            if any(event['event'] == 'stage3_pe_continue' for event in rows):
                need(any(event['event'] in ('stage3_guest_exit', 'stage3_process_exit') and
                         type(event.get('exit_code')) is int and event['exit_code'] == (controlled_exits[role]['native_reported_status']
                         if role in controlled_exits else exit_code)
                         for event in rows), 'missing_completed_guest_exit')


def assess_case(result, raw_logs, runtime, signed, *, case_root=None):
    need(result.get('schema_version') == 1 and result.get('record_kind') == 'wine_api_case', 'api_case_version')
    validate_environment_policy(result.get('environment_policy'))
    stage4 = result.get('case', {}).get('id') == 'threads'
    stage5 = result.get('case', {}).get('id') == 'window'
    if stage4:
        validate_suite_authorization(STAGE4_SUITE, signed)
    if stage5:
        validate_suite_authorization(STAGE5_SUITE, signed)
        graphical = result.get('graphical_session')
        need(isinstance(graphical, dict) and set(graphical) == {'status', 'available'} and
             type(graphical.get('status')) is int and graphical['status'] == 0 and
             graphical.get('available') is True, 'graphical_session_unavailable')
    else:
        need('graphical_session' not in result, 'unexpected_graphical_precondition')
    expected_environment = {**LOADER_ENVIRONMENT, **({'PEAR_WINE_STAGE4_FIXTURE': '1'} if stage4 else {}),
                            **({'PEAR_WINE_STAGE5_FIXTURE': '1'} if stage5 else {})}
    need(result.get('loader_environment') == expected_environment, 'api_loader_environment')
    need(result.get('error') is None and result.get('stream_error') is None and result.get('outcome') == 'exited',
         'api_operation_failed')
    need(result.get('runtime_qualified') is False and result.get('pe_executed') is True, 'api_qualification_scope')
    need(set(result['processes']) == {'loader', 'server', 'sentinel'}, 'direct_process_coverage')
    identities = [row.get('identity') for row in result['processes'].values()]
    need(all(isinstance(identity, dict) and set(identity) == {'pid', 'ppid', 'start_sec', 'start_usec'} and
             all(type(value) is int for value in identity.values()) and identity['pid'] > 1 and
             identity['ppid'] > 1 and identity['start_sec'] > 0 and 0 <= identity['start_usec'] < 1000000
             for identity in identities) and len({item['pid'] for item in identities}) == 3 and
             len({item['ppid'] for item in identities}) == 1, 'invalid_direct_identity')
    for role, process in result['processes'].items():
        names = ['api_launch', 'loader'] if role == 'loader' else [role]
        paths = sorted(str((runtime / signed['entrypoints'][name]).resolve()) for name in names)
        need(process.get('allowed_paths') == paths, 'changed_process_executables')
    for name, roles in [('cleanup', {'loader', 'server'}), ('sentinel_cleanup', {'sentinel'})]:
        item = result[name]
        need(all(entry.get('role') in roles and type(entry.get('signal')) is int and
                 entry['signal'] in (int(signal.SIGINT), int(signal.SIGTERM), int(signal.SIGKILL))
                 for entry in item.get('signals', [])), 'cleanup_signal_scope')
        need(item.get('complete') is True and item.get('errors') == [] and item.get('observation_gap') is False and
             set(item.get('reaped', {})) == roles and all(value is True for value in item['reaped'].values()),
             'api_cleanup_incomplete')
    need(all(row.get('reaped') is True for row in result['processes'].values()), 'direct_child_not_reaped')
    need(result.get('sentinel_survived') is True and result['sentinel_cleanup']['signals'] == [], 'sentinel_lost')
    loader = SimpleNamespace(identity=result['processes']['loader']['identity'])
    sentinel = SimpleNamespace(identity=result['processes']['sentinel']['identity'])
    sentinel_rows = [decode_json(line) for line in raw_logs[('sentinel', 'stdout')].splitlines()]
    need(len(sentinel_rows) == 2 and sentinel_rows[1] ==
         {'version': 1, 'record_kind': 'pear_sentinel_done', 'signal': 0, 'command': 81}, 'sentinel_changed')
    base.validate_helper(sentinel_rows[0], 'pear_sentinel_ready', sentinel)
    need(result['processes']['sentinel']['exit_code'] == 0 and
         result['processes']['loader']['exit_code'] == result['case']['expected_exit'], 'api_exit_failed')
    _, private_lifetime, private_relocation = fixture_observations(raw_logs[('loader', 'stdout')], result['case']['id'], loader)
    for role, rows in result['events'].items():
        lines = raw_logs[(role, 'events')].splitlines()
        parsed = [decode_json(line, 32768) for line in lines]
        need(all(len(line) + 1 <= 512 for line, row in zip(lines, parsed)
                 if row.get('event') in STAGE4_EVENTS or row.get('event') == 'stage5_window'),
             'window_native_atomic_record_bound' if stage5 else 'stage4_native_atomic_record_bound')
        need(parsed == rows, 'event_log_mismatch')
    pe_count = assess_native_events(result, runtime, signed)
    validate_stage4_native_scope(result)
    if stage5:
        from window_evidence import validate_native_scope as validate_stage5_native_scope
        validate_stage5_native_scope(result)
    else:
        need(not any(row['event'] in STAGE5_EVENTS for rows in result['events'].values() for row in rows),
             'window_native_scope')
    arena = assess_arena_events(result, signed, private_lifetime)
    relocation = (assess_relocation_events(result, private_relocation, runtime, signed, case_root)
                  if result['case']['id'] == 'abi' else None)
    dynamic = assess_dynamic_events(result, signed)
    stage4_observations, controlled_exits = None, {}
    if stage4:
        from exception_evidence import assess as assess_stage4, decode_stdout_row
        rows = [decode_stdout_row(line) for line in raw_logs[('loader', 'stdout')].splitlines()[1:]]
        stage4_observations, controlled_exits = assess_stage4(rows, result, runtime, signed, dynamic)
    window_observations = None
    if stage5:
        from window_evidence import assess as assess_window, decode_stdout_row
        rows = [decode_stdout_row(line) for line in raw_logs[('loader', 'stdout')].splitlines()[1:]]
        window_observations = assess_window(rows, result, runtime, signed, dynamic)
    assess_descendant_exits(result, controlled_exits)
    root_rows = result['events']['loader']
    need(any(row['event'] == 'stage3_guest_exit' and row.get('exit_code') == 0 for row in root_rows),
         'missing_real_guest_exit')
    if result['case']['id'] == 'api':
        child_rows = [row for row in result['registrations'] if row['role'] != 'loader' and row.get('exit_code') == 37]
        need(len(child_rows) == 1 and any(event['event'] == 'stage3_guest_exit' and event.get('exit_code') == 37
             for event in result['events'][child_rows[0]['role']]), 'api_child_execution_unproven')
    need(pe_count >= 2, 'wine_prefix_initialization_unobserved')
    return {'passed': True, 'native_processes': len(result['registrations']) + 2, 'pe_processes': pe_count,
            'code_publication_policy': 'page-wx', 'environment_policy': dict(ENVIRONMENT_POLICY),
            'arena_observations': arena, **({'relocation_observations': relocation} if relocation else {}),
            **({'dynamic_observations': dynamic} if dynamic['dynamic_supported'] else {}),
            **({'thread_memory_exception_observations': stage4_observations} if stage4 else {}),
            **({'window_observations': window_observations} if stage5 else {})}


def run_case(case, runtime, signed, output, bounds):
    # Private diagnostics reuse this boundary. Require the fixed original case
    # and actual Stage 5 authorization before granting its larger envelope.
    suite = 'api-abi'
    if case.get('id') == 'window':
        need(case == WINDOW_CASE and all(type(case.get(key)) is int for key in
             ('timeout_ms', 'expected_exit')), 'unsupported_api_cases')
        validate_suite_authorization(STAGE5_SUITE, signed)
        suite = STAGE5_SUITE
    output.mkdir(mode=0o700)
    home, prefix, work = output / 'home', output / 'prefix', output / 'work'
    for path in (home, prefix, work, home / 'tmp'):
        path.mkdir(mode=0o700)
    prefix_record = base.prefix_identity(prefix)
    nonce = uuid.uuid4().hex
    paths = {key: runtime.joinpath(*relative(value)) for key, value in signed['entrypoints'].items()}
    session = APISession(output, runtime, signed, nonce, suite=suite, case_id=case['id'])
    env = base.environment(home, prefix, nonce)
    loader_environment = None
    graphical = None
    read_fd, control = os.pipe()
    error, outcome, survived = None, 'not_started', False
    start = time.monotonic()
    deadline = start + case['timeout_ms'] / 1000
    remaining = lambda cap: max(0, min(cap, deadline - time.monotonic()))
    try:
        if case['id'] == 'window':
            graphical = graphical_session()
            need(graphical['available'], 'graphical_session_unavailable')
        sentinel = session.launch('sentinel', [str(paths['sentinel']), str(read_fd)], env, pass_fds=(read_fd,))
        os.close(read_fd)
        read_fd = None
        need(session.wait_for(lambda: b'\n' in session.streams[('sentinel', 'stdout')]['data'], remaining(5)),
             'sentinel_start_timeout')
        base.validate_helper(base.parse_lines(session, 'sentinel')[0], 'pear_sentinel_ready', sentinel)
        server_env = base.environment(home, prefix, nonce)
        server = session.launch('server', [str(paths['server']), '-f', '-p'], server_env, event_pipe=True)
        need(session.wait_for(lambda: any(row.get('event') == 'server_ready' for row in session.events['server'])
                             or server.exited, remaining(30)) and not server.exited, 'server_start_failed')
        env = fixture_loader_environment(home, prefix, nonce, session.endpoint, server.pid,
                                         stage4=case['id'] == 'threads', stage5=case['id'] == 'window')
        # Record the exact controlled values passed to the real launch boundary.
        loader_environment = {key: env[key] for key in LOADER_ENVIRONMENT}
        if case['id'] == 'threads':
            loader_environment['PEAR_WINE_STAGE4_FIXTURE'] = env['PEAR_WINE_STAGE4_FIXTURE']
        if case['id'] == 'window':
            loader_environment['PEAR_WINE_STAGE5_FIXTURE'] = env['PEAR_WINE_STAGE5_FIXTURE']
        # Popen's cwd is the dedicated writable fixture directory; prefix and home are separate.
        session.output = work
        try:
            loader = session.launch('loader', [str(paths['api_launch']), '--exec-4k', str(paths['loader']),
                                               str(paths[case['entrypoint']]), *case['args']], env,
                                    allowed_paths=[paths['api_launch'], paths['loader']])
        finally:
            session.output = output
        completed = session.wait_for(lambda: loader.exited, remaining(case['timeout_ms'] / 1000))
        outcome = 'exited' if completed else 'timeout'
    except KeyboardInterrupt:
        error, outcome = 'runner_interrupted', 'interrupted'
    except (Error, OSError, KeyError, ValueError, TypeError) as exc:
        error, outcome = getattr(exc, 'code', 'api_runner_operation_failed'), 'error'
    finally:
        if read_fd is not None:
            os.close(read_fd)
        try:
            session.observer.refresh()
        except (Error, OSError) as exc:
            error = error or getattr(exc, 'code', 'pre_cleanup_observation_failed')
        pre_cleanup = {'at_ns': time.monotonic_ns(),
                       'processes': {row['role']: {'exited': row['exited'], 'exit_code': row['exit_code'],
                                                'exit_status': row['exit_status']}
                                     for row in session.observer.registrations.values()}}
        cleanup = session.cleanup(('loader', 'server'), bounds)
        if 'sentinel' in session.children:
            sentinel = session.children['sentinel']
            try:
                session.observer.refresh()
                survived = not sentinel.exited and session.observer.identity(sentinel.pid) == sentinel.identity
                if survived:
                    os.write(control, b'Q')
                    finish = time.monotonic() + SENTINEL_WAIT_MS / 1000
                    while not sentinel.exited and time.monotonic() < finish:
                        session.pump()
            except (Error, OSError):
                survived = False
        os.close(control)
        sentinel_cleanup = session.cleanup(('sentinel',), bounds)
        logs = session.finish_logs(bounds['drain_ms'])
    record = {'schema_version': 1, 'record_kind': 'wine_api_case', 'case': case, 'nonce': nonce,
              'environment_policy': dict(ENVIRONMENT_POLICY), 'loader_environment': loader_environment,
              'prefix': prefix_record, 'outcome': outcome, 'error': error, 'stream_error': session.failure,
              'elapsed_ms': round((time.monotonic() - start) * 1000),
              'events': session.events, 'logs': logs, 'cleanup': cleanup, 'sentinel_cleanup': sentinel_cleanup,
              'sentinel_survived': survived, 'registrations': list(session.observer.registrations.values()),
              'pre_cleanup': pre_cleanup, 'signal_observations': session.observer.signal_observations,
              'processes': {role: {'identity': child.identity, 'allowed_paths': sorted(child.allowed_paths),
                                   'exit_code': child.exit_code, 'reaped': child.reaped}
                            for role, child in session.children.items()},
              'passed': False, 'assessment_error': None, 'runtime_qualified': False,
              'pe_executed': any(row.get('event') == 'stage3_guest_exit'
                                 for rows in session.events.values() for row in rows),
              'ownership_scope': 'reserved-root-session-with-registered-instrumented-descendants',
              'observation_limitations': ['post-fork-pre-registration-native-window',
                                         'instrumented-descendants-retain-root-process-group',
                                         'loaded-native-image-snapshots-not-general-load-timeline']}
    if case['id'] == 'window':
        record['graphical_session'] = graphical
    try:
        assessment = assess_case(record, {(role, channel): bytes(item['data'])
                                         for (role, channel), item in session.streams.items()}, runtime, signed, case_root=output)
        record['passed'] = assessment['passed']
    except (Error, KeyError, TypeError, ValueError, OSError) as exc:
        record['assessment_error'] = getattr(exc, 'code', 'api_case_evidence_invalid')
    base.write_new(output / 'case.json', record)
    return record


def target_controls(runtime, signed):
    requirements_path = runtime / 'requirements.json'
    need(sha256(requirements_path) == signed.get('requirements_sha256'), 'changed_signing_requirements')
    requirements = load_json(requirements_path)
    need(requirements.get('fixture_suite') in PE_SUITES, 'api_runtime_required')
    guests = requirements.get('guest_fixtures', {})
    results = []
    for role, machine in [('x64_control', 'x86_64'), ('i386_control', 'i386')]:
        # Actual current bytes are already checked by signing.validate_prepared.
        item = guests.get(role)
        need(isinstance(item, dict) and item.get('execution_permitted') is False, 'control_execution_forbidden')
        path = runtime / signed['entrypoints'][role]
        raw = path.read_bytes()
        need(raw[:2] == b'MZ' and len(raw) >= 64, 'control_pe_header')
        offset = struct.unpack_from('<I', raw, 0x3c)[0]
        need(offset + 24 <= len(raw) and raw[offset:offset + 4] == b'PE\0\0', 'control_pe_header')
        actual = struct.unpack_from('<H', raw, offset + 4)[0]
        need(actual == (0x8664 if role == 'x64_control' else 0x14c), 'control_pe_machine')
        need(hashlib.sha256(raw).hexdigest() == item.get('sha256'), 'control_bytes_changed')
        results.append({'role': role, 'machine': machine, 'sha256': item['sha256'], 'executed': False,
                        'accepted': False, 'reason': 'translator-not-qualified-for-target'})
    return results


def validate_suite_authorization(suite, signed):
    scopes = ('development_windows_api_abi_fixtures', 'development_windows_thread_memory_exception_fixtures',
              'development_windows_mac_driver_fixtures')
    need(suite in PE_SUITES and signed.get('authorization_scope') in scopes[PE_SUITES.index(suite):] and
         signed.get('code_publication_policy') == 'page-wx', 'api_authorization_required')
    if suite in (STAGE4_SUITE, STAGE5_SUITE):
        need(isinstance(signed.get('entrypoints'), dict) and 'stage4_pe' in signed['entrypoints'],
             'stage4_signed_entrypoint_missing')
    if suite == STAGE5_SUITE:
        need(all(name in signed['entrypoints'] for name in ('window_pe', 'window_driver_pe')),
             'stage5_signed_entrypoint_missing')


def run(runtime, output, require_empty, suite='api-abi'):
    from signing import validate_prepared
    need(require_empty, 'explicit_api_empty_output_required')
    runtime = Path(runtime).resolve()
    signed = validate_prepared(runtime)
    validate_suite_authorization(suite, signed)
    cases = validate_cases(load_json(cases_path(suite)), suite)
    controls = target_controls(runtime, signed)
    output = base.create_output(output)
    producer_hashes = snapshot_producers(output, suite)
    results, error, pe_seen = [], None, False
    for case in cases['cases']:
        result, gate = None, None
        try:
            need(validate_prepared(runtime) == signed, 'signed_runtime_changed')
            need(producers(suite) == producer_hashes, 'api_producer_changed')
            result = run_case(case, runtime, signed, output / case['id'], cases['bounds'])
            need(validate_prepared(runtime) == signed, 'signed_runtime_changed')
            need(producers(suite) == producer_hashes, 'api_producer_changed')
        except KeyboardInterrupt:
            gate = 'runner_interrupted'
        except (Error, OSError) as exc:
            gate = getattr(exc, 'code', 'api_run_failed')
        if result is None:
            error = gate or 'missing_case_record'
            break
        pe_seen |= result['pe_executed']
        results.append(base.write_case_assessment(output, case['id'], result, gate))
        if gate or not result['passed']:
            error = gate or result['assessment_error']
            break
    record = {'schema_version': 1, 'record_kind': 'wine_api_run', 'suite': suite,
              'environment_policy': dict(ENVIRONMENT_POLICY),
              'code_publication_policy': signed['code_publication_policy'],
              'producer_sha256': producer_hashes,
              'cases_sha256': sha256(cases_path(suite)),
              'runtime_path': runtime.relative_to(REPO.resolve()).as_posix(),
              'signed_sha256': sha256(runtime / 'signed.json'), 'cases': results, 'controls': controls,
              'error': error, 'passed': error is None and len(results) == len(cases['cases']) and
                                      all(row['passed'] for row in results),
              'runtime_qualified': False, 'pe_executed': pe_seen}
    base.write_new(output / 'run.json', record)
    return record


def verify_logs(root, case_id, result, *, suite='api-abi'):
    required = {(role, channel) for role in ('server', 'loader', 'sentinel') for channel in ('stdout', 'stderr')}
    required |= {(role, 'events') for role in result['events']}
    logs = result.get('logs')
    need(isinstance(logs, list) and len(logs) == len(required) and
         {(row.get('role'), row.get('channel')) for row in logs} == required, 'api_log_coverage')
    raw, total = {}, 0
    for row in logs:
        role, channel = row['role'], row['channel']
        need(role in ('loader', 'server', 'sentinel') or re.fullmatch('process-[0-9]{2}', role), 'unsafe_process_role')
        name = role + '.' + channel + '.log'
        need(row.get('path') == name, 'api_log_path')
        data = read_relative(root, case_id + '/' + name,
                             event_limit(role, suite=suite, case_id=case_id) if channel == 'events' else base.STREAM_LIMIT)
        need(row.get('bytes') == len(data) == row.get('observed_bytes') and row.get('eof') is True and
             row.get('write_error') is None and hashlib.sha256(data).hexdigest() == row.get('sha256'),
             'api_log_integrity')
        if channel == 'events':
            total += len(data)
            need(not data or data.endswith(b'\n'), 'truncated_event_log')
        raw[(role, channel)] = data
    need(total <= TOTAL_EVENTS, 'api_event_output_limit')
    return raw


def validate_runs(root, suite='api-abi'):
    from signing import owned, validate_prepared
    root = owned(root)
    raw = read_relative(root, 'run.json')
    record = decode_json(raw)
    need(record.get('schema_version') == 1 and record.get('record_kind') == 'wine_api_run' and
         suite in PE_SUITES and record.get('suite') == suite, 'api_run_version')
    validate_environment_policy(record.get('environment_policy'))
    need(record.get('producer_sha256') == producers(suite) and record.get('cases_sha256') == sha256(cases_path(suite)),
         'stale_api_producer')
    for name, expected in record['producer_sha256'].items():
        need(hashlib.sha256(read_relative(root, 'producer/' + name)).hexdigest() == expected,
             'api_producer_snapshot_changed')
    runtime = owned(REPO.joinpath(*relative(record.get('runtime_path'))))
    signed = validate_prepared(runtime)
    validate_suite_authorization(suite, signed)
    need(record.get('code_publication_policy') == signed.get('code_publication_policy') == 'page-wx',
         'api_publication_policy')
    need(record.get('signed_sha256') == sha256(runtime / 'signed.json') and
         record.get('controls') == target_controls(runtime, signed), 'changed_api_runtime')
    need(record.get('error') is None and record.get('runtime_qualified') is False and
         record.get('pe_executed') is True, 'api_run_not_accepted')
    cases = validate_cases(load_json(cases_path(suite)), suite)
    need(isinstance(record.get('cases'), list) and [row.get('id') for row in record['cases']] ==
         [case['id'] for case in cases['cases']], 'api_case_coverage')
    summaries, nonces = [], set()
    for row, expected in zip(record['cases'], cases['cases']):
        case_id = expected['id']
        need(row.get('path') == case_id + '/case.json' and
             row.get('assessment_path') == case_id + '/assessment.json', 'api_record_path')
        data = read_relative(root, row['path'], case_json_limits(suite=suite, case_id=case_id)[0])
        gate = read_relative(root, row['assessment_path'])
        need(hashlib.sha256(data).hexdigest() == row.get('sha256') and
             hashlib.sha256(gate).hexdigest() == row.get('assessment_sha256'), 'changed_api_record')
        need(decode_json(gate) == {'schema_version': 1, 'record_kind': 'wine_case_gate_assessment',
                                  'case_sha256': row['sha256'], 'passed': True, 'error': None}, 'api_case_gate')
        result = decode_case(data, suite=suite, case_id=case_id)
        need(result.get('case') == expected and result.get('passed') is True and row.get('passed') is True,
             'api_case_configuration')
        need(isinstance(result.get('nonce'), str) and re.fullmatch('[0-9a-f]{32}', result['nonce']) and
             result['nonce'] not in nonces, 'api_nonce_reuse')
        nonces.add(result['nonce'])
        prefix = root / case_id / 'prefix'
        info = prefix.stat()
        need(not prefix.is_symlink() and result['prefix']['device'] == info.st_dev and
             result['prefix']['inode'] == info.st_ino, 'api_prefix_changed')
        validate_duration(result.get('elapsed_ms'), expected['timeout_ms'], cases['bounds'])
        assessment = assess_case(result, verify_logs(root, case_id, result, suite=suite), runtime, signed, case_root=root / case_id)
        summaries.append({'id': case_id, 'case_sha256': row['sha256'], **assessment,
                          'fixture_results': expected_fixture_rows(case_id),
                          'cleanup_complete': True, 'sentinel_survived': True})
    need(record.get('passed') is True and validate_prepared(runtime) == signed, 'api_run_changed')
    return {'schema_version': 1, 'record_kind': ('wine_api_abi_assessment' if suite == 'api-abi' else 'wine_thread_memory_exception_assessment' if suite == STAGE4_SUITE
                else 'wine_mac_driver_assessment'), 'suite': suite,
            'environment_policy': dict(ENVIRONMENT_POLICY),
            'run_sha256': hashlib.sha256(raw).hexdigest(), 'signed_sha256': record['signed_sha256'],
            'code_publication_policy': 'page-wx', 'producer_sha256': producers(suite), 'cases': summaries, 'case_count': len(summaries),
            'controls': record['controls'], 'passed': True, 'pe_executed': True, 'runtime_qualified': False,
            'evidence_scope': ('instrumented-arm64-pe-api-abi-with-constrained-owned-descendants' if suite == 'api-abi'
                else 'instrumented-arm64-thread-memory-exception-with-constrained-owned-descendants' if suite == STAGE4_SUITE
                else 'instrumented-arm64-mac-driver-with-constrained-owned-descendants'),
            'game_qualified': False,
            'observation_limitations': ['post-fork-pre-registration-native-window',
                                       'instrumented-descendants-retain-root-process-group',
                                       'loaded-native-image-snapshots-not-general-load-timeline']}
