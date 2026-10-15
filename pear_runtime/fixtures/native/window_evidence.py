"""Source-bound finite Win32/Cocoa fixture evidence; all addresses stay private.

The caller verifies process identity, signed bytes, raw logs and image UUIDs.
This module binds twenty owned lifetimes to the real driver and guest exports.
It does not establish rendering support or arbitrary future callback safety.
"""
import hashlib
import json
from pathlib import Path

from common import Error, _json_preflight, need, read_relative
from modules import PE
from abi_review import macho

CYCLES = 20
MESSAGE = 0x8351
TOKEN_BASE = 0x53350000
REPLY_XOR = 0x13579bdf
WAKE_TAG = 0x505335
IDLE_FLAGS = 15
MAX_DRAINS = 100
MAX_TURNS = 100
MAX_NATIVE_PARTS = 527 + 4 * CYCLES * (MAX_DRAINS + MAX_TURNS)
LIFETIME_PHASES = {*range(1, 16), 17, 18}
NATIVE_EVENTS = frozenset({'stage5_window', 'stage5_window_images'})
NATIVE_BASE = {'version', 'role', 'event', 'nonce', 'pid', 'ppid', 'generation',
               'start_sec', 'start_usec', 'identity_error'}
PART_FIELDS = {1: ('hwnd', 'window', 'token'), 2: ('thread_id', 'main', 'mode', 'value'),
               3: ('driver_base', 'driver_entry', 'teb', 'native_tid')}
FINAL = dict(passed=1, error_step=0, error_code=0, cycles=20, app_messages=20,
             reentries=20, closes=20, destroys=20, ncdestroys=20, late_callbacks=0,
             class_registered=1, class_unregistered=1, native_final=1, cleanup_complete=1)
FIELDS = {
    'pear_window_identity': ('module_base wndproc guest_teb guest_tid native_pid driver_module driver_control cycles').split(),
    'pear_window_cycle': ('cycle hwnd token guest_teb guest_tid nccreate create app_messages reentries sysclose close '
                          'destroy ncdestroy late_callbacks title_checks hwnd_gone drain_complete callback_result').split(),
    'pear_window_result': list(FINAL),
}
UNQUALIFIED = ['metal_rendering', 'dxmt_driver_pairing', 'general_callbacks', 'native_created_guest_callback_thread',
               'x64_guest_translation', 'game_execution', 'ordinary_user_distribution']


def integer(value, low=0, high=2**64 - 1):
    return type(value) is int and low <= value <= high


def expected_results():
    return [{'version': 1, 'record_kind': 'pear_window_result', **FINAL}]


def validate_row(row):
    need(isinstance(row, dict) and type(row.get('record_kind')) is str and
         row['record_kind'] in FIELDS, 'window_row_kind')
    fields = FIELDS[row['record_kind']]
    need(set(row) == {'version', 'record_kind', *fields} and type(row.get('version')) is int and
         row['version'] == 1 and all(integer(row[key]) for key in fields), 'window_row_fields')
    return row


def decode_stdout_row(data):
    """Decode only this flat private uint64 wire schema, retaining shared limits."""
    need(isinstance(data, bytes) and len(data) <= 3072, 'window_stdout_size')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    def unsigned(token):
        need(len(token) <= 20 and not token.startswith('-'), 'window_stdout_uint64')
        value = int(token)
        need(value < 2**64, 'window_stdout_uint64')
        return value
    def forbidden(_):
        raise Error('window_stdout_noninteger')
    try:
        text = data.decode('utf-8')
        _json_preflight(text, 1 + 2 * (2 + max(map(len, FIELDS.values()))))
        row = json.loads(text, object_pairs_hook=pairs, parse_int=unsigned,
                         parse_float=forbidden, parse_constant=forbidden)
    except (UnicodeError, ValueError, RecursionError):
        raise Error('invalid_json') from None
    return validate_row(row)


def group_rows(rows):
    need(isinstance(rows, list) and len(rows) == CYCLES + 2, 'window_row_count')
    for row in rows:
        validate_row(row)
    need([row['record_kind'] for row in rows] == ['pear_window_identity'] +
         ['pear_window_cycle'] * CYCLES + ['pear_window_result'], 'window_row_order')
    identity, cycles, final = rows[0], rows[1:-1], rows[-1]
    need(identity['cycles'] == CYCLES and all(final[key] == value for key, value in FINAL.items()),
         'window_fixture_failed')
    for index, row in enumerate(cycles, 1):
        need(row['cycle'] == index and row['token'] == TOKEN_BASE + index and
             row['guest_tid'] == identity['guest_tid'] and row['guest_teb'] == identity['guest_teb'] and
             integer(row['hwnd'], 1) and row['callback_result'] == ((TOKEN_BASE + index) ^ REPLY_XOR),
             'window_cycle_identity')
        need(all(row[key] == 1 for key in ('nccreate', 'create', 'app_messages', 'reentries', 'sysclose', 'close',
             'destroy', 'ncdestroy', 'title_checks', 'hwnd_gone', 'drain_complete')) and
             row['late_callbacks'] == 0, 'window_cycle_failed')
    return identity, cycles


def fixture_rows(rows):
    group_rows(rows)
    return expected_results()


def validate_native_scope(result):
    for role, rows in result['events'].items():
        observed = [row for row in rows if row['event'] in NATIVE_EVENTS]
        need(not observed or result['case']['id'] == 'window' and role == 'loader', 'window_native_scope')


def native_parts(rows):
    selected = [(index, row) for index, row in enumerate(rows) if row['event'] == 'stage5_window']
    need(0 < len(selected) <= MAX_NATIVE_PARTS, 'window_native_part_count')
    merged, current, expected_part, previous_index = [], None, 1, None
    for index, row in selected:
        part = row.get('part')
        need(integer(part, 1, 3) and part == expected_part, 'window_native_part_order')
        need(type(row.get('version')) is int and row['version'] == 1 and
             set(row) == NATIVE_BASE | {'seq', 'cycle', 'phase', 'part'} | set(PART_FIELDS[part]) and
             all(integer(row[key], 0, 2**53 - 1) for key in ('seq', 'cycle', 'phase', 'part', *PART_FIELDS[part])),
             'window_native_part_fields')
        if part == 1:
            need(row['seq'] == len(merged) + 1 and 0 <= row['cycle'] <= CYCLES and 0 <= row['phase'] <= 19,
                 'window_native_sequence')
            current = {'seq': row['seq'], 'cycle': row['cycle'], 'phase': row['phase'], 'index': index}
        else:
            need(index == previous_index + 1, 'window_native_part_interleaving')
            need(all(row[key] == current[key] for key in ('seq', 'cycle', 'phase')), 'window_native_part_identity')
        current.update({key: row[key] for key in PART_FIELDS[part]})
        current['end_index'] = previous_index = index
        terminal = 3 if current['phase'] == 0 else 2
        if part == terminal:
            merged.append(current)
            current, expected_part = None, 1
        else:
            expected_part += 1
    need(current is None, 'window_native_partial_record')
    return merged, len(selected)


def _pe_fact(data, name):
    pe = PE(data)
    need(pe.machine == 0xaa64, 'window_pe_architecture')
    exports = [row for row in pe.exports() if row.get('name') == name]
    need(len(exports) == 1 and 'forwarder' not in exports[0], 'window_pe_export')
    rva = exports[0]['rva']
    sections = [row for row in pe.sections if row['rva'] <= rva < row['rva'] + row['virtual_size']]
    need(rva % 4 == 0 and len(sections) == 1 and sections[0]['characteristics'] & 0x20000000 and
         not sections[0]['characteristics'] & 0x80000000, 'window_pe_export_section')
    pe.offset(rva, 4)
    return {'image_size': pe.u('I', pe.opt + 56), 'original_base': pe.base, 'rva': rva,
            'sha256': hashlib.sha256(data).hexdigest()}


def fixture_facts(runtime, signed):
    fixture = _pe_fact(read_relative(runtime, signed['entrypoints']['window_pe'], 16 * 1024 * 1024), 'PearWindowProc')
    native_rows = [row for row in signed['native_images'] if row.get('source_path', '').endswith('/winemac.so')]
    need(len(native_rows) == 1, 'window_native_driver_identity')
    driver_path = native_rows[0]['path']
    native = read_relative(runtime, driver_path, 64 * 1024 * 1024)
    native_hash = hashlib.sha256(native).hexdigest()
    need(native_hash == native_rows[0]['sha256'], 'window_native_driver_changed')
    symbols, segments = macho(native, extra_symbols=('_pear_stage5_window_control',))
    need('_pear_stage5_window_control' in symbols, 'window_native_control_symbol')
    headers = [address for address, size, offset, _ in segments if offset == 0 and size >= 32]
    entry = symbols['_pear_stage5_window_control']
    need(len(headers) == 1 and entry % 4 == 0 and any(protection & 4 and address <= entry < address + size
         for address, size, _, protection in segments), 'window_native_control_section')
    # The built-in PE and native driver have separately checked actual bytes.
    control_path = signed['entrypoints']['window_driver_pe']
    control = _pe_fact(read_relative(runtime, control_path, 16 * 1024 * 1024), 'PearStage5Control')
    return {'fixture': fixture, 'control': control, 'native_sha256': native_hash,
            'native_path': driver_path, 'native_offset': entry - headers[0]}


def bind_image(rows, base, facts, begin, end):
    need(integer(base, 1) and base % 65536 == 0 and base + facts['image_size'] < 2**64, 'window_pe_base')
    matches = [index for index, row in enumerate(rows) if row['event'] == 'arena_publish' and
               row.get('base') == base and row.get('size') == facts['image_size'] and
               row.get('original_base') == facts['original_base']]
    need(len(matches) == 1, 'window_executed_image_binding')
    publication = matches[0]
    need(publication < begin <= end and not any(row['event'] == 'arena_retire' and row.get('base') == base
         and publication < index <= end for index, row in enumerate(rows)), 'window_executed_image_lifetime')


def image_snapshot(rows, runtime, facts, initialized_index, created_index):
    markers = [index for index, row in enumerate(rows) if row['event'] == 'stage5_window_images']
    need(len(markers) == 1 and initialized_index < markers[0] < created_index, 'window_image_snapshot_order')
    selected = []
    index = markers[0] + 1
    while index < len(rows) and rows[index]['event'] == 'image':
        selected.append(rows[index]); index += 1
    need(0 < len(selected) <= 2048 and index < len(rows) and rows[index]['event'] == 'images_end' and
         rows[index].get('count') == len(selected) and index < created_index, 'window_image_snapshot_complete')
    paths = [row.get('path') for row in selected]
    native_path = str((runtime / facts['native_path']).resolve())
    need(sum(isinstance(path, str) and str(Path(path).resolve()) == native_path for path in paths) == 1,
         'window_driver_not_loaded')
    for framework in ('AppKit', 'CoreFoundation'):
        need(any(isinstance(path, str) and path.startswith('/System/Library/Frameworks/' + framework + '.framework/')
             and Path(path).name == framework for path in paths), 'window_framework_not_loaded')
    return len(selected)


def assess(rows, result, runtime, signed, dynamic):
    identity, cycles = group_rows(rows)
    validate_native_scope(result)
    need(result['case']['id'] == 'window' and signed.get('authorization_scope') ==
         'development_windows_mac_driver_fixtures', 'window_authorization_scope')
    native_rows = result['events']['loader']
    events, parts = native_parts(native_rows)
    facts = fixture_facts(runtime, signed)
    need(integer(identity['guest_teb'], 1) and identity['guest_teb'] % 16 == 0 and
         integer(identity['guest_tid'], 1) and identity['native_pid'] == result['processes']['loader']['identity']['pid'],
         'window_guest_identity')
    bind_image(native_rows, identity['module_base'], facts['fixture'], events[0]['index'], events[-1]['end_index'])
    bind_image(native_rows, identity['driver_module'], facts['control'], events[0]['index'], events[-1]['end_index'])
    need(identity['wndproc'] == identity['module_base'] + facts['fixture']['rva'] and
         identity['driver_control'] == identity['driver_module'] + facts['control']['rva'], 'window_guest_control_binding')
    init, final_drain, final = events[0], events[-2], events[-1]
    need(init['phase'] == 0 and final['phase'] == 16 and init['cycle'] == final_drain['cycle'] == final['cycle'] == 0 and
         all(item[key] == 0 for item in (init, final_drain, final) for key in ('hwnd', 'window', 'token')) and
         init['value'] == 0 and final['value'] == CYCLES, 'window_native_endpoints')
    need(final_drain['phase'] == 19 and final_drain['value'] == IDLE_FLAGS, 'window_final_queue_idle')
    need(init['teb'] == identity['guest_teb'] and init['native_tid'] == identity['guest_tid'] and
         integer(init['driver_base'], 1) and init['driver_base'] % 4096 == 0 and
         init['driver_entry'] == init['driver_base'] + facts['native_offset'], 'window_native_control_binding')
    wine_tid, main_tid, queue = init['thread_id'], None, None
    need(integer(wine_tid, 1), 'window_native_thread_identity')
    main_phases = {1, 3, 4, 7, 10, 13, 17, 18}
    for event in events:
        need(event['mode'] == 0 and event['main'] in (0, 1) and integer(event['thread_id'], 1),
             'window_native_host_mode')
        if event['phase'] in main_phases:
            need(event['main'] == 1 and event['thread_id'] != wine_tid, 'window_main_thread_ownership')
            main_tid = main_tid or event['thread_id']
            need(event['thread_id'] == main_tid, 'window_main_thread_changed')
        elif event['phase'] != 12:
            need(event['main'] == 0 and event['thread_id'] == wine_tid, 'window_wine_thread_ownership')
        else:
            need(event['thread_id'] == (main_tid if event['main'] else wine_tid), 'window_deallocation_thread')
    need(main_tid is not None, 'window_main_thread_missing')
    offset, barriers, drains, turns = 1, 0, 0, 0
    for guest in cycles:
        own = []
        while offset < len(events) - 2 and events[offset]['cycle'] == guest['cycle']:
            own.append(events[offset]); offset += 1
        need(own and own[0]['phase'] == 1 and own[-1]['phase'] == 15 and
             all(event['phase'] in LIFETIME_PHASES for event in own), 'window_lifetime_order')
        window = own[0]['window']
        need(integer(window, 1) and window % 8 == 0 and all(event['hwnd'] == guest['hwnd'] and
             event['token'] == guest['token'] and event['window'] == window for event in own), 'window_lifetime_identity')
        by_phase = {phase: [event for event in own if event['phase'] == phase] for phase in LIFETIME_PHASES}
        need(all(len(by_phase[phase]) == 1 for phase in LIFETIME_PHASES if phase not in (13, 14, 17, 18)) and
             1 <= len(by_phase[13]) == len(by_phase[14]) <= MAX_DRAINS and
             1 <= len(by_phase[17]) == len(by_phase[18]) <= MAX_TURNS, 'window_lifetime_coverage')
        positions = {phase: by_phase[phase][0]['seq'] for phase in LIFETIME_PHASES}
        required = [1, 2, 3, 4, 5, 6, 8, 9, 10, 11]
        need([positions[p] for p in required] == sorted(positions[p] for p in required) and
             positions[5] < positions[7] < positions[8] and positions[11] < positions[12] < positions[15] and
             positions[11] < positions[13], 'window_callback_lifecycle_order')
        drain_events = [event for event in own if event['phase'] in (13, 14)]
        need([event['phase'] for event in drain_events] == [13, 14] * len(by_phase[13]) and
             all(event['value'] == i // 2 + 1 if event['phase'] == 13 else
                 event['value'] >> 4 == i // 2 + 1 for i, event in enumerate(drain_events)) and
             all(event['value'] & 8 for event in by_phase[14]) and
             drain_events[-1]['value'] & IDLE_FLAGS == IDLE_FLAGS and
             positions[12] < drain_events[-1]['seq'] and
             by_phase[18][-1]['seq'] < drain_events[-2]['seq'] < drain_events[-1]['seq'] < positions[15], 'window_teardown_barrier_order')
        wake_events = [event for event in own if event['phase'] in (17, 18)]
        turn_count = len(by_phase[17])
        need([event['phase'] for event in wake_events] == [17, 18] * turn_count and
             all(event['value'] == ((WAKE_TAG << 24) | (guest['cycle'] << 8) | (i // 2 + 1))
                 for i, event in enumerate(wake_events)) and
             positions[11] < wake_events[0]['seq'] and wake_events[-1]['seq'] < positions[15],
             'window_appkit_turn_order')
        posting_barriers = set()
        for ordinal, (posted, consumed) in enumerate(zip(by_phase[17], by_phase[18]), 1):
            # Each successful post belongs to one DRAIN main-thread block. That
            # block emits its barrier before AppKit can dispatch the queued wake.
            next_barriers = [i for i, event in enumerate(by_phase[13]) if event['seq'] > posted['seq']]
            need(next_barriers, 'window_appkit_posting_barrier')
            attempt = next_barriers[0]
            need((ordinal != 1 or attempt == 0) and attempt not in posting_barriers and
                 by_phase[13][attempt]['seq'] < consumed['seq'] and
                 (attempt == 0 or by_phase[14][attempt - 1]['seq'] < posted['seq']) and
                 (ordinal == 1 or posted['seq'] < positions[12]), 'window_appkit_posting_barrier')
            posting_barriers.add(attempt)
        need(all(event['value'] == 0 for event in own if event['phase'] in (2, 3, 4, 6, 7, 9, 10, 11, 12)) and
             by_phase[5][0]['value'] == MESSAGE and by_phase[8][0]['value'] == guest['callback_result'] and
             by_phase[15][0]['value'] == 1, 'window_native_operation_failed')
        queue = queue or by_phase[1][0]['value']
        need(integer(queue, 1) and by_phase[1][0]['value'] == queue, 'window_event_queue_ownership')
        barriers += len(by_phase[13]); drains += len(by_phase[14]); turns += turn_count
    need(offset == len(events) - 2, 'window_late_or_alien_lifetime')
    need(parts == 527 + 4 * barriers + 4 * turns, 'window_native_count_binding')
    loaded = image_snapshot(native_rows, runtime, facts, init['index'], events[1]['index'])
    exits = [index for index, row in enumerate(native_rows) if row['event'] == 'stage3_guest_exit']
    need(len(exits) == 1 and events[-1]['end_index'] < exits[0], 'window_exit_before_teardown')
    need(dynamic.get('dynamic_supported') is True and dynamic.get('root', {}).get('reservations') == 0 and
         all(item.get('reservations') == 0 for item in dynamic.get('processes', [])), 'window_dynamic_scope')
    return {'fixture_sha256': facts['fixture']['sha256'], 'driver_pe_sha256': facts['control']['sha256'],
            'native_driver_sha256': facts['native_sha256'], 'cycles': CYCLES, 'native_anchor_parts': parts,
            'native_image_snapshot_count': loaded, 'native_main_thread_verified': True,
            'wine_callback_thread_verified': True, 'cocoa_close_events': CYCLES, 'application_messages': CYCLES,
            'callback_reentries': CYCLES, 'destroyed_windows': CYCLES, 'deallocated_windows': CYCLES,
            'main_thread_barriers': barriers, 'event_drains': drains, 'appkit_event_turns': turns,
            'final_queue_idle_verified': True, 'observed_late_callbacks': 0,
            'active_windows_at_completion': 0, 'pending_owned_events_at_completion': 0,
            'loaded_driver_verified': True, 'loaded_appkit_verified': True, 'loaded_corefoundation_verified': True,
            'observation_scope': 'twenty_owned_lifetimes_through_final_barrier',
            'unqualified': list(UNQUALIFIED)}
