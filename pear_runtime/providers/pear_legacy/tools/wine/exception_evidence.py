"""Strict finite Stage 4 observations, bound to actual signed fixture bytes.

Private addresses remain local. Summaries describe these fixture paths only;
software exception handling, Darwin signals and controlled termination remain
separate observations and do not qualify arbitrary unwinding or translation.
"""
import hashlib
import json
import signal
import struct

from common import Error, _json_preflight, need, read_relative
from modules import PE
from abi_review import macho

ACCESS = 0xc0000005
GUARD = 0x80000001
SENTINEL = 0x3456789a
MEMORY = dict(error_step=0, error_code=0, queries=22, sentinel_checks=4, zero_bytes=28672,
    access_faults=2, guard_faults=1, ordinary_commits=2, ordinary_protects=3, ordinary_decommits=1,
    ordinary_releases=1, dynamic_reserves=2, dynamic_commits=3, dynamic_protects=3,
    dynamic_decommits=1, dynamic_releases=2, flushes=2, code_calls=2, first_value=42,
    second_value=84, reuse_checks=1, negative_controls=3)
FINAL = dict(passed=1, error_step=0, win32_error=0, workers=2, signals=2, suspends=1,
    injected_errors=2, workers_cleaned=1, exceptions_status=0, memory_status=0,
    handlers_removed=1, child_passed=1)
EXCEPTION_FIELDS = ('sequence kind expected_code operation address fault_pc recovery_pc teb first_count '
    'second_count order error code fault_address context_pc access_kind context_x18 context_x19 '
    'context_sp exception_pc continued context_x0 context_flags exception_flags parameters module_base').split()
FIELDS = {
    'pear_signal_event': ('slot phase module_base teb native_tid ntdll_base guest_begin guest_end host_begin host_end '
        'before_count after_count signal entry_mode handler_mode return_mode before_pc after_pc before_x18 after_x18 '
        'before_x19 after_x19 before_sp after_sp error send_status').split(),
    'pear_suspend_result': ('slot suspend_previous resume_previous context_ok context_flags context_pc context_sp '
        'context_x18 context_x19 stack_low stack_high passed').split(),
    'pear_thread_event': ('slot teb tid tls_value checks error exit_code registered init_seen init_host_mode init_tls_matches '
        'native_tid native_teb native_exit_seen native_exit_mode host_entry host_exit').split(),
    'pear_exception_event': EXCEPTION_FIELDS,
    'pear_exception_region': 'base size offset'.split(),
    'pear_exception_cleanup': 'released operation_error'.split(),
    'pear_memory_region': 'base size page_bytes middle_offset allocation_protect'.split(),
    'pear_dynamic_call': 'ordinal base bytes word0 word1 hash value'.split(),
    'pear_memory_result': list(MEMORY),
    'pear_stage4_child_ready': 'guest_pid native_pid teb module_base fault_pc recovery_pc address expected_code region_base region_size region_offset'.split(),
    'pear_stage4_child_fault': EXCEPTION_FIELDS,
    'pear_stage4_child_result': 'guest_pid exit_code wait_result exit_query thread_closed process_closed expected_code'.split(),
    'pear_stage4_result': [*FINAL, 'module_base', 'main_teb', 'native_pid'],
}
COUNTS = dict(pear_signal_event=3, pear_suspend_result=1, pear_thread_event=2, pear_exception_event=5,
    pear_exception_region=1, pear_exception_cleanup=1, pear_memory_region=1, pear_dynamic_call=2, pear_memory_result=1,
    pear_stage4_child_ready=1, pear_stage4_child_fault=1, pear_stage4_child_result=1, pear_stage4_result=1)
PE_NAMES = ('pear_guest_spin_begin', 'pear_guest_spin_end', 'pear_fault_read_pc',
            'pear_fault_read_recovery', 'pear_fault_write_pc', 'pear_fault_write_recovery', 'PearDynamicCall')
NATIVE_NAMES = ('_pear_stage4_host_begin', '_pear_stage4_host_end')


NATIVE_EVENTS = frozenset(('stage4_thread_register', 'stage4_signal', 'stage4_thread_exit'))
NATIVE_BASE_FIELDS = {'version', 'role', 'event', 'nonce', 'pid', 'ppid', 'generation',
                      'start_sec', 'start_usec', 'identity_error'}
REGISTER_FIELDS = ('teb native_tid ntdll_base guest_begin guest_end host_begin host_end '
                   'init_seen init_host_mode init_tls_matches').split()
SIGNAL_FIELDS = ('teb native_tid ntdll_base guest_begin guest_end host_begin host_end before_count after_count '
                 'signal entry_mode handler_mode return_mode before_pc after_pc before_x18 after_x18 '
                 'before_x19 after_x19 before_sp after_sp error').split()


def validate_native_scope(result):
    for role, rows in result['events'].items():
        observed = [row for row in rows if row['event'] in NATIVE_EVENTS]
        need(not observed or result['case']['id'] == 'threads' and role == 'loader', 'stage4_native_event_scope')


def native_parts(rows, event, names, keys):
    selected = [row for row in rows if row['event'] == event]
    width = (len(names) + 2) // 3
    need(len(selected) == width * len(keys), 'stage4_native_part_coverage')
    merged, orders = {}, {}
    for row in selected:
        key = (row.get('slot'), row.get('phase')) if event == 'stage4_signal' else row.get('slot')
        need(key in keys, 'stage4_native_part_key')
        part = row.get('part')
        need(type(part) is int and part == orders.get(key, 0) and part < width, 'stage4_native_part_order')
        fields = names[part * 3:(part + 1) * 3]
        controls = {'slot', 'part'} | ({'phase'} if event == 'stage4_signal' else set())
        need(set(row) == NATIVE_BASE_FIELDS | controls | set(fields) and
             type(row['version']) is int and row['version'] == 1 and
             all(type(row[name]) is int and 0 <= row[name] < 2**64 for name in [*controls, *fields]),
             'stage4_native_part_fields')
        merged.setdefault(key, {}).update({name: row[name] for name in fields})
        orders[key] = part + 1
    need(set(merged) == set(keys) and all(count == width for count in orders.values()), 'stage4_native_part_missing')
    return merged


def bind_native_anchors(result, threads, signals):
    rows = result['events']['loader']
    anchors = [row for row in rows if row['event'] in NATIVE_EVENTS]
    need([row['event'] for row in anchors] == ['stage4_thread_register'] * 8 +
         ['stage4_signal'] * 24 + ['stage4_thread_exit'] * 2, 'stage4_native_lifecycle_order')
    need([(row.get('slot'), row.get('phase')) for row in anchors[8:32]] ==
         [(0, 1)] * 8 + [(1, 2)] * 8 + [(0, 3)] * 8, 'stage4_native_signal_order')
    registered = native_parts(rows, 'stage4_thread_register', REGISTER_FIELDS, (0, 1))
    captured = native_parts(rows, 'stage4_signal', SIGNAL_FIELDS, ((0, 1), (1, 2), (0, 3)))
    exits = [row for row in rows if row['event'] == 'stage4_thread_exit']
    need(len(exits) == 2 and {row.get('slot') for row in exits} == {0, 1}, 'stage4_native_thread_exit_count')
    for row in exits:
        need(set(row) == NATIVE_BASE_FIELDS | {'slot', 'teb', 'native_tid', 'exit_mode'} and
             type(row['version']) is int and row['version'] == 1 and
             all(type(row[key]) is int and 0 <= row[key] < 2**64 for key in ('slot', 'teb', 'native_tid', 'exit_mode')),
             'stage4_native_thread_exit_fields')
        worker = threads[row['slot']]
        need(row['teb'] == worker['teb'] and row['native_tid'] == worker['tid'] and row['exit_mode'] == 0,
             'stage4_native_thread_exit_binding')
    for index, worker in enumerate(threads):
        native = registered[index]
        need(all(native[key] == worker[key] for key in ('teb', 'native_tid', 'init_seen', 'init_host_mode', 'init_tls_matches')),
             'stage4_native_registration_binding')
    for row in signals:
        key = (row['slot'], row['phase'])
        need(all(captured[key][name] == row[name] for name in SIGNAL_FIELDS), 'stage4_native_signal_binding')
        need(all(registered[row['slot']][name] == row[name] for name in
                 ('teb', 'native_tid', 'ntdll_base', 'guest_begin', 'guest_end', 'host_begin', 'host_end')),
             'stage4_native_window_binding')


def expected_results():
    return [{'version': 1, 'record_kind': 'pear_memory_result', **MEMORY},
            {'version': 1, 'record_kind': 'pear_stage4_result', **FINAL}]


def validate_row(row):
    need(isinstance(row, dict) and type(row.get('record_kind')) is str and
         row['record_kind'] in FIELDS, 'stage4_row_kind')
    fields = FIELDS[row['record_kind']]
    need(set(row) == {'version', 'record_kind', *fields} and
         type(row.get('version')) is int and row['version'] == 1 and
         all(type(row[key]) is int and 0 <= row[key] < 2**64 for key in fields), 'stage4_row_fields')
    return row


def decode_stdout_row(data):
    """Decode one bounded flat Stage 4 row with exact unsigned 64-bit fields.

    The fixture emits uint64_t values, including FNV-1a hashes beyond JSON's
    interoperable 53-bit range. This private wire decoder does not broaden the
    shared decoder used for manifests, native events, helpers or public output.
    """
    need(isinstance(data, bytes) and len(data) <= 3072, 'stage4_stdout_size')

    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate_json_key')
            result[key] = value
        return result

    def unsigned(token):
        need(len(token) <= 20 and not token.startswith('-'), 'stage4_stdout_uint64')
        value = int(token)
        need(value < 2**64, 'stage4_stdout_uint64')
        return value

    def forbidden(_):
        raise Error('stage4_stdout_noninteger')

    try:
        text = data.decode('utf-8')
        # Count keys, values and the one object before JSON can allocate them.
        _json_preflight(text, 1 + 2 * (2 + max(map(len, FIELDS.values()))))
        row = json.loads(text, object_pairs_hook=pairs, parse_int=unsigned,
                         parse_float=forbidden, parse_constant=forbidden)
    except (UnicodeError, ValueError, RecursionError):
        raise Error('invalid_json') from None
    return validate_row(row)


def group_rows(rows):
    need(isinstance(rows, list) and len(rows) == sum(COUNTS.values()), 'stage4_row_count')
    grouped = {kind: [] for kind in FIELDS}
    positions = {kind: [] for kind in FIELDS}
    for index, row in enumerate(rows):
        validate_row(row)
        kind = row['record_kind']
        grouped[kind].append(row)
        positions[kind].append(index)
    need({kind: len(values) for kind, values in grouped.items()} == COUNTS, 'stage4_row_coverage')
    need(rows[-1]['record_kind'] == 'pear_stage4_result', 'stage4_final_order')
    # Main-thread operations are sequential, and the child writes its records
    # before the parent's successful process wait. Bind declarations and cleanup
    # to that observed order, not merely to matching addresses and final counts.
    exceptions = positions['pear_exception_event']
    memory_result = positions['pear_memory_result'][0]
    owned_order = [exceptions[0], positions['pear_exception_region'][0], exceptions[1],
                   positions['pear_exception_cleanup'][0], positions['pear_memory_region'][0],
                   *exceptions[2:], memory_result]
    need(owned_order == sorted(owned_order), 'stage4_owned_region_order')
    need(memory_result < positions['pear_stage4_child_ready'][0] <
         positions['pear_stage4_child_fault'][0] < positions['pear_stage4_child_result'][0] <
         positions['pear_stage4_result'][0], 'stage4_child_record_order')
    for kind, expected in [('pear_memory_result', MEMORY), ('pear_stage4_result', FINAL)]:
        need(all(grouped[kind][0][key] == value for key, value in expected.items()), 'stage4_result_failed')
    return grouped


def fixture_rows(rows):
    group_rows(rows)
    return expected_results()


def fixture_facts(runtime, signed):
    data = read_relative(runtime, signed['entrypoints']['stage4_pe'], 16 * 1024 * 1024)
    pe = PE(data)
    need(pe.machine == 0xaa64, 'stage4_fixture_architecture')
    exports = [row for row in pe.exports() if row.get('name') in PE_NAMES]
    need(len(exports) == len(PE_NAMES) and {row['name'] for row in exports} == set(PE_NAMES) and
         all('forwarder' not in row for row in exports), 'stage4_fixture_exports')
    rvas = {row['name']: row['rva'] for row in exports}
    for rva in rvas.values():
        sections = [row for row in pe.sections if row['rva'] <= rva < row['rva'] + row['virtual_size']]
        need(rva % 4 == 0 and len(sections) == 1 and sections[0]['characteristics'] & 0x20000000 and
             not sections[0]['characteristics'] & 0x80000000, 'stage4_label_section')
        pe.offset(rva, 4)
    need(rvas['pear_guest_spin_end'] - rvas['pear_guest_spin_begin'] == 8, 'stage4_guest_window_size')
    for name, opcode in [('pear_fault_read_pc', 0x39400001), ('pear_fault_write_pc', 0x39000001)]:
        need(pe.u('I', pe.offset(rvas[name], 4)) == opcode and
             rvas[name.replace('_pc', '_recovery')] == rvas[name] + 4, 'stage4_fault_instruction')
    # This original boundary must call the runtime pointer; a constant return
    # cannot satisfy code execution, even if a forged observation says 42/84.
    call_words = (0xf81f0ffe, 0xd63f0000, 0xb9000fe0, 0xb9400fe0, 0xf84107fe, 0xd65f03c0)
    need(pe.unpack('6I', pe.offset(rvas['PearDynamicCall'], 24)) == call_words,
         'stage4_dynamic_indirect_branch')
    native = read_relative(runtime, signed['entrypoints']['ntdll'], 64 * 1024 * 1024)
    symbols, segments = macho(native, extra_symbols=NATIVE_NAMES)
    need(all(name in symbols for name in NATIVE_NAMES), 'stage4_native_window_symbols')
    headers = [address for address, size, offset, _ in segments if offset == 0 and size >= 32]
    need(len(headers) == 1, 'stage4_native_header_mapping')
    low, high = (symbols[name] for name in NATIVE_NAMES)
    need(0 < high - low <= 128 and low % 4 == high % 4 == 0 and any(
        protection & 4 and address <= low < high <= address + size
        for address, size, _, protection in segments), 'stage4_native_window_bounds')
    return {'rvas': rvas, 'image_size': pe.u('I', pe.opt + 56), 'original_base': pe.base,
            'native_offsets': [low - headers[0], high - headers[0]],
            'fixture_sha256': hashlib.sha256(data).hexdigest(), 'native_sha256': hashlib.sha256(native).hexdigest()}


def address(value, alignment=1):
    need(type(value) is int and 0 < value < 2**64 and value % alignment == 0, 'stage4_address')


def bind_image(result, role, base, facts):
    address(base, 65536)
    matches = [row for row in result['events'][role] if row['event'] == 'arena_publish' and
               row.get('base') == base and row.get('size') == facts['image_size'] and
               row.get('original_base') == facts['original_base']]
    need(len(matches) == 1, 'stage4_executed_image_binding')


def check_exception(row, *, kind, sequence, teb, base, facts, region=None, fatal=False):
    code = 0xe0424401 if kind == 1 else GUARD if kind == 4 else ACCESS
    need(row['kind'] == kind and row['sequence'] == sequence and row['code'] == row['expected_code'] == code and
         row['first_count'] == row['second_count'] == 1 and row['order'] == 12 and row['error'] == 0 and
         row['teb'] == row['context_x18'] == teb and row['module_base'] == base and
         row['exception_flags'] == 0 and row['context_flags'] & 0x400007 == 0x400007 and
         row['continued'] == (0 if fatal else 1), 'stage4_exception_context')
    address(teb, 16)
    address(row['context_sp'], 16)
    address(row['context_pc'], 4)
    address(row['exception_pc'], 4)
    if kind == 1:
        # Pinned ARM64 RtlRaiseException captures CONTEXT_FULL, adds
        # CONTEXT_UNWOUND_TO_CALL and copies the same caller LR to both PCs.
        # Its captured X19 belongs to RaiseException; the original sentinel is
        # checked by the assembly wrapper after the software exception returns.
        need(row['context_flags'] == 0x20400007 and row['context_pc'] == row['exception_pc'],
             'stage4_software_exception_context')
        need(all(row[key] == 0 for key in ('operation', 'address', 'fault_pc', 'recovery_pc', 'fault_address', 'access_kind', 'parameters')),
             'stage4_software_exception_fields')
        return
    operation = int(kind == 3)
    target = 'pear_fault_write' if operation else 'pear_fault_read'
    need(row['operation'] == row['access_kind'] == operation and row['parameters'] == 2 and
         row['context_x19'] == SENTINEL and row['context_x0'] == region and
         row['context_flags'] & 0x400017 == 0x400017 and
         row['context_pc'] == row['exception_pc'] == row['fault_pc'] == base + facts['rvas'][target + '_pc'] and
         row['recovery_pc'] == base + facts['rvas'][target + '_recovery'] and
         row['address'] == row['fault_address'] == region, 'stage4_fault_label_or_address')


def assess(rows, result, runtime, signed, dynamic):
    grouped = group_rows(rows)
    facts = fixture_facts(runtime, signed)
    final = grouped['pear_stage4_result'][0]
    need(final['native_pid'] == result['processes']['loader']['identity']['pid'], 'stage4_root_pid')
    main_teb, main_base = final['main_teb'], final['module_base']
    address(main_teb, 16)
    bind_image(result, 'loader', main_base, facts)
    threads = grouped['pear_thread_event']
    need([row['slot'] for row in threads] == [0, 1], 'stage4_worker_slots')
    need(len({main_teb, *(row['teb'] for row in threads)}) == 3 and
         threads[0]['tid'] != threads[1]['tid'], 'stage4_worker_isolation')
    for index, row in enumerate(threads):
        address(row['teb'], 16)
        need(row['tid'] > 0 and row['teb'] == row['native_teb'] and row['tid'] == row['native_tid'] and
             row['tls_value'] == 0x7300 + index and row['checks'] == (5 if index == 0 else 4) and
             all(row[key] == 0 for key in ('error', 'exit_code', 'init_host_mode', 'native_exit_mode', 'host_entry', 'host_exit')) and
             all(row[key] == 1 for key in ('registered', 'init_seen', 'init_tls_matches', 'native_exit_seen')),
             'stage4_worker_start_exit')
    signals = grouped['pear_signal_event']
    bind_native_anchors(result, threads, signals)
    need([(row['slot'], row['phase']) for row in signals] == [(0, 1), (1, 2), (0, 3)], 'stage4_signal_coverage')
    for row in signals:
        worker = threads[row['slot']]
        guest = row['phase'] != 2
        need(row['module_base'] == main_base and row['teb'] == worker['teb'] and row['native_tid'] == worker['tid'] and
             row['guest_begin'] == main_base + facts['rvas']['pear_guest_spin_begin'] and
             row['guest_end'] == main_base + facts['rvas']['pear_guest_spin_end'], 'stage4_signal_guest_binding')
        address(row['ntdll_base'], 4096)
        need([row['host_begin'], row['host_end']] == [row['ntdll_base'] + offset for offset in facts['native_offsets']],
             'stage4_signal_native_binding')
        low, high = (row['guest_begin'], row['guest_end']) if guest else (row['host_begin'], row['host_end'])
        need(row['before_count'] == row['after_count'] == 1 and row['signal'] == int(signal.SIGUSR1) and
             row['entry_mode'] == row['return_mode'] == int(guest) and row['handler_mode'] == 0 and
             row['error'] == row['send_status'] == 0 and low <= row['before_pc'] < high and
             all(row['before_' + key] == row['after_' + key] for key in ('pc', 'sp', 'x18', 'x19')),
             'stage4_signal_context')
        address(row['before_sp'], 16)
        if guest:
            need(row['before_x18'] == worker['teb'] and row['before_x19'] == SENTINEL + row['slot'],
                 'stage4_guest_signal_registers')
    need(len({row['ntdll_base'] for row in signals}) == 1, 'stage4_native_image_changed')
    suspended = grouped['pear_suspend_result'][0]
    need(suspended['slot'] == suspended['suspend_previous'] == 0 and
         suspended['resume_previous'] == suspended['context_ok'] == suspended['passed'] == 1 and
         suspended['context_flags'] & 0x400017 == 0x400017 and
         suspended['context_flags'] & ~0x40001f == 0 and
         all(suspended['context_' + key] == signals[2]['before_' + key] for key in ('pc', 'sp', 'x18', 'x19')) and
         0 < suspended['stack_low'] <= suspended['context_sp'] < suspended['stack_high'] < 2**64,
         'stage4_suspend_context')
    cleanup = grouped['pear_exception_cleanup'][0]
    need(cleanup['released'] == 1 and cleanup['operation_error'] == 0, 'stage4_exception_cleanup')
    exceptions = grouped['pear_exception_event']
    region = grouped['pear_exception_region'][0]
    ordinary = grouped['pear_memory_region'][0]
    need(region['size'] == 4096 and region['offset'] == 37 and ordinary['size'] == 12288 and
         ordinary['page_bytes'] == ordinary['middle_offset'] == 4096 and ordinary['allocation_protect'] == 1,
         'stage4_owned_region_geometry')
    for item in (region, ordinary):
        address(item['base'], 65536)
        need(item['base'] + item['size'] < 2**64, 'stage4_owned_region_overflow')
    fault_regions = [None, region['base'] + 37, *([ordinary['base'] + 4096] * 3)]
    for seq, (row, kind, target) in enumerate(zip(exceptions, (1, 2, 3, 4, 2), fault_regions), 1):
        check_exception(row, kind=kind, sequence=seq, teb=main_teb, base=main_base, facts=facts, region=target)
    calls = grouped['pear_dynamic_call']
    need([row['ordinal'] for row in calls] == [1, 2] and calls[0]['base'] == calls[1]['base'], 'stage4_dynamic_call_order')
    for row, value, word in zip(calls, (42, 84), (0x52800540, 0x52800a80)):
        address(row['base'], 65536)
        hashed = 14695981039346656037
        for byte in struct.pack('<II', word, 0xd65f03c0):
            hashed = ((hashed ^ byte) * 1099511628211) & (2**64 - 1)
        need(row['bytes'] == 8 and row['word0'] == word and row['word1'] == 0xd65f03c0 and
             row['hash'] == hashed and row['value'] == value, 'stage4_dynamic_code_result')
    expected_owner = dict(reservations=2, commits=3, protects=3, decommits=3, releases=2,
                          compatible_reuses=1, executable_publications=2, writable_transitions=4,
                          committed_pages=3, decommitted_pages=3, live_allocations_at_last_observation=0)
    need(all(dynamic.get('root', {}).get(key) == value for key, value in expected_owner.items()),
         'stage4_dynamic_operation_counts')
    owner = [row for row in result['events']['loader'] if row['event'].startswith('dynamic_')]
    expected_path = [('dynamic_budget', None), ('dynamic_reserve', None),
        ('dynamic_protect', 'commit'), ('dynamic_protect', 'protect'),
        ('dynamic_protect', 'protect'), ('dynamic_protect', 'protect'),
        ('dynamic_decommit', None), ('dynamic_protect', 'commit'),
        ('dynamic_decommit', None), ('dynamic_release', None), ('dynamic_reserve', None),
        ('dynamic_protect', 'commit'), ('dynamic_decommit', None), ('dynamic_release', None)]
    need([(row['event'], row.get('operation')) for row in owner] == expected_path,
         'stage4_dynamic_publication_path')
    transitions = [row for row in owner if row['event'] == 'dynamic_protect']
    need([row['vprot'] for row in transitions] == [35, 37, 35, 37, 35, 35] and
         [row['slot_generation'] for row in transitions] == [1, 1, 1, 1, 1, 2] and
         all(row['offset'] == 0 and row['size'] == 4096 for row in transitions),
         'stage4_dynamic_publication_generations')
    reserves = [row for row in owner if row['event'] == 'dynamic_reserve']
    need(len(reserves) == 2 and all(row['base'] == calls[0]['base'] and row['size'] == 4096 for row in reserves),
         'stage4_dynamic_owner_binding')
    ready, fault, child = (grouped[kind][0] for kind in ('pear_stage4_child_ready', 'pear_stage4_child_fault', 'pear_stage4_child_result'))
    need(ready['guest_pid'] == child['guest_pid'] > 0 and ready['native_pid'] != final['native_pid'] and
         ready['expected_code'] == child['expected_code'] == child['exit_code'] == ACCESS and child['wait_result'] == 0 and
         all(child[key] == 1 for key in ('exit_query', 'thread_closed', 'process_closed')) and
         ready['region_size'] == 4096 and ready['region_offset'] == 53 and ready['address'] == ready['region_base'] + 53,
         'stage4_controlled_termination')
    address(ready['region_base'], 65536)
    matches = [row for row in result['registrations'] if row['identity']['pid'] == ready['native_pid'] and row['role'] != 'loader']
    need(len(matches) == 1, 'stage4_fault_child_identity')
    role = matches[0]['role']
    bind_image(result, role, ready['module_base'], facts)
    check_exception(fault, kind=5, sequence=1, teb=ready['teb'], base=ready['module_base'], facts=facts,
                    region=ready['address'], fatal=True)
    need(ready['fault_pc'] == fault['fault_pc'] and ready['recovery_pc'] == fault['recovery_pc'], 'stage4_child_ready_fault_binding')
    need(matches[0]['exit_code'] == (ACCESS & 255) and result['pre_cleanup']['processes'][role]['exited'] is True,
         'stage4_child_termination_observation')
    need(any(row['event'] in ('stage3_guest_exit', 'stage3_process_exit') and type(row.get('exit_code')) is int and row['exit_code'] == ACCESS - 2**32
             for row in result['events'][role]), 'stage4_child_windows_exit')
    summary = {'fixture_sha256': facts['fixture_sha256'], 'native_fixture_library_sha256': facts['native_sha256'],
        'workers': 2, 'tls_teb_isolation': True, 'native_anchor_parts': 34, 'guest_signals': 1, 'host_signals': 1, 'controlled_suspensions': 1,
        'software_exceptions': 1, 'access_faults_recovered': 3, 'guard_faults_retried': 1,
        'handler_order_checks': 6, 'dynamic_results': [42, 84], 'controlled_fault_terminations': 1,
        'controlled_windows_exit': ACCESS, 'controlled_native_exit': ACCESS & 255,
        'dynamic_owner': dynamic, 'memory_result': dict(MEMORY),
        'unqualified': ['general_unwinding', 'arbitrary_asynchronous_suspension', 'native_created_callback_thread',
                        'x64_guest_translation', 'game_execution', 'general_jit_service']}
    return summary, {role: {'native_exit': ACCESS & 255, 'windows_exit': ACCESS, 'native_reported_status': ACCESS - 2**32}}
