"""Bind finite native dynamic-code events to the source-qualified shared arena.

The caller first binds raw event bytes, producer/build/signing identities, each
PID/birth/nonce, and process ownership. This module reconstructs the finite native
owner timeline; guest code bytes, results and API outcomes are checked separately.
It does not establish general JIT, translated-state or concurrent-code safety.
"""
from common import need

DYNAMIC_EVENTS = frozenset({'dynamic_budget', 'dynamic_reserve', 'dynamic_protect',
                            'dynamic_decommit', 'dynamic_release', 'dynamic_failure'})
LIMITS = {'bytes': 524288, 'slots': 8, 'slot_bytes': 65536}
PAGE = 4096
MAX_ADDRESS = 2**64
MAX_EVENTS = 16384
BASE_FIELDS = {'version', 'role', 'event', 'nonce', 'pid', 'ppid', 'generation',
               'start_sec', 'start_usec', 'identity_error', 'policy', 'dynamic_sequence'}
FIELDS = {
    'dynamic_budget': {'policy_version', 'base', 'bytes', 'slots', 'slot_bytes'},
    'dynamic_reserve': {'slot', 'slot_generation', 'base', 'size', 'capacity'},
    'dynamic_protect': {'operation', 'slot', 'slot_generation', 'offset', 'size',
                        'vprot', 'unix_protection', 'committed_pages', 'protection_verified'},
    'dynamic_decommit': {'slot', 'slot_generation', 'offset', 'size', 'zeroed_pages',
                         'protection_verified'},
    'dynamic_release': {'slot', 'slot_generation', 'base', 'size', 'capacity', 'protection_verified'},
}
PROTECTIONS = {32: 0, 33: 1, 35: 3, 37: 5}
COUNT_FIELDS = ('reservations', 'commits', 'protects', 'decommits', 'releases',
                'compatible_reuses', 'committed_pages', 'decommitted_pages',
                'executable_publications', 'writable_transitions')


def integer(value, low=0, high=MAX_ADDRESS - 1):
    return type(value) is int and low <= value <= high


def dynamic_rows(rows):
    need(isinstance(rows, list) and len(rows) <= MAX_EVENTS and
         all(isinstance(row, dict) and isinstance(row.get('event'), str) for row in rows),
         'dynamic_event_rows')
    selected = [(index, row) for index, row in enumerate(rows) if row['event'].startswith('dynamic_')]
    need(all(row['event'] in DYNAMIC_EVENTS for _, row in selected), 'dynamic_unknown_event')
    return selected


def validate_budget(rows, capacity, reserve):
    """Return the separate dynamic tail size; old capacities admit no such events."""
    selected = dynamic_rows(rows)
    need(isinstance(capacity, dict), 'dynamic_capacity_type')
    if 'dynamic_limits' not in capacity:
        need(not selected, 'dynamic_legacy_capacity')
        return 0
    dynamic = capacity['dynamic_limits']
    need(isinstance(dynamic, dict) and set(dynamic) == set(LIMITS) and
         all(type(dynamic[key]) is int and dynamic[key] == value for key, value in LIMITS.items()),
         'dynamic_capacity_limits')
    limits = capacity.get('limits', {})
    need(isinstance(limits, dict) and limits.get('alignment') == 65536 and
         type(limits.get('alignment')) is int and limits.get('page_bytes') == PAGE and
         type(limits.get('page_bytes')) is int and integer(limits.get('interior_bytes'), 65536, 2**40) and
         limits['interior_bytes'] % 65536 == 0, 'dynamic_image_capacity')
    need(isinstance(reserve, dict) and reserve.get('event') == 'arena_reserve', 'dynamic_arena_reservation')
    matches = [index for index, row in enumerate(rows) if row.get('event') == 'arena_reserve']
    need(len(matches) == 1 and rows[matches[0]] == reserve and selected and
         selected[0][1]['event'] == 'dynamic_budget' and matches[0] < selected[0][0] and
         sum(row['event'] == 'dynamic_budget' for _, row in selected) == 1,
         'dynamic_budget_order')
    mapping, interior = reserve.get('mapping_base'), reserve.get('interior_base')
    total = limits['interior_bytes'] + LIMITS['bytes'] + 65536
    need(integer(mapping, 1) and mapping % PAGE == 0 and integer(interior, mapping) and
         interior % 65536 == 0 and interior - mapping < 65536 and
         integer(reserve.get('mapping_bytes')) and reserve['mapping_bytes'] == total and
         integer(reserve.get('interior_bytes')) and reserve['interior_bytes'] == limits['interior_bytes'] and
         mapping + total < MAX_ADDRESS, 'dynamic_mapping_geometry')
    budget = selected[0][1]
    need(set(budget) == BASE_FIELDS | FIELDS['dynamic_budget'] and
         type(budget.get('policy_version')) is int and budget['policy_version'] == 1 and
         all(type(budget.get(key)) is int and budget[key] == value for key, value in LIMITS.items()) and
         integer(budget.get('base'), 1) and budget['base'] == interior + limits['interior_bytes'] and
         budget['base'] % 65536 == 0 and budget['base'] + LIMITS['bytes'] <= mapping + total,
         'dynamic_budget_geometry')
    for sequence, (index, row) in enumerate(selected, 1):
        need(row.get('policy') == 'page-wx' and type(row.get('dynamic_sequence')) is int and
             row['dynamic_sequence'] == sequence and type(row.get('generation')) is int and
             row['generation'] == 1, 'dynamic_event_sequence')
        need(row['event'] != 'dynamic_failure', 'dynamic_operation_failed')
        need(set(row) == BASE_FIELDS | FIELDS[row['event']], 'dynamic_event_fields')
    # pear_bootstrap_stop emits continuation before load_ntdll maps the first
    # PE. The arena and its budget are then initialized lazily by that mapping.
    continuation = [index for index, row in enumerate(rows) if row['event'] == 'stage3_pe_continue']
    publications = [index for index, row in enumerate(rows) if row['event'] == 'arena_publish']
    need(len(continuation) == 1 and continuation[0] < matches[0] < selected[0][0] and
         publications and all(index > selected[0][0] for index, row in enumerate(rows)
                              if row['event'] in ('arena_publish', 'arena_retire')),
         'dynamic_budget_loader_order')
    return LIMITS['bytes']


def _process(rows, capacity, reserve, allow_operations):
    validate_budget(rows, capacity, reserve)
    selected = dynamic_rows(rows)
    budget = selected[0][1]
    operations = selected[1:]
    need(allow_operations or not operations, 'dynamic_unexpected_process_operation')
    slots = {}
    counts = {name: 0 for name in COUNT_FIELDS}
    continuation = [index for index, row in enumerate(rows) if row['event'] == 'stage3_pe_continue']
    publication = next(index for index, row in enumerate(rows) if row['event'] == 'arena_publish')
    exit_indices = [index for index, row in enumerate(rows) if row['event'] == 'stage3_guest_exit']
    need(len(continuation) == 1, 'dynamic_pe_continuation')
    previous = None
    for index, row in operations:
        need(index > publication > continuation[0] and all(index < end for end in exit_indices),
             'dynamic_guest_window')
        slot, generation = row.get('slot'), row.get('slot_generation')
        need(integer(slot, 0, LIMITS['slots'] - 1) and integer(generation, 1), 'dynamic_slot_identity')
        event, state = row['event'], slots.get(slot)
        address = budget['base'] + slot * LIMITS['slot_bytes']
        if event == 'dynamic_reserve':
            size = row.get('size')
            need(integer(size, PAGE, LIMITS['slot_bytes']) and size % PAGE == 0 and
                 integer(row.get('capacity')) and row['capacity'] == LIMITS['slot_bytes'] and
                 integer(row.get('base')) and row['base'] == address, 'dynamic_reservation_geometry')
            need((state is None and generation == 1) or
                 (state is not None and not state['active'] and generation == state['generation'] + 1),
                 'dynamic_reservation_generation')
            counts['compatible_reuses'] += int(state is not None)
            slots[slot] = {'active': True, 'generation': generation, 'size': size,
                           'pages': [None] * (size // PAGE)}
            counts['reservations'] += 1
        else:
            need(state is not None and state['active'] and state['generation'] == generation,
                 'dynamic_operation_generation')
            need(row.get('protection_verified') is True, 'dynamic_protection_unverified')
            if event == 'dynamic_release':
                need(integer(row.get('base')) and row['base'] == address and
                     type(row.get('size')) is int and row['size'] == state['size'] and
                     type(row.get('capacity')) is int and row['capacity'] == LIMITS['slot_bytes'],
                     'dynamic_release_geometry')
                need(previous is not None and previous['event'] == 'dynamic_decommit' and
                     previous['slot'] == slot and previous['slot_generation'] == generation and
                     previous['offset'] == 0 and previous['size'] == state['size'] and
                     all(page is None for page in state['pages']), 'dynamic_release_without_revoke')
                state['active'] = False
                counts['releases'] += 1
            else:
                offset, size = row.get('offset'), row.get('size')
                need(integer(offset, 0, state['size'] - PAGE) and offset % PAGE == 0 and
                     integer(size, PAGE, state['size']) and size % PAGE == 0 and
                     offset + size <= state['size'], 'dynamic_operation_range')
                first, end = offset // PAGE, (offset + size) // PAGE
                if event == 'dynamic_protect':
                    vprot, protection = row.get('vprot'), row.get('unix_protection')
                    need(type(vprot) is int and vprot in PROTECTIONS and type(protection) is int and
                         protection == PROTECTIONS[vprot], 'dynamic_page_wx')
                    need(type(row.get('committed_pages')) is int and row['committed_pages'] == end - first,
                         'dynamic_commit_count')
                    operation = row.get('operation')
                    need(operation in ('commit', 'protect'), 'dynamic_protect_operation')
                    if operation == 'protect':
                        need(all(page is not None for page in state['pages'][first:end]),
                             'dynamic_protect_uncommitted')
                    state['pages'][first:end] = [vprot] * (end - first)
                    counts['commits' if operation == 'commit' else 'protects'] += 1
                    if operation == 'commit':
                        counts['committed_pages'] += end - first
                    counts['executable_publications'] += int(protection == 5)
                    counts['writable_transitions'] += int(protection == 3)
                else:
                    need(event == 'dynamic_decommit' and type(row.get('zeroed_pages')) is int and
                         row['zeroed_pages'] == end - first, 'dynamic_decommit_count')
                    state['pages'][first:end] = [None] * (end - first)
                    counts['decommits'] += 1
                    counts['decommitted_pages'] += end - first
        previous = row
    need(all(not state['active'] for state in slots.values()), 'dynamic_live_allocation')
    if allow_operations:
        need(counts['reservations'] > 0 and counts['commits'] > 0 and counts['protects'] > 0 and
             counts['executable_publications'] > 0 and counts['releases'] == counts['reservations'],
             'dynamic_required_operations_missing')
    return {'budget_bytes': LIMITS['bytes'], 'slots': LIMITS['slots'], 'slot_bytes': LIMITS['slot_bytes'],
            'budget_verified': True, **counts, 'live_allocations_at_last_observation': 0}


def assess_events(result, signed):
    """Return address-free finite observations after the caller's native binding."""
    need(signed.get('code_publication_policy') == 'page-wx', 'dynamic_publication_policy')
    capacity = signed.get('arena_capacity', {})
    need(isinstance(capacity, dict), 'dynamic_capacity_type')
    case = result.get('case', {}).get('id')
    need(case in ('api', 'abi', 'threads', 'window'), 'dynamic_fixture_case')
    event_map = result.get('events')
    need(isinstance(event_map, dict) and 'loader' in event_map, 'dynamic_process_coverage')
    supported = 'dynamic_limits' in capacity
    need(case not in ('threads', 'window') or supported, 'dynamic_fixture_capacity_missing')
    public, root = [], None
    for role, rows in event_map.items():
        selected = dynamic_rows(rows)
        executes = any(row['event'] == 'stage3_pe_continue' for row in rows)
        if not supported:
            need(not selected, 'dynamic_legacy_capacity')
            continue
        if not executes:
            need(not selected, 'dynamic_non_pe_process')
            continue
        need(role != 'server', 'dynamic_server_execution')
        reservations = [row for row in rows if row['event'] == 'arena_reserve']
        need(len(reservations) == 1, 'dynamic_arena_reservation')
        allow = case == 'threads' and role == 'loader'
        observation = _process(rows, capacity, reservations[0], allow)
        public.append({'role': role, **observation})
        if role == 'loader':
            root = observation
    need(not supported or root is not None, 'dynamic_root_budget_missing')
    return {'policy': 'page-wx', 'dynamic_supported': supported, 'processes': public, 'root': root,
            'runtime_qualified': False, 'game_qualified': False}
