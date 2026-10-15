# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent finite ABI2 owner transcript checks; no runtime admission."""
from collections import Counter

POSITIVES = {
    'atomic_enter_dispatcher': (1, 8),
    'atomic_handoff_dispatcher': (1, 13),
    'atomic_refusal_preserves_original_pin': (9, 13),
    'atomic_consume_original_pin_on_current_epoch': (1, 14),
    'atomic_exit_consumed_continuation': (1, 9),
}
REFUSALS = {
    'atomic_wrong_size': (14, 1),
    'atomic_wrong_offset': (14, 1),
    'atomic_wrong_continuation': (14, 6),
    'atomic_missing_continuation': (14, 1),
    'atomic_stale_current_epoch': (14, 6),
    'atomic_old_wire_version': (14, 2),
    'atomic_wrong_generation': (14, 6),
    'atomic_wrong_executor': (14, 6),
    'atomic_wrong_role': (14, 6),
    'atomic_retirement_preserves_original_pin': (5, 3),
    'atomic_original_epoch_requires_retry': (14, 6),
    'atomic_consumed_continuation_cannot_repeat': (14, 6),
}

def controls(scope):
    if scope not in ('native_owner', 'wine_owner'):
        raise ValueError('memory_atomic_scope')
    counts = {key: value[0] for key, value in POSITIVES.items()}
    counts.update(dict.fromkeys(REFUSALS, 1))
    statuses = {key: value[1] for key, value in REFUSALS.items()}
    # Wine's finite PE front door refuses ARM64EC before Unix owner dispatch;
    # the native fixture reaches the owner's extent-role mismatch instead.
    statuses['atomic_wrong_role'] = 6 if scope == 'native_owner' else 3
    opcodes = {key: value[1] for key, value in POSITIVES.items()}
    opcodes.update({key: value[0] for key, value in REFUSALS.items()})
    return counts, statuses, opcodes

def validate(calls, need, *, scope):
    # Only requested_state, operation_offset and operation_size are logged
    # request facts. Never infer request PID/role/token/epoch/continuation from
    # zero refusal responses, or grant FEX source-lifetime authority here.
    need(type(calls) is list and calls and all(type(row) is dict and type(row.get('control')) is str
         for row in calls), 'memory_atomic_call_shape')
    need(scope in ('native_owner', 'wine_owner') and all(row.get('scope') == scope for row in calls),
         'memory_atomic_scope')
    selected = [row for row in calls if row['control'].startswith('atomic_')]
    counts, statuses, opcodes = controls(scope)
    need(Counter(row['control'] for row in selected) == counts, 'memory_atomic_control_counts')
    identity = ('allocation_id', 'generation', 'extent_offset', 'extent_size', 'executor_id')
    facts = identity + ('write_epoch', 'continuation_id', 'executor_state', 'lifecycle', 'protection', 'capabilities')
    for row in selected:
        need(all(type(row[key]) is int for key in facts + ('opcode', 'status', 'requested_state',
              'native_error_domain', 'native_error_code')), 'memory_atomic_fact_types')
        need(type(row['returned_status']) is int and row['returned_status'] == row['status']
             and row['opcode'] == opcodes[row['control']] and row['status'] == statuses.get(row['control'], 0),
             'memory_atomic_control_result')
        size = 0 if row['control'] in ('atomic_wrong_size', 'atomic_retirement_preserves_original_pin',
                  'atomic_refusal_preserves_original_pin', 'atomic_exit_consumed_continuation') else 4
        offset = 4 if row['control'] == 'atomic_wrong_offset' else 0
        need(row['requested_state'] == 3 and row['operation_offset'] == format(offset, '016x')
             and row['operation_size'] == format(size, '016x'), 'memory_atomic_request_shape')
        need(row['native_error_domain'] == row['native_error_code'] == 0, 'memory_atomic_control_native_error')
        if row['status']: need(all(row[key] == 0 for key in facts), 'memory_atomic_refusal_facts')
    good = [row for row in selected if row['status'] == 0]
    for row in good:
        need(row['lifecycle'] == 3 and row['extent_size'] == 16384, 'memory_atomic_operation_shape')
    enter, handoff, *tail = good
    need(enter['control'] == 'atomic_enter_dispatcher' and handoff['control'] == 'atomic_handoff_dispatcher',
         'memory_atomic_entry_order')
    need(enter['executor_state'] == 2 and not enter['continuation_id'] and
         handoff['executor_state'] == 3 and handoff['continuation_id'] > 0,
         'memory_atomic_initial_state')
    need(enter['protection'] == 2 and not handoff['protection'], 'memory_atomic_initial_protection')
    need(all(enter[key] == handoff[key] and enter[key] > 0 for key in identity if key != 'extent_offset')
         and enter['extent_offset'] == handoff['extent_offset'] and enter['extent_offset'] % 16384 == 0
         and enter['write_epoch'] > 0 and enter['write_epoch'] == handoff['write_epoch'],
         'memory_atomic_initial_identity')
    need(len(tail) == 11, 'memory_atomic_positive_count')
    for poll in tail[:9]:
        need(poll['control'] == 'atomic_refusal_preserves_original_pin' and poll['executor_state'] == 3
             and poll['continuation_id'] == handoff['continuation_id'] and not poll['protection']
             and poll['write_epoch'] == handoff['write_epoch']
             and all(poll[key] == handoff[key] for key in identity), 'memory_atomic_original_pin')
    resume, exit_row = tail[-2:]
    need(resume['control'] == 'atomic_consume_original_pin_on_current_epoch' and
         exit_row['control'] == 'atomic_exit_consumed_continuation' and
         all(row['continuation_id'] == 0 for row in (resume, exit_row)) and
         resume['executor_state'] == 2 and exit_row['executor_state'] == 1 and
         resume['write_epoch'] > handoff['write_epoch'] and exit_row['write_epoch'] == resume['write_epoch']
         and all(row[key] == handoff[key] for row in (resume, exit_row) for key in identity),
         'memory_atomic_committed_state')
    need(resume['lifecycle'] == 3 and resume['protection'] == 2 and
         exit_row['lifecycle'] == 3 and not exit_row['protection'], 'memory_atomic_committed_protection')
    positions = {id(row): index for index, row in enumerate(calls)}
    need(len(positions) == len(calls), 'memory_atomic_duplicate_row')
    need(positions[id(handoff)] == positions[id(enter)] + 1, 'memory_atomic_enter_handoff_order')
    negatives = [row for row in selected if row['control'] in list(REFUSALS)[:9]]
    need(len(negatives) == 9, 'memory_atomic_negative_count')
    for index, (negative, poll) in enumerate(zip(negatives, tail[:9])):
        need(negative['control'] == list(REFUSALS)[index]
             and positions[id(negative)] == positions[id(handoff)] + 1 + 2 * index
             and positions[id(poll)] == positions[id(negative)] + 1, 'memory_atomic_refusal_pin_pair')
    retry = next(row for row in selected if row['control'] == 'atomic_original_epoch_requires_retry')
    duplicate = next(row for row in selected if row['control'] == 'atomic_consumed_continuation_cannot_repeat')
    need(positions[id(resume)] == positions[id(retry)] + 1 and
         positions[id(duplicate)] == positions[id(resume)] + 1 and
         positions[id(exit_row)] == positions[id(duplicate)] + 1, 'memory_atomic_commit_order')
    retirement = next(row for row in selected if row['control'] == 'atomic_retirement_preserves_original_pin')
    need(positions[id(retirement)] == positions[id(tail[8])] + 1 and
         positions[id(retry)] == positions[id(retirement)] + 4, 'memory_atomic_retirement_before_write')
    start = positions[id(enter)]
    need(start >= 4, 'memory_atomic_initial_publication_missing')
    initial = calls[start - 4:start]
    middle = calls[positions[id(retirement)] + 1:positions[id(retry)]]
    need([row['control'] for row in initial] == ['reserve_extent', 'query_current_token',
         'begin_two_page_write', 'publish_two_pages'] and
         [row['control'] for row in middle] == ['mixed_extent_query_unavailable',
         'begin_two_page_write', 'publish_two_pages'], 'memory_atomic_publication_order')
    def successful(row, opcode, requested, operation, state, lifecycle, protection, epoch):
        need(type(row['opcode']) is int and row['opcode'] == opcode
             and type(row['status']) is int and row['status'] == 0
             and type(row['returned_status']) is int and row['returned_status'] == 0
             and type(row['requested_state']) is int and row['requested_state'] == requested
             and row['operation_offset'] == '0000000000000000'
             and row['operation_size'] == format(operation, '016x')
             and all(type(row[key]) is int and row[key] == enter[key] for key in identity)
             and type(row['write_epoch']) is int and row['write_epoch'] == epoch
             and type(row['executor_state']) is int and row['executor_state'] == state
             and type(row['continuation_id']) is int and row['continuation_id'] == 0
             and type(row['lifecycle']) is int and row['lifecycle'] == lifecycle
             and type(row['protection']) is int and row['protection'] == protection
             and type(row['native_error_domain']) is int and type(row['native_error_code']) is int
             and row['native_error_domain'] == row['native_error_code'] == 0,
             'memory_atomic_publication_facts')
    successful(initial[0], 1, 0, 0, 1, 1, 0, 0)
    successful(initial[1], 6, 0, 0, 1, 1, 0, 0)
    successful(initial[2], 2, 1, 8192, 1, 2, 1, enter['write_epoch'])
    successful(initial[3], 3, 2, 0, 1, 3, 2, enter['write_epoch'])
    refresh, writing, published = middle
    need(type(refresh['opcode']) is int and refresh['opcode'] == 6
         and type(refresh['status']) is int and refresh['status'] == 3
         and type(refresh['returned_status']) is int and refresh['returned_status'] == 3
         and type(refresh['requested_state']) is int and refresh['requested_state'] == 0
         and refresh['operation_offset'] == refresh['operation_size'] == '0000000000000000'
         and all(type(refresh[key]) is int and refresh[key] == 0 for key in facts)
         and type(refresh['native_error_domain']) is int and type(refresh['native_error_code']) is int
         and refresh['native_error_domain'] == refresh['native_error_code'] == 0,
         'memory_atomic_refresh_unavailable')
    successful(writing, 2, 3, 8192, 3, 2, 1, resume['write_epoch'])
    successful(published, 3, 2, 0, 3, 3, 2, resume['write_epoch'])
    return {'actual_owner_operations': len(selected), 'precommit_refusals': 11,
            'committed_resumes': 1, 'source_lifetime_qualified': False,
            'fex_initialization': False}
