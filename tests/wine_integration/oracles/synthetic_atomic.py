# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact synthetic source-row generator; never native observations."""

IDENTITY = {'allocation_id': 17, 'generation': 19, 'extent_offset': 32768,
            'extent_size': 16384, 'executor_id': 23}


FACTS = tuple(IDENTITY) + ('write_epoch', 'continuation_id', 'executor_state',
                         'lifecycle', 'protection', 'capabilities')


def source_rows(scope='native_owner'):
    rows = []

    def row(control, opcode, *, status=0, request=3, offset=0, size=4, epoch=29,
            state=3, lifecycle=3, protection=0, continuation=0):
        value = {'version': 1, 'record_kind': 'pear_fex_memory_fixture', 'scope': scope,
                 'sequence': len(rows) + 1, 'event': 'owner_call', 'control': control,
                 'opcode': opcode, 'returned_status': status, 'status': status,
                 'requested_state': request, 'operation_offset': f'{offset:016x}',
                 'operation_size': f'{size:016x}', **IDENTITY, 'write_epoch': epoch,
                 'continuation_id': continuation, 'executor_state': state,
                 'lifecycle': lifecycle, 'protection': protection, 'capabilities': 0,
                 'native_error_domain': 0, 'native_error_code': 0}
        if status:
            value.update(dict.fromkeys(FACTS, 0))
        rows.append(value)

    row('reserve_extent', 1, request=0, size=0, epoch=0, state=1, lifecycle=1)
    row('query_current_token', 6, request=0, size=0, epoch=0, state=1, lifecycle=1)
    row('begin_two_page_write', 2, request=1, size=8192, state=1, lifecycle=2, protection=1)
    row('publish_two_pages', 3, request=2, size=0, state=1, protection=2)
    row('atomic_enter_dispatcher', 8, state=2, protection=2)
    row('atomic_handoff_dispatcher', 13, continuation=31)
    # Independent C order/status declarations, rather than checks.controls().
    negatives = [('atomic_wrong_size', 1, 0, 0), ('atomic_wrong_offset', 1, 4, 4),
                 ('atomic_wrong_continuation', 6, 0, 4), ('atomic_missing_continuation', 1, 0, 4),
                 ('atomic_stale_current_epoch', 6, 0, 4), ('atomic_old_wire_version', 2, 0, 4),
                 ('atomic_wrong_generation', 6, 0, 4), ('atomic_wrong_executor', 6, 0, 4),
                 ('atomic_wrong_role', 6 if scope == 'native_owner' else 3, 0, 4)]
    for control, status, offset, size in negatives:
        row(control, 14, status=status, offset=offset, size=size)
        row('atomic_refusal_preserves_original_pin', 13, size=0, continuation=31)
    row('atomic_retirement_preserves_original_pin', 5, status=3, size=0)
    row('mixed_extent_query_unavailable', 6, status=3, request=0, size=0)
    row('begin_two_page_write', 2, size=8192, epoch=37, lifecycle=2, protection=1)
    row('publish_two_pages', 3, request=2, size=0, epoch=37, protection=2)
    row('atomic_original_epoch_requires_retry', 14, status=6)
    row('atomic_consume_original_pin_on_current_epoch', 14, epoch=37, state=2, protection=2)
    row('atomic_consumed_continuation_cannot_repeat', 14, status=6)
    row('atomic_exit_consumed_continuation', 9, size=0, epoch=37, state=1)
    return rows
