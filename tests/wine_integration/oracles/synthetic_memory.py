# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact synthetic transcript inputs; counters never admit a host."""
from types import SimpleNamespace
from collections import Counter

NONCE = '0123456789abcdef0123456789abcdef'


CHILD = SimpleNamespace(identity={'pid': 17, 'ppid': 19, 'start_sec': 23, 'start_usec': 29})


def ready():
    return dict(version=1, record_kind='pear_fex_memory_admission', event='ready',
        pid=17, parent_pid=19, start_seconds=23, start_microseconds=29, nonce=NONCE,
        user_page=4096, vm_page=4096, kernel_page=16384, translation_result=0,
        translation_errno=0, translation_value=0, translation_size=4, user_page_errno=0,
        kernel_page_result=0, host_port_release_result=0, cpu_type=0x100000c, jit_supported=1,
        geometry_accepted=True, restricted_operations_started=False, checked_ec=False,
        wine_view_registration=False)


def helper():
    return dict(version=1, record_kind='pear_bootstrap_helper', pid=17, ppid=19,
        start_sec=23, start_usec=29, cpu_type=0x100000c, translation_value=0, query_errno=0,
        user_page=16384, vm_page=16384, kernel_page=16384, kernel_error=0)


def owner_row(control, opcode=6, status=0):
    value = dict(version=1, record_kind='pear_fex_memory_fixture', scope='native_owner',
        sequence=1, event='owner_call', control=control, opcode=opcode, returned_status=status,
        status=status, requested_state=0, operation_offset='0000000000000000',
        operation_size='0000000000000000', allocation_id=0, generation=0, extent_offset=0,
        extent_size=0, write_epoch=0, executor_id=0, continuation_id=0, executor_state=0,
        lifecycle=0, protection=0, capabilities=0, native_error_domain=0, native_error_code=0)
    return value


def atomic_rows():
    """Independent source-realistic scalar example; not native evidence."""
    from .synthetic_atomic import source_rows
    return source_rows('native_owner')


def native_rows():
    """Structural transcript fixture only; counters never establish host admission."""
    rows = [helper(), ready(), dict(version=1, record_kind='pear_fex_memory_admission',
        event='initialize', status=0, native_error_domain=0, native_error_code=0,
        checked_ec=False, wine_view_registration=False)]
    groups = {'register_actual_native_executor': (1, 7), 'reserve_extent': (102, 1),
        'query_current_token': (102, 6), 'begin_two_page_write': (37, 2), 'publish_two_pages': (37, 3),
        'enter_owned_leaf': (73, 8), 'exit_to_native_gate': (73, 9), 'begin_cross_page_instruction_pair': (1, 2),
        'publish_cross_page_instruction_pair': (1, 3), 'enter_before_source_continuation': (1, 8),
        'pin_saved_source_resume': (1, 10), 'direct_owned_handoff_to_native': (1, 13),
        'poll_existing_owned_handoff': (1, 13),
        'admit_finite_saved_resume': (127, 10), 'discard_owned_saved_resume': (127, 11),
        'release_original_pin_epoch': (1, 11), 'begin_unpublished_abort_control': (1, 2),
        'abort_unpublished_window': (1, 4), 'retire_extent': (103, 5), 'unregister_actual_native_executor': (1, 12)}
    for control, (count, opcode) in groups.items():
        rows += [owner_row(control, opcode) for _ in range(count)]
    failures = {'version_mismatch': (6, 2), 'record_size_mismatch': (6, 1), 'unknown_opcode': (15, 1),
        'unknown_flags': (6, 1), 'reserved_word': (6, 1), 'reserved_word64': (6, 1), 'foreign_owner': (6, 6),
        'stale_generation': (6, 6), 'foreign_allocation': (6, 6), 'offset_alias': (6, 6), 'extent_alias': (6, 6),
        'unselected_role': (6, 1), 'native_fixture_cannot_select_arm64ec_role': (7, 3),
        'wrapped_write_range': (2, 1), 'source_guard_write': (2, 1), 'empty_write': (2, 1),
        'ordinary_exit_cannot_drop_saved_resume': (9, 1), 'nested_handoff_refused': (13, 1),
        'poll_requires_original_pin_epoch': (13, 1), 'poll_requires_exact_resume_offset': (13, 1),
        'poll_requires_existing_continuation': (13, 1),
        'unregister_cannot_drop_saved_resume': (12, 1), 'retirement_keeps_saved_generation': (5, 3),
        'continuation_capacity_preserves_old_pins': (10, 4), 'new_epoch_cannot_release_original_pin': (11, 1),
        'duplicate_retirement': (5, 6), 'shared_capacity_exhausted': (1, 4),
        'fragmented_free_bytes_refused': (1, 4), 'dispatcher_capacity_exhausted': (1, 4)}
    rows += [owner_row(c, op, status) for c, (op, status) in failures.items()]
    rows += [owner_row('mixed_extent_query_unavailable', 6, 3) for _ in range(111)]
    rows += atomic_rows()
    for index, row in enumerate(rows[3:], 1): row['sequence'] = index
    calls = len(rows) - 3
    rows += [dict(version=1, record_kind='pear_fex_memory_fixture', scope='native_owner', sequence=calls+1,
        event='suite_complete', passed=True, checked_ec=False, owner_calls=calls, refusals=153,
        allocations=103, retirements=103, publications=40, owned_code_calls=73,
        protection_observations=83, patch_rounds=32, fragmentation_controls=1, continuation_controls=2,
        fex_initialization=False, translated_guest_execution=False, game_execution=False),
        dict(version=1, record_kind='pear_fex_memory_admission', event='finish', observed_regions=83,
        native_owned_code_execution=True, native_arm64_pe_execution=False, checked_ec=False,
        wine_view_registration=False, fex_initialization=False, translated_guest_execution=False,
        game_execution=False, exit_code=0)]
    return rows


def cooperative_rows():
    """Structural schedules; synthetic identities are never current host evidence."""
    rows = [helper(), ready()]
    setup = [('setup_register', 7), ('reserve_extent', 1), ('query_current_token', 6),
             ('begin_two_page_write', 2), ('publish_two_pages', 3), ('setup_unregister', 12)]
    rows += [owner_row(control, opcode) for control, opcode in setup]
    def event(actor, name):
        return dict(version=1, record_kind='pear_fex_memory_cooperative', sequence=1,
                    event=name, actor=actor, native_error_code=0)
    def call(actor, control, opcode, state, status=0):
        return dict(version=1, record_kind='pear_fex_memory_cooperative', sequence=1,
            event='owner_call', actor=actor, control=control, opcode=opcode,
            returned_status=status, status=status, executor_id=0 if status else actor+1,
            continuation_id=0, executor_state=state, write_epoch=0,
            native_error_domain=0, native_error_code=0)
    for actor in range(4):
        rows += [event(actor, 'thread_create'), call(actor, 'register_owned_worker', 7, 1)]
    for phase in range(32):
        for actor in range(3):
            rows.append(call(actor, 'enter_source_leaf', 8, 2))
        rows.append(call(3, ('active_participant_timeout' if phase == 0 else
            'native_pin_without_park_timeout' if phase == 1 else 'cooperative_writer_admission'),
            2, 0 if phase < 2 else 1, 5 if phase < 2 else 0))
        for actor in range(3):
            rows.append(call(actor, 'handoff_to_compiled_native_gate', 13, 3))
        if phase >= 2: rows.append(call(3, 'publish_after_native_park_ack', 3, 1))
        for actor in range(3):
            rows.append(call(actor, 'poll_existing_source_descriptor', 13, 3))
            rows.append(call(actor, 'discard_saved_resume_original_epoch', 11, 1))
    for actor in range(4):
        rows += [call(actor, 'unregister_owned_worker', 12, 5), event(actor, 'thread_join')]
    rows += [owner_row('cleanup_register_after_worker_join', 7),
        owner_row('mixed_extent_query_unavailable', 6, 3), owner_row('retire_extent', 5),
        owner_row('cleanup_unregister_after_retirement', 12)]
    rows.append(dict(version=1, record_kind='pear_fex_memory_cooperative', event='complete', sequence=1,
        passed=True, owned_workers=4, workers_joined=4, schedules=32, timeout_controls=2,
        writes=30, handoffs=96, owned_leaf_calls=96, wire_poll_calls=96, condition_cleanup=0, mutex_cleanup=0,
        trace_cleanup=0, checked_ec=False, wine_view_registration=False, fex_initialization=False,
        translated_guest_execution=False, game_execution=False))
    counts = Counter()
    for row in rows[2:]:
        counts[row['record_kind']] += 1; row['sequence'] = counts[row['record_kind']]
    return rows
