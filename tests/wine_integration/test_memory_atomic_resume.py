# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact original assertions; historical finite transcript scope only."""
import copy
import unittest
from tests.wine_integration.oracles import resume as checks
from tests.wine_integration.oracles.synthetic_atomic import IDENTITY, FACTS, source_rows

def need(condition, message):
    if not condition:
        raise ValueError(message)


def named(rows, name, occurrence=0):
    return [value for value in rows if value['control'] == name][occurrence]


class AtomicReaderTests(unittest.TestCase):
    def assert_refused(self, rows, scope='native_owner', reason=None):
        with self.assertRaises(ValueError) as caught:
            checks.validate(rows, need, scope=scope)
        if reason:
            self.assertEqual(str(caught.exception), reason)

    def test_realistic_native_transcript(self):
        value = checks.validate(source_rows(), need, scope='native_owner')
        self.assertEqual(value, {'actual_owner_operations': 25, 'precommit_refusals': 11,
                               'committed_resumes': 1, 'source_lifetime_qualified': False,
                               'fex_initialization': False})

    def test_realistic_wine_transcript(self):
        value = checks.validate(source_rows('wine_owner'), need, scope='wine_owner')
        self.assertEqual(value['actual_owner_operations'], 25)
        self.assertFalse(value['source_lifetime_qualified'])

    def test_scopes_fix_wrong_role_status(self):
        self.assertEqual(checks.controls('native_owner')[1]['atomic_wrong_role'], 6)
        self.assertEqual(checks.controls('wine_owner')[1]['atomic_wrong_role'], 3)
        for scope, wrong in [('native_owner', 3), ('wine_owner', 6)]:
            with self.subTest(scope=scope):
                rows = source_rows(scope)
                value = named(rows, 'atomic_wrong_role')
                value['status'] = value['returned_status'] = wrong
                self.assert_refused(rows, scope, 'memory_atomic_control_result')

    def test_scope_is_explicit(self):
        with self.assertRaises(TypeError):
            checks.validate(source_rows(), need)
        with self.assertRaises(TypeError):
            checks.controls()

    def test_unknown_scope(self):
        self.assert_refused(source_rows(), 'any_owner', 'memory_atomic_scope')
        with self.assertRaises(ValueError):
            checks.controls('any_owner')

    def test_declared_scope_cannot_relabel_rows(self):
        self.assert_refused(source_rows(), 'wine_owner', 'memory_atomic_scope')

    def test_one_changed_scope(self):
        rows = source_rows()
        rows[2]['scope'] = 'wine_owner'
        self.assert_refused(rows, reason='memory_atomic_scope')

    def test_negative_request_fields(self):
        mutations = [('atomic_wrong_size', 'operation_size', '0000000000000004'),
                     ('atomic_wrong_offset', 'operation_offset', '0000000000000000'),
                     ('atomic_old_wire_version', 'requested_state', 0),
                     ('atomic_missing_continuation', 'operation_size', '0000000000000000'),
                     ('atomic_wrong_role', 'operation_offset', '0000000000000004')]
        for control, key, value in mutations:
            with self.subTest(control=control, key=key):
                rows = source_rows(); named(rows, control)[key] = value
                self.assert_refused(rows, reason='memory_atomic_request_shape')

    def test_positive_request_fields(self):
        for control, key, value in [('atomic_enter_dispatcher', 'operation_size', '0000000000000000'),
                                    ('atomic_refusal_preserves_original_pin', 'operation_size', '0000000000000004'),
                                    ('atomic_exit_consumed_continuation', 'requested_state', 1)]:
            with self.subTest(control=control):
                rows = source_rows(); named(rows, control)[key] = value
                self.assert_refused(rows, reason='memory_atomic_request_shape')

    def test_refusal_cannot_grant_facts(self):
        for key in FACTS:
            with self.subTest(key=key):
                rows = source_rows(); named(rows, 'atomic_wrong_generation')[key] = 1
                self.assert_refused(rows, reason='memory_atomic_refusal_facts')

    def test_native_error_fields_not_discarded(self):
        for key in ['native_error_domain', 'native_error_code']:
            rows = source_rows(); named(rows, 'atomic_wrong_size')[key] = 1
            self.assert_refused(rows, reason='memory_atomic_control_native_error')

    def test_bool_scalar_is_not_integer_fact(self):
        for key in ['write_epoch', 'status', 'requested_state', 'native_error_code']:
            rows = source_rows(); named(rows, 'atomic_enter_dispatcher')[key] = True
            self.assert_refused(rows, reason='memory_atomic_fact_types')

    def test_returned_status_matches_actual_status(self):
        for control in ['atomic_wrong_size', 'atomic_consume_original_pin_on_current_epoch',
                        'reserve_extent', 'mixed_extent_query_unavailable']:
            rows = source_rows(); named(rows, control)['returned_status'] = 12
            self.assert_refused(rows)

    def test_poll_preserves_original_identity(self):
        for key in list(IDENTITY) + ['write_epoch', 'continuation_id']:
            rows = source_rows(); named(rows, 'atomic_refusal_preserves_original_pin')[key] += 1
            self.assert_refused(rows, reason='memory_atomic_operation_shape' if key == 'extent_size' else 'memory_atomic_original_pin')

    def test_poll_no_managed_active_claim(self):
        rows = source_rows(); named(rows, 'atomic_refusal_preserves_original_pin')['executor_state'] = 2
        self.assert_refused(rows, reason='memory_atomic_original_pin')

    def test_initial_pin_not_fabricated(self):
        rows = source_rows(); named(rows, 'atomic_handoff_dispatcher')['continuation_id'] = 0
        self.assert_refused(rows, reason='memory_atomic_initial_state')

    def test_aligned_source_extent(self):
        rows = source_rows()
        for row in rows:
            if row['extent_size']:
                row['extent_offset'] = 4096
        self.assert_refused(rows, reason='memory_atomic_initial_identity')

    def test_resume_identity_matches_original(self):
        for key in IDENTITY:
            rows = source_rows(); named(rows, 'atomic_consume_original_pin_on_current_epoch')[key] += 16384
            self.assert_refused(rows)

    def test_consumed_continuation_not_retained(self):
        rows = source_rows(); named(rows, 'atomic_consume_original_pin_on_current_epoch')['continuation_id'] = 31
        self.assert_refused(rows, reason='memory_atomic_committed_state')

    def test_resume_epoch_really_advanced(self):
        rows = source_rows(); named(rows, 'atomic_consume_original_pin_on_current_epoch')['write_epoch'] = 29
        self.assert_refused(rows, reason='memory_atomic_committed_state')

    def test_made_up_new_epoch_requires_publisher(self):
        rows = source_rows()
        for control in ['atomic_consume_original_pin_on_current_epoch', 'atomic_exit_consumed_continuation']:
            named(rows, control)['write_epoch'] = 999
        self.assert_refused(rows, reason='memory_atomic_publication_facts')

    def test_exit_same_current_epoch(self):
        rows = source_rows(); named(rows, 'atomic_exit_consumed_continuation')['write_epoch'] = 38
        self.assert_refused(rows, reason='memory_atomic_committed_state')

    def test_missing_initial_publisher(self):
        self.assert_refused(source_rows()[4:], reason='memory_atomic_initial_publication_missing')

    def test_initial_publisher_identity(self):
        for index in range(4):
            rows = source_rows(); rows[index]['generation'] += 1
            self.assert_refused(rows, reason='memory_atomic_publication_facts')

    def test_initial_publisher_original_epoch(self):
        rows = source_rows(); rows[3]['write_epoch'] = 28
        self.assert_refused(rows, reason='memory_atomic_publication_facts')

    def test_initial_write_window_size(self):
        rows = source_rows(); rows[2]['operation_size'] = '0000000000000004'
        self.assert_refused(rows, reason='memory_atomic_publication_facts')

    def test_publication_requires_actual_rx(self):
        rows = source_rows(); named(rows, 'publish_two_pages', 1)['protection'] = 1
        self.assert_refused(rows, reason='memory_atomic_publication_facts')

    def test_replacement_write_identity(self):
        for key in IDENTITY:
            rows = source_rows(); named(rows, 'begin_two_page_write', 1)[key] += 16384
            self.assert_refused(rows, reason='memory_atomic_publication_facts')

    def test_replacement_current_epoch(self):
        rows = source_rows(); named(rows, 'begin_two_page_write', 1)['write_epoch'] = 36
        self.assert_refused(rows, reason='memory_atomic_publication_facts')

    def test_refresh_status_is_actual_unavailable(self):
        rows = source_rows(); value = named(rows, 'mixed_extent_query_unavailable')
        value['status'] = value['returned_status'] = 6
        self.assert_refused(rows, reason='memory_atomic_refresh_unavailable')

    def test_refresh_refusal_facts_are_zero(self):
        rows = source_rows(); named(rows, 'mixed_extent_query_unavailable')['write_epoch'] = 37
        self.assert_refused(rows, reason='memory_atomic_refresh_unavailable')

    def test_refresh_request_is_zero(self):
        rows = source_rows(); named(rows, 'mixed_extent_query_unavailable')['requested_state'] = 3
        self.assert_refused(rows, reason='memory_atomic_refresh_unavailable')

    def test_replacement_state_requires_pin(self):
        rows = source_rows(); named(rows, 'begin_two_page_write', 1)['executor_state'] = 1
        self.assert_refused(rows, reason='memory_atomic_publication_facts')

    def test_retirement_precedes_write(self):
        rows = source_rows(); retired = named(rows, 'atomic_retirement_preserves_original_pin')
        rows.remove(retired); rows.append(retired)
        self.assert_refused(rows, reason='memory_atomic_retirement_before_write')

    def test_no_extra_writer_between_pin_and_retire(self):
        rows = source_rows(); index = rows.index(named(rows, 'atomic_retirement_preserves_original_pin'))
        rows.insert(index, copy.deepcopy(rows[3]))
        self.assert_refused(rows, reason='memory_atomic_retirement_before_write')

    def test_no_missing_refresh_before_current_write(self):
        rows = source_rows(); rows.remove(named(rows, 'mixed_extent_query_unavailable'))
        self.assert_refused(rows, reason='memory_atomic_retirement_before_write')

    def test_publication_order_not_interchangeable(self):
        rows = source_rows(); rows[2], rows[3] = rows[3], rows[2]
        self.assert_refused(rows, reason='memory_atomic_publication_order')

    def test_negative_pairs_source_order(self):
        rows = source_rows(); rows[6:10] = rows[8:10] + rows[6:8]
        self.assert_refused(rows, reason='memory_atomic_refusal_pin_pair')

    def test_poll_adjacent_to_refusal(self):
        rows = source_rows(); rows[6], rows[7] = rows[7], rows[6]
        self.assert_refused(rows, reason='memory_atomic_refusal_pin_pair')

    def test_no_extra_call_before_handoff(self):
        rows = source_rows(); rows.insert(5, copy.deepcopy(rows[3]))
        self.assert_refused(rows, reason='memory_atomic_enter_handoff_order')

    def test_no_gap_in_commit_sequence(self):
        rows = source_rows(); index = rows.index(named(rows, 'atomic_exit_consumed_continuation'))
        rows.insert(index, copy.deepcopy(rows[3]))
        self.assert_refused(rows, reason='memory_atomic_commit_order')

    def test_duplicate_objects_refused(self):
        rows = source_rows(); rows.append(rows[0])
        self.assert_refused(rows, reason='memory_atomic_duplicate_row')

    def test_unknown_atomic_control(self):
        rows = source_rows(); value = copy.deepcopy(rows[6]); value['control'] = 'atomic_unknown'
        rows.append(value)
        self.assert_refused(rows, reason='memory_atomic_control_counts')

    def test_missing_atomic_control(self):
        rows = source_rows(); rows.remove(named(rows, 'atomic_wrong_size'))
        self.assert_refused(rows, reason='memory_atomic_control_counts')

    def test_empty_calls(self):
        self.assert_refused([], reason='memory_atomic_call_shape')

    def test_not_control_row(self):
        self.assert_refused([{'scope': 'native_owner'}], reason='memory_atomic_call_shape')
