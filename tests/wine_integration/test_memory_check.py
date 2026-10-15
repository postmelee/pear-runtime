# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact original assertions; historical finite transcript scope only."""
from copy import deepcopy
import unittest
from pear_runtime.errors import Error
from tests.wine_integration.oracles import memory as runner
from tests.wine_integration.oracles.synthetic_memory import (NONCE, CHILD, ready, helper, owner_row, atomic_rows, native_rows, cooperative_rows)

class AdmissionAndResult(unittest.TestCase):
    def test_admission_binds_exact_current_identity_and_original_error_facts(self):
        runner.validate_ready(ready(), CHILD, NONCE)
        for key, value in [('pid', 18), ('parent_pid', 20), ('start_microseconds', 30),
            ('translation_value', 1), ('kernel_page_result', 5), ('host_port_release_result', 5),
            ('user_page_errno', 13), ('user_page', 16384), ('geometry_accepted', 1), ('version', True)]:
            row = ready(); row[key] = value
            with self.subTest(field=key), self.assertRaises(Error): runner.validate_ready(row, CHILD, NONCE)
        row = ready(); row['unreviewed_permission'] = True
        with self.assertRaises(Error): runner.validate_ready(row, CHILD, NONCE)

    def test_successful_structural_transcript_keeps_native_scope_and_128_pins(self):
        value = runner.validate_result(native_rows(), 'pear-fex-memory')
        self.assertEqual(value['terminal']['continuation_controls'], 2)
        self.assertEqual(value['owner_calls'], 964)
        self.assertEqual(value['controlled_refusals'], 153)

    def test_duplicate_or_missing_trace_sequence_never_passes(self):
        for change in ('duplicate', 'missing'):
            rows = native_rows(); rows[4]['sequence'] += -1 if change == 'duplicate' else 1
            with self.subTest(change=change), self.assertRaises(Error): runner.validate_result(rows, 'pear-fex-memory')

    def test_unknown_records_extra_fields_and_boolean_status_are_closed(self):
        mutations = [('record_kind', 'unrelated_native_result'), ('status', False),
                     ('native_error_domain', False), ('extra', 0), ('version', True)]
        for key, value in mutations:
            rows = native_rows(); rows[3][key] = value
            with self.subTest(field=key), self.assertRaises(Error): runner.validate_result(rows, 'pear-fex-memory')

    def test_native_error_codes_and_refusal_facts_cannot_be_hidden(self):
        for field, number in [('executor_id', 7), ('generation', 7), ('capabilities', 7),
                              ('native_error_code', 13)]:
            rows = native_rows(); row = next(r for r in rows if r.get('status') == 6); row[field] = number
            with self.subTest(field=field), self.assertRaises(Error): runner.validate_result(rows, 'pear-fex-memory')

    def test_uint64_malformed_range_is_lossless_hex_with_original_json_bound(self):
        rows = native_rows(); row = next(r for r in rows if r.get('control') == 'wrapped_write_range')
        row['operation_offset'] = 'ffffffffffffffff'
        runner.validate_result(rows, 'pear-fex-memory')
        for value in [2**64-1, 'FFFFFFFFFFFFFFFF', '0xffffffffffffffff', 'fff']:
            row['operation_offset'] = value
            with self.subTest(value=value), self.assertRaises(Error): runner.validate_result(rows, 'pear-fex-memory')

    def test_partial_pin_admission_or_generic_native_failure_does_not_qualify(self):
        for change in ('pin', 'failure', 'ec'):
            rows = native_rows()
            if change == 'pin': next(r for r in rows if r.get('control') == 'admit_finite_saved_resume')['opcode'] = 6
            elif change == 'failure':
                r = next(r for r in rows if r.get('control') == 'shared_capacity_exhausted'); r['status'] = r['returned_status'] = 7
                r['native_error_domain'] = 1; r['native_error_code'] = 13
            else: rows[-2]['checked_ec'] = True
            with self.subTest(change=change), self.assertRaises(Error): runner.validate_result(rows, 'pear-fex-memory')

    def test_terminals_are_not_reordered_or_relabelled(self):
        rows = native_rows(); rows[-1], rows[-2] = rows[-2], rows[-1]
        with self.assertRaises(Error): runner.validate_result(rows, 'pear-fex-memory')
        with self.assertRaises(Error): runner.validate_result(native_rows(), 'unknown-fixture')


class CooperativeResult(unittest.TestCase):
    def test_four_owned_workers_and_both_real_timeout_controls_are_required(self):
        result = runner.validate_result(cooperative_rows(), 'pear-fex-cooperative')
        self.assertEqual(result['owner_calls'], 464)
        self.assertEqual(result['controlled_refusals'], 3)
        self.assertEqual(result['terminal']['owned_workers'], 4)

    def test_join_failure_duplicate_actor_and_cleanup_errors_never_pass(self):
        for change in ('join_error', 'duplicate_actor', 'cleanup', 'boolean_count'):
            rows = cooperative_rows()
            if change == 'join_error':
                next(r for r in rows if r.get('event') == 'thread_join')['native_error_code'] = 22
            elif change == 'duplicate_actor':
                joined = [r for r in rows if r.get('event') == 'thread_join']; joined[-1]['actor'] = 0
            elif change == 'cleanup': rows[-1]['trace_cleanup'] = 16
            else: rows[-1]['timeout_controls'] = True
            with self.subTest(change=change), self.assertRaises(Error):
                runner.validate_result(rows, 'pear-fex-cooperative')

    def test_pinned_or_active_state_is_not_a_completed_native_park(self):
        for field, value in [('status', 0), ('executor_state', 3), ('actor', 2), ('opcode', 6)]:
            rows = cooperative_rows()
            row = next(r for r in rows if r.get('control') == 'native_pin_without_park_timeout')
            row[field] = value
            if field == 'status': row['returned_status'] = value
            with self.subTest(field=field), self.assertRaises(Error):
                runner.validate_result(rows, 'pear-fex-cooperative')

    def test_failed_cleanup_or_relabelled_opcode_cannot_count_as_retirement(self):
        for field, value in [('status', 3), ('opcode', 6)]:
            rows = cooperative_rows(); row = next(r for r in rows if r.get('control') == 'retire_extent')
            row[field] = value
            if field == 'status': row['returned_status'] = value
            with self.subTest(field=field), self.assertRaises(Error):
                runner.validate_result(rows, 'pear-fex-cooperative')
