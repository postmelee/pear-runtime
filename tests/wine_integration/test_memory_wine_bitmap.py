# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic private row controls only; no Wine/VM/owner/compiled code."""
from copy import deepcopy
import json
import unittest
from tests.wine_integration.oracles import bitmap as policy


def observation(mode=0):
    value = dict.fromkeys(policy.VM_KEYS, 0)
    value.update(performed=False, port_release_performed=False, predicate_failed=False)
    value['mode'] = mode
    if mode:
        value.update(performed=True, calls=1, count=9)
    return value


def row():
    value = dict.fromkeys(policy.KEYS, 0)
    value.update({name: False for name in policy.BOOL_KEYS})
    value.update(schema_version=1, record_kind='pear_fex_bitmap_diagnostic',
                 scope='finite_wine_owner_bitmap_restoration', final_bitmap_equal=True, final_peb_equal=True,
                 original_bitmap_present=True, original_peb_bitmap_present=True,
                 bitmap_prepared=True, page_count_performed=True, page_count=1)
    for name in ('cleanup_vm', 'page_vm', 'release_vm'):
        value[name] = observation()
    value['cleanup_vm'] = observation(1)
    value['cleanup_vm'].update(expected=3, protection=3, maximum=7)
    return value


def early_row():
    value = row()
    value.update(bitmap_prepared=False, page_count_performed=False, page_count=0)
    value['cleanup_vm'] = observation()
    return value


def wire(value):
    return policy.PREFIX + json.dumps(value, separators=(',', ':')).encode() + b'\n'


def bitmap(restored=False, domain=0, code=0):
    return dict(set_observed=True, clear_observed=True, restoration_observed=restored,
                none_before=True, none_after=True, actual_peb_bitmap=True, restoration_attempted=True,
                hybrid_classification=False, error_domain=domain, error_code=code)


def primary_wire(value):
    return policy.BITMAP_PREFIX + json.dumps(value, separators=(',', ':')).encode() + b'\n'


def created_release(success):
    value = row()
    value.update(created_bitmap=True,original_bitmap_present=False,original_peb_bitmap_present=False,
                 release_performed=True,release_classification_performed=True,
                 release_arena_check_performed=True,release_method=2,release_native_performed=True,
                 release_native_succeeded=success)
    if success:
        value['release_vm'] = observation(2); value['release_vm'].update(region_code=1)
    else:
        value.update(failure_predicates=512|2048|4096,final_bitmap_equal=False,final_peb_equal=False,
                     native_error_domain=1,native_error_code=22)
    return value


class DiagnosticControls(unittest.TestCase):
    def test_unperformed_fields_do_not_infer_restoration_or_execution(self):
        primary = bitmap()
        primary.update(set_observed=False, clear_observed=False, none_before=False,
                       none_after=False, actual_peb_bitmap=False, restoration_attempted=False)
        value = policy.parse_row(wire(early_row()), primary)
        self.assertFalse(value['page_count_performed'])
        self.assertFalse(value['release_native_performed'])
        self.assertFalse(value['fex_initialization'])

    def test_logical_failed_page_preserves_zero_native_error(self):
        value = row()
        value.update(failure_predicates=4, bitmap_prepared=True, page_count_performed=True, page_count=2,
                     first_page_performed=True, first_page=1, previous_vprot=33, current_vprot=33,
                     set_vprot_performed=True, set_vprot_succeeded=True)
        value['page_vm'] = observation(1)
        value['page_vm'].update(expected=1, protection=5, maximum=7, predicate_failed=True)
        actual = policy.parse_row(wire(value), bitmap())
        self.assertEqual((actual['native_error_domain'], actual['native_error_code']), (0, 0))
        self.assertEqual(actual['page_vm']['protection'], 5)
        with self.assertRaisesRegex(policy.Refused, 'promoted'):
            policy.parse_row(wire(value), bitmap(restored=True))

    def test_real_native_error_stays_distinct_from_predicate_failure(self):
        value = row(); value.update(failure_predicates=1, native_error_domain=3, native_error_code=2)
        value['cleanup_vm'] = observation(1); value['cleanup_vm'].update(expected=3, region_code=2)
        policy.parse_row(wire(value), bitmap(domain=3, code=2))
        with self.assertRaisesRegex(policy.Refused, 'primary_error'):
            policy.parse_row(wire(value), bitmap(domain=3, code=3))

    def test_partial_reserved_release_refuses_without_fabricated_syscall(self):
        value = row(); value.update(created_bitmap=True, release_performed=True,
            original_bitmap_present=False, release_classification_performed=True,
            release_reserved=-1, failure_predicates=32|2048, final_bitmap_equal=False)
        policy.parse_row(wire(value), bitmap())
        value['release_native_performed'] = True
        with self.assertRaises(policy.Refused): policy.parse_row(wire(value), bitmap())

    def test_successful_hole_observation_can_return_kern_invalid_address(self):
        value = row(); value.update(created_bitmap=True, release_performed=True,
            original_bitmap_present=False, release_classification_performed=True, release_arena_check_performed=True,
            release_method=2, release_native_performed=True, release_native_succeeded=True)
        value['release_vm'] = observation(2); value['release_vm'].update(region_code=1)
        policy.parse_row(wire(value), bitmap(restored=True))
        value['release_vm']['mode'] = 1
        with self.assertRaises(policy.Refused): policy.parse_row(wire(value))

    def test_wrong_scope_flags_unknown_keys_boolean_integers_and_mask_refused(self):
        for key, val in [('schema_version', True), ('scope', 'runtime'), ('failure_predicates', 8192),
                         ('first_page', True), ('page_count', -1), ('game_execution', True),
                         ('native_error_domain', 4), ('native_error_code', 9), ('arbitrary', 17)]:
            value = row(); value[key] = val
            with self.subTest(key=key), self.assertRaises(policy.Refused): policy.parse_row(wire(value))

    def test_missing_duplicate_truncated_extra_lines_nonascii_and_overbound_refused(self):
        value = row(); del value['cleanup_vm']
        malformed = [wire(value), wire(row())[:-1], wire(row())+b'\n', wire(row())+b'garbage\n',
                     wire(row()).replace(b'{', b'{"schema_version":1,', 1), policy.PREFIX+b'\xff\n',
                     policy.PREFIX+b' '*policy.MAX_ROW+b'\n']
        for raw in malformed:
            with self.subTest(raw=raw[:100]), self.assertRaises(policy.Refused): policy.parse_row(raw)

    def test_first_page_capacity_identity_missing_observation_refused(self):
        for changes in [dict(first_page_performed=True), dict(page_count=33),
                        dict(first_page=32), dict(set_vprot_succeeded=True)]:
            value = row(); value.update(changes)
            with self.subTest(changes=changes), self.assertRaises(policy.Refused): policy.parse_row(wire(value))

    def test_unknown_vm_never_fabricates_protection_or_port_release(self):
        for changes in [dict(protection=1), dict(performed=True), dict(calls=1),
                        dict(port_release_performed=True), dict(port_release_code=2), dict(expected=True)]:
            value = row(); value['page_vm'].update(changes)
            with self.subTest(changes=changes), self.assertRaises(policy.Refused): policy.parse_row(wire(value))

    def test_failed_original_identity_is_not_reset_by_parser(self):
        value = row(); value.update(failure_predicates=2048|4096, final_bitmap_equal=False, final_peb_equal=False)
        result = policy.parse_row(wire(value), bitmap())
        self.assertFalse(result['final_bitmap_equal'])
        value['final_bitmap_equal'] = True
        with self.assertRaises(policy.Refused): policy.parse_row(wire(value), bitmap())

    def test_native_protection_flags_and_error_type_are_strict(self):
        for name, bad in [('region_code', True), ('protection', -1), ('maximum', 2**32), ('performed', 1)]:
            value = row(); value['cleanup_vm'].update({name: bad})
            with self.subTest(name=name), self.assertRaises(policy.Refused): policy.parse_row(wire(value))

    def test_stream_pairs_each_diagnostic_without_promoting_failed_primary(self):
        first = row()
        first.update(failure_predicates=2048, final_bitmap_equal=False)
        raw = (b'private prior stderr\n' + wire(first) + primary_wire(bitmap())
               + wire(row()) + primary_wire(bitmap(restored=True)) + b'private tail stderr\n')
        pairs, remainder = policy.parse_stream(raw, 2)
        self.assertEqual(len(pairs), 2)
        self.assertFalse(pairs[0]['bitmap']['restoration_observed'])
        self.assertFalse(pairs[0]['diagnostic']['final_bitmap_equal'])
        self.assertEqual(remainder, b'private prior stderr\nprivate tail stderr\n')
        self.assertNotIn('passed', pairs[0])

    def test_stream_missing_duplicate_orphan_reordered_and_interleaved_refused(self):
        diag = wire(row()); primary = primary_wire(bitmap())
        cases = [primary, diag, diag+diag+primary, primary+diag, diag+b'unrelated\n'+primary,
                 diag+primary+diag, diag+primary+diag+primary]
        for raw in cases:
            with self.subTest(raw=raw[:70]), self.assertRaises(policy.Refused): policy.parse_stream(raw, 1)

    def test_stream_unknown_bitmap_like_lines_remain_refused(self):
        pair = wire(row())+primary_wire(bitmap())
        for line in (b'PEAR_FEX_BITMAP_DIAGNOSTICX {}\n', b'warning PEAR_FEX_BITMAP {}\n',
                     b' PEAR_FEX_BITMAP_DIAGNOSTIC {}\n'):
            with self.subTest(line=line), self.assertRaisesRegex(policy.Refused, 'unrecognized'):
                policy.parse_stream(pair+line, 1)

    def test_stream_count_bound_primary_types_and_error_pairing_are_closed(self):
        pair = wire(row())+primary_wire(bitmap())
        for expected in (True, 0, 129, 2):
            with self.subTest(expected=expected), self.assertRaises(policy.Refused):
                policy.parse_stream(pair, expected)
        for change in ({'error_code':True}, {'restoration_observed':1}, {'arbitrary':False},
                       {'hybrid_classification':True}, {'error_domain':3,'error_code':2}):
            primary = bitmap(); primary.update(change)
            with self.subTest(change=change), self.assertRaises(policy.Refused):
                policy.parse_stream(wire(row())+primary_wire(primary), 1)
        with self.assertRaises(policy.Refused): policy.parse_stream(b'x'* (policy.MAX_STREAM+1), 1)

    def test_stream_diagnostic_and_primary_duplicate_json_keys_are_refused(self):
        for raw in (wire(row()).replace(b'{', b'{"schema_version":1,', 1)+primary_wire(bitmap()),
                    wire(row())+primary_wire(bitmap()).replace(b'{', b'{"set_observed":true,', 1)):
            with self.assertRaisesRegex(policy.Refused, 'duplicate'):
                policy.parse_stream(raw, 1)

    def test_four_reviewed_source_impossible_positive_pairs_are_refused(self):
        release = created_release(False)
        release.update(failure_predicates=0, final_bitmap_equal=True, final_peb_equal=True)
        cleanup = row()
        cleanup.update(native_error_domain=3, native_error_code=5)
        cleanup['cleanup_vm'].update(region_code=5)
        pages = row(); pages['page_count'] = 33
        hole = created_release(True); hole['release_vm']['calls'] = 8
        for value in (release, cleanup, pages, hole):
            primary = bitmap(restored=True, domain=value['native_error_domain'], code=value['native_error_code'])
            with self.subTest(value=value), self.assertRaises(policy.Refused):
                policy.parse_row(wire(value), primary)

    def test_failed_release_requires_exact_branch_mask_and_retained_identity(self):
        value = created_release(False)
        primary = bitmap(domain=1, code=22)
        policy.parse_row(wire(value), primary)
        for changes in ({'failure_predicates':2048|4096},
                        {'failure_predicates':128|2048|4096},
                        {'failure_predicates':512|256|2048|4096},
                        {'release_native_succeeded':True}, {'native_error_domain':0,'native_error_code':0},
                        {'final_bitmap_equal':True,'failure_predicates':512|4096}):
            bad = deepcopy(value); bad.update(changes)
            with self.subTest(changes=changes), self.assertRaises(policy.Refused):
                policy.parse_row(wire(bad))

    def test_first_failed_page_requires_actual_failure_presence_and_matching_bits(self):
        value = row()
        value.update(failure_predicates=2, first_page_performed=True, previous_vprot=33,
                     current_vprot=33, set_vprot_performed=True, set_vprot_succeeded=False)
        value['page_vm'] = observation(1)
        value['page_vm'].update(expected=1, protection=1, maximum=7)
        policy.parse_row(wire(value), bitmap())
        for changes in ({'first_page_performed':False}, {'failure_predicates':4},
                        {'failure_predicates':6}, {'set_vprot_succeeded':True},
                        {'previous_vprot':35}):
            bad = deepcopy(value); bad.update(changes)
            with self.subTest(changes=changes), self.assertRaises(policy.Refused):
                policy.parse_row(wire(bad))
        no_snapshot = row(); no_snapshot['failure_predicates'] = 4
        with self.assertRaisesRegex(policy.Refused, 'mask_presence'): policy.parse_row(wire(no_snapshot))

    def test_global_later_failure_bits_do_not_overwrite_first_snapshot_or_primary_error(self):
        value = row()
        value.update(page_count=2, failure_predicates=1|2|4, first_page_performed=True,
                     previous_vprot=33, current_vprot=33, set_vprot_performed=True,
                     set_vprot_succeeded=True, native_error_domain=3, native_error_code=7)
        value['cleanup_vm'].update(region_code=5)
        value['page_vm'] = observation(1)
        value['page_vm'].update(expected=1, protection=5, maximum=7, predicate_failed=True)
        actual = policy.parse_row(wire(value), bitmap(domain=3, code=7))
        self.assertEqual(actual['native_error_code'], 7)
        self.assertEqual(actual['cleanup_vm']['region_code'], 5)
        self.assertTrue(actual['set_vprot_succeeded'])
        value['first_page'] = 1
        with self.assertRaisesRegex(policy.Refused, 'exact_mask'): policy.parse_row(wire(value))

    def test_created_bitmap_complement_and_unperformed_source_paths_are_closed(self):
        for changes in ({'created_bitmap':True}, {'original_bitmap_present':False},
                        {'original_peb_bitmap_present':False}, {'bitmap_prepared':False}):
            value = row(); value.update(changes)
            with self.subTest(changes=changes), self.assertRaises(policy.Refused):
                policy.parse_row(wire(value))
        early = early_row(); early.update(page_count_performed=True, page_count=33)
        primary = bitmap(); primary.update(set_observed=False,clear_observed=False,restoration_observed=False,
                                          none_after=False,restoration_attempted=False)
        policy.parse_row(wire(early), primary)
        primary['restoration_observed'] = True
        with self.assertRaises(policy.Refused): policy.parse_row(wire(early), primary)

    def test_native_observer_branch_and_unmarked_logical_failure_are_closed(self):
        for changes in ({'count':8}, {'protection':5}, {'maximum':0},
                        {'port_release_performed':True,'port_release_code':3},
                        {'region_code':5}, {'performed':False}):
            value = row(); value['cleanup_vm'].update(changes)
            with self.subTest(changes=changes), self.assertRaises(policy.Refused):
                policy.parse_row(wire(value), bitmap(restored=True))
        value = row(); value.update(failure_predicates=1)
        value['cleanup_vm'].update(protection=5,predicate_failed=True)
        policy.parse_row(wire(value), bitmap())

    def test_primary_prior_error_can_survive_successful_restoration(self):
        value = row(); value.update(native_error_domain=1,native_error_code=13)
        primary = bitmap(restored=True,domain=1,code=13)
        primary['set_observed'] = False
        policy.parse_row(wire(value),primary)
        # Parser retains facts; the parent's original all-success/zero-error
        # qualification predicate must still deny this pair.
        self.assertFalse(primary['set_observed'])

    def test_selected_get_unix_prot_mapping_is_exact_and_not_force_exec_relabeling(self):
        for value, expected in ((0x00,0),(0x21,1),(0x23,3),(0x24,5),(0x28,3),
                                (0x31,0),(0x63,1),(0x64,5),(0x20,0)):
            with self.subTest(vprot=value): self.assertEqual(policy.unix_protection(value),expected)
        hole = created_release(True)
        hole['release_vm'].update(port_release_performed=True,port_release_code=5)
        policy.parse_row(wire(hole),bitmap(restored=True))
        # Original hole code keeps KERN_INVALID_ADDRESS and returns success;
        # the failed object-port release is preserved but not invented as error.
        self.assertEqual(hole['native_error_domain'],0)

    def test_release_observer_failure_requires_exact_mask_and_retains_prior_primary_error(self):
        value = created_release(True)
        value.update(failure_predicates=1024|2048, final_bitmap_equal=False,
                     native_error_domain=3, native_error_code=7)
        value['release_vm'].update(region_code=5)
        policy.parse_row(wire(value),bitmap(domain=3,code=7))
        for changes in ({'failure_predicates':2048}, {'failure_predicates':256|2048},
                        {'native_error_domain':0,'native_error_code':0}):
            bad = deepcopy(value); bad.update(changes)
            with self.subTest(changes=changes), self.assertRaises(policy.Refused):
                policy.parse_row(wire(bad))
        value['release_vm']['predicate_failed'] = True
        with self.assertRaisesRegex(policy.Refused,'precedes_predicate'): policy.parse_row(wire(value))

    def test_cleanup_native_port_error_requires_failure_mask_without_latest_code_override(self):
        value = row()
        value.update(failure_predicates=1, native_error_domain=2, native_error_code=-1073741811)
        value['cleanup_vm'].update(port_release_performed=True,port_release_code=5)
        result = policy.parse_row(wire(value),bitmap(domain=2,code=-1073741811))
        self.assertEqual(result['native_error_code'],-1073741811)
        self.assertEqual(result['cleanup_vm']['port_release_code'],5)
        value['failure_predicates'] = 0
        with self.assertRaisesRegex(policy.Refused,'cleanup_failure_mask'): policy.parse_row(wire(value))

    def test_source_realistic_positive_completed_pairs_are_separate_from_partial_failure(self):
        existing = row()
        created = created_release(True)
        created['release_vm'].update(port_release_performed=True,port_release_code=5)
        raw = wire(existing)+primary_wire(bitmap(restored=True))+wire(created)+primary_wire(bitmap(restored=True))
        pairs,other = policy.parse_stream(raw,2)
        self.assertEqual(len(pairs),2)
        self.assertEqual(other,b'')
        self.assertFalse(pairs[0]['diagnostic']['created_bitmap'])
        self.assertTrue(pairs[1]['diagnostic']['created_bitmap'])
        self.assertEqual(pairs[1]['diagnostic']['release_vm']['region_code'],1)
        self.assertEqual(pairs[1]['diagnostic']['native_error_domain'],0)
        failed,_ = policy.parse_failed_prefix(raw,2)
        self.assertEqual(failed['observed_self_tests'],2)
        self.assertIs(failed['completed_self_test_count_verified'],False)
        self.assertNotIn('passed',failed)

    def test_partial_failed_prefix_preserves_required_count_and_original_error(self):
        value = row()
        value.update(failure_predicates=1,native_error_domain=3,native_error_code=7)
        value['cleanup_vm']['region_code'] = 5
        raw = wire(value)+primary_wire(bitmap(domain=3,code=7))
        observed,other = policy.parse_failed_prefix(raw,38)
        self.assertEqual(observed['required_self_tests'],38)
        self.assertEqual(observed['observed_self_tests'],1)
        self.assertIs(observed['completed_self_test_count_verified'],False)
        self.assertEqual(observed['observations'][0]['bitmap']['error_code'],7)
        self.assertEqual(other,b'')
        with self.assertRaisesRegex(policy.Refused,'count'): policy.parse_stream(raw,38)

    def test_partial_prefix_does_not_recover_malformed_rows_or_infer_unobserved_execution(self):
        assessment,other = policy.parse_failed_prefix(b'private early process failure\n',38)
        self.assertEqual(assessment['observed_self_tests'],0)
        self.assertEqual(assessment['runtime_qualification'],'unperformed')
        self.assertEqual(other,b'private early process failure\n')
        raw = wire(row())+primary_wire(bitmap())
        for tail in (wire(row()),b'PEAR_FEX_BITMAP_DIAGNOSTIC {}\n',b'PEAR_FEX_BITMAP {}\n'):
            with self.subTest(tail=tail[:40]), self.assertRaises(policy.Refused):
                policy.parse_failed_prefix(raw+tail,38)
        for count in (True,0,129):
            with self.subTest(count=count), self.assertRaises(policy.Refused):
                policy.parse_failed_prefix(raw,count)


if __name__ == '__main__':
    unittest.main()
