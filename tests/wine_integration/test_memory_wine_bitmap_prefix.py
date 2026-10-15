# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable failed-prefix provenance controls; no native or owner execution."""
import hashlib
import unittest
from tests.wine_integration.oracles import bitmap as policy
from tests.wine_integration import test_memory_wine_bitmap as rows

fixture={name:getattr(rows,name) for name in
    ('observation','row','early_row','wire','bitmap','primary_wire','created_release')}


def pair(diagnostic=None, primary=None):
    return fixture['wire'](fixture['row']() if diagnostic is None else diagnostic) + \
        fixture['primary_wire'](fixture['bitmap'](restored=True) if primary is None else primary)


class FailedPrefixControls(unittest.TestCase):
    def observed(self, raw):
        result = policy.observe_failed_prefix(raw)
        self.assertEqual(result['scope'], 'partial_bitmap_diagnostics')
        self.assertIs(result['completed_count_qualified'], False)
        self.assertNotIn('passed', result)
        self.assertNotIn('required_self_tests', result)
        self.assertNotIn('native_error', result)
        return result

    def span(self, observed, raw, start, size):
        self.assertEqual(observed['raw_offset_bytes'], start)
        self.assertEqual(observed['raw_size_bytes'], size)
        self.assertEqual(observed['raw_sha256'], hashlib.sha256(raw[start:start + size]).hexdigest())

    def test_positive_existing_and_created_pairs_keep_exact_raw_spans(self):
        existing = pair()
        created = pair(fixture['created_release'](True))
        lead = b'captured unrelated stderr\n'
        between = b'captured independent line\n'
        raw = lead + existing + between + created
        result = self.observed(raw)
        self.assertIsNone(result['parse_error'])
        self.assertEqual(len(result['observations']), 2)
        self.span(result['observations'][0], raw, len(lead), len(existing))
        self.span(result['observations'][1], raw,
                  len(lead) + len(existing) + len(between), len(created))

    def test_orphan_retains_prior_complete_pair_and_reports_eof_offset(self):
        original = pair()
        raw = original + fixture['wire'](fixture['row']())
        result = self.observed(raw)
        self.assertEqual(len(result['observations']), 1)
        self.span(result['observations'][0], raw, 0, len(original))
        self.assertEqual(result['parse_error']['reason'], 'diagnostic_orphan')
        self.assertEqual(result['parse_error']['raw_offset_bytes'], len(raw))

    def test_malformed_later_diagnostic_retains_first_pair(self):
        original = pair()
        for tail, reason in ((policy.PREFIX + b'{broken\n', 'invalid_json'),
                             (policy.PREFIX + b'{}\n', 'row_shape')):
            with self.subTest(reason=reason):
                raw = original + tail
                result = self.observed(raw)
                self.assertEqual(len(result['observations']), 1)
                self.span(result['observations'][0], raw, 0, len(original))
                self.assertEqual(result['parse_error']['reason'], reason)
                self.assertEqual(result['parse_error']['raw_offset_bytes'], len(original))

    def test_unpaired_or_interleaved_output_never_becomes_a_pair(self):
        original = pair()
        diagnostic = fixture['wire'](fixture['row']())
        for tail, reason, offset in (
            (fixture['primary_wire'](fixture['bitmap']()), 'diagnostic_missing', len(original)),
            (diagnostic + b'interleaved stderr\n', 'diagnostic_not_adjacent', len(original + diagnostic)),
            (b'warning PEAR_FEX_BITMAP {}\n', 'bitmap_unrecognized', len(original)),
        ):
            with self.subTest(reason=reason):
                result = self.observed(original + tail)
                self.assertEqual(len(result['observations']), 1)
                self.assertEqual(result['parse_error']['reason'], reason)
                self.assertEqual(result['parse_error']['raw_offset_bytes'], offset)

    def test_original_failed_primary_survives_later_parser_refusal(self):
        diagnostic = fixture['row']()
        diagnostic.update(native_error_domain=3, native_error_code=7)
        primary = fixture['bitmap'](restored=False, domain=3, code=7)
        original = pair(diagnostic, primary)
        result = self.observed(original + policy.PREFIX + b'{}\n')
        self.assertEqual(len(result['observations']), 1)
        self.assertEqual(result['observations'][0]['bitmap'], primary)
        self.assertEqual(result['observations'][0]['diagnostic']['native_error_code'], 7)
        self.assertFalse(result['observations'][0]['bitmap']['restoration_observed'])
        self.assertEqual(result['parse_error']['reason'], 'row_shape')

    def test_zero_observations_never_infer_an_invocation_or_native_error(self):
        for raw in (b'', b'original process failure without bitmap rows\n'):
            with self.subTest(raw=raw):
                result = self.observed(raw)
                self.assertEqual(result['observations'], [])
                self.assertIsNone(result['parse_error'])
        for raw in (None, b'x' * (policy.MAX_STREAM + 1)):
            with self.subTest(kind=type(raw).__name__):
                result = self.observed(raw)
                self.assertEqual(result['observations'], [])
                self.assertEqual(result['parse_error']['reason'], 'stream_bound')
                self.assertEqual(result['parse_error']['raw_offset_bytes'], 0)

    def test_even_full_observed_prefix_never_substitutes_for_completed_count(self):
        original = pair()
        result = self.observed(original * 38)
        self.assertEqual(len(result['observations']), 38)
        self.assertIsNone(result['parse_error'])
        self.assertFalse(result['completed_count_qualified'])
        complete, other = policy.parse_stream(original * 38, 38)
        self.assertEqual(len(complete), 38)
        self.assertEqual(other, b'')
        with self.assertRaisesRegex(policy.Refused, 'diagnostic_count'):
            policy.parse_stream(original, 38)

    def test_capacity_refusal_keeps_first_128_exact_pairs_without_count_wrap(self):
        original = pair()
        raw = original * 129
        result = self.observed(raw)
        self.assertEqual(len(result['observations']), 128)
        self.span(result['observations'][-1], raw, 127 * len(original), len(original))
        self.assertEqual(result['parse_error']['reason'], 'diagnostic_count')
        self.assertEqual(result['parse_error']['raw_offset_bytes'],
                         128 * len(original) + len(fixture['wire'](fixture['row']())))


if __name__ == '__main__':
    unittest.main()
