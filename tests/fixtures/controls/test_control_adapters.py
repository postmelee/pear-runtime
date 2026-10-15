# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic full-comparison and explicit producer-boundary refusal controls."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from pear_runtime.errors import Error
from pear_runtime.fixtures.controls import corpus, presentation

if __package__:
    from . import test_corpus_results as original_corpus
    from . import test_present_frames as original_frames
else:
    import test_corpus_results as original_corpus
    import test_present_frames as original_frames


def wire(events):
    return b''.join(json.dumps(row, separators=(',', ':')).encode() + b'\n' for row in events)


class FullCorpusComparisons(unittest.TestCase):
    def setUp(self):
        original = original_corpus.HarnessTests()
        original.setUp()
        self.provider = original.provider
        self.build = corpus.canonical(original.build)
        self.reference = copy.deepcopy(original.run)
        self.candidate = copy.deepcopy(original.run['cases'])
        self.logs = {}
        for row in self.reference['cases']:
            for stream in ('stdout', 'stderr'):
                raw = wire(row['events']) if stream == 'stdout' else b''
                self.logs[(row['id'], stream)] = raw
                row[stream + '_sha256'] = corpus.digest(raw)

    def compare(self):
        return corpus.compare_result_rows(self.build, self.reference, self.logs, self.candidate, provider=self.provider)

    def test_complete19_preserves_separate_execution_admission(self):
        result = self.compare()
        self.assertEqual(len(result['cases']), 19)
        self.assertTrue(all(row['status'] == 'passed' for row in result['cases']))
        self.assertFalse(result['execution_admission_performed'])
        self.assertFalse(result['cpu_qualified'])

    def test_missing_duplicate_or_reordered_candidate_cannot_shorten_suite(self):
        for rows in (self.candidate[:-1], self.candidate + self.candidate[-1:],
                     self.candidate[1:] + self.candidate[:1]):
            with self.subTest(ids=[row['id'] for row in rows]), self.assertRaisesRegex(ValueError, 'candidate_case_set'):
                corpus.compare_result_rows(self.build, self.reference, self.logs, rows, provider=self.provider)

    def test_foreign_binary_and_nonexit_are_rejected(self):
        for key, value in (('binary_sha256', 'b' * 64), ('outcome', 'timeout')):
            rows = copy.deepcopy(self.candidate)
            rows[0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'case_binary_or_outcome'):
                corpus.compare_result_rows(self.build, self.reference, self.logs, rows, provider=self.provider)

    def test_wrong_result_cannot_be_hidden_by_complete_suite(self):
        self.candidate[0]['events'][1]['values'][0] = '0x0000000000000000'
        with self.assertRaisesRegex(ValueError, 'golden_mismatch'):
            self.compare()

    def test_avx_absence_remains_unsupported_not_a_pass(self):
        row = self.candidate[11]
        row['exit_code'] = 77
        row['events'][0].update(cpuid_ecx='0x0000000000000000', xcr0='0x0000000000000000', avx=False)
        row['events'][1] = dict(event='unavailable', reason='AVX_OSXSAVE_XCR0')
        result = self.compare()
        self.assertEqual(sum(r['status'] == 'passed' for r in result['cases']), 18)
        self.assertEqual(result['cases'][11]['status'], 'unsupported_not_exposed')

    def test_reference_log_bytes_and_events_are_both_checked(self):
        row = self.reference['cases'][0]
        self.logs[(row['id'], 'stdout')] = b'{}\n'
        with self.assertRaisesRegex(ValueError, 'reference_log_changed'):
            self.compare()
        row['stdout_sha256'] = corpus.digest(b'{}\n')
        with self.assertRaisesRegex(ValueError, 'reference_events_changed'):
            self.compare()

    def test_reference_must_remain_native_windows_x64(self):
        self.reference['host']['native_machine'] = 0xAA64
        with self.assertRaisesRegex(ValueError, 'reference_not_native_x64'):
            self.compare()

    def test_duplicate_json_results_are_not_accepted(self):
        with self.assertRaisesRegex(ValueError, 'duplicate_key'):
            corpus.decode(b'{"complete":false,"complete":true}')

    def test_original_generic_candidate_route_stays_unimplemented(self):
        record = copy.deepcopy(self.reference)
        record['scope'] = 'cpu_pear_results'
        with self.assertRaisesRegex(ValueError, 'candidate_admission_not_implemented'):
            corpus.assess_records(corpus.manifest(), self.build, record, 'pear', provider=self.provider)


class FullOrderingComparisons(unittest.TestCase):
    def setUp(self):
        self.build = corpus.canonical(dict(scope='cpu_ordering_build', passed=True, iterations=2048, rounds=4))
        self.events = [dict(event='ordering_round', round=i, iterations=2048, joined=2, tls_ok=True,
                            coordinator=10, workers=[11 + 2*i, 12 + 2*i],
                            counts=[[1024, 1024, 0, 0], [512, 512, 0, 1024],
                                    [768, 512, 512, 256], [0, 768, 768, 512]]) for i in range(4)]
        self.events.append(dict(event='ordering_complete', rounds=4, iterations=2048))
        self.logs = {'stdout': wire(self.events), 'stderr': b''}
        self.reference = dict(scope='ordering_native_reference', passed=True,
                              build_sha256=corpus.digest(self.build), exit_code=42,
                              host=dict(native_machine=0x8664, process_machine=0, pointer_bits=64,
                                        system='Windows', processor='synthetic-x64'),
                              assessment=corpus.assess(self.events, 2048, 4, 42))
        for key, raw in self.logs.items():
            self.reference[key + '_sha256'] = corpus.digest(raw)
        self.stderr = b''
        for tid in range(10, 19):
            self.stderr += (f'Pear CPU policy state={tid:x} scalar=true vector=true memcpy=true\n'
                            f'Pear CPU thread tid={tid} state={tid:x}\n').encode()
        self.retirement = b'Pear FEX init ThreadTerm.complete: status=00000000 domain=0 code=0\n'
        self.stderr += self.retirement * 8

    def compare(self, **kwargs):
        return corpus.compare_ordering_records(self.build, self.reference, self.logs,
                                               kwargs.get('events', self.events),
                                               kwargs.get('exit_code', 42), kwargs.get('stderr', self.stderr))

    def test_complete32768pairs8workers_and8retirements(self):
        result = self.compare()
        self.assertEqual(result['candidate']['measured_pairs'], 32768)
        self.assertEqual(len(result['candidate']['workers']), 8)
        self.assertEqual(result['candidate']['checked_worker_retirements'], 8)
        self.assertFalse(result['execution_admission_performed'])
        self.assertFalse(result['candidate']['universal_ordering_proof'])

    def test_reduced_budget_is_not_the_required_control(self):
        self.build = corpus.canonical(dict(scope='cpu_ordering_build', passed=True, iterations=8, rounds=1))
        with self.assertRaisesRegex(ValueError, 'ordering_budget'):
            self.compare()

    def test_failure_exit_and_missing_retirement_are_preserved(self):
        with self.assertRaisesRegex(ValueError, 'ordering_exit'):
            self.compare(exit_code=108)
        with self.assertRaisesRegex(ValueError, 'worker_source_retirement_incomplete'):
            self.compare(stderr=self.stderr.removesuffix(self.retirement))

    def test_actual_policy_and_forbidden_outcomes_remain_required(self):
        with self.assertRaisesRegex(ValueError, 'software_policy_disabled'):
            self.compare(stderr=self.stderr.replace(b'vector=true', b'vector=false', 1))
        rows = copy.deepcopy(self.events)
        rows[3]['counts'][1] = [511, 512, 1, 1024]
        with self.assertRaisesRegex(ValueError, 'message_passing_forbidden'):
            self.compare(events=rows)

    def test_reference_bytes_and_assessment_cannot_be_replaced(self):
        self.logs['stderr'] = b'changed'
        with self.assertRaisesRegex(ValueError, 'ordering_reference_log'):
            self.compare()
        self.logs['stderr'] = b''
        self.reference['assessment']['measured_pairs'] -= 1
        with self.assertRaisesRegex(ValueError, 'ordering_reference_assessment'):
            self.compare()


def presentation_terminal():
    lines = ['{"record_kind":"pear_bootstrap_helper"}',
             'PEAR_PRESENT_BEGIN version=1 cycles=3 frames=18']
    for i, name in enumerate(('d3d11.dll', 'dxgi.dll', 'winemetal.dll'), 1):
        lines.append(f'PEAR_GRAPHICS_MODULE name={name} base={4096*i:x} path=C:\\windows\\system32\\{name}')
    for cycle in range(1, 4):
        operations = ['device_swapchain', 'query', 'backbuffer', 'rtv', 'present', 'present']
        operations += ['resize', 'backbuffer', 'rtv', 'present', 'present'] * 2
        lines.extend(f'PEAR_PRESENT_HR cycle={cycle} operation={name} hr=00000000' for name in operations)
        for phase, (width, height) in enumerate(((64, 64), (96, 80), (64, 64))):
            lines.append(f'PEAR_PRESENT_READY cycle={cycle} phase={phase} width={width} height={height}')
            lines.append(f'PEAR_PRESENT_SIZE cycle={cycle} width={width} height={height} count={phase+1}')
            for frame in range(2):
                lines.append(f'PEAR_PRESENT_FRAME cycle={cycle} phase={phase} frame={frame} width={width} height={height} gpu=1')
        lines.append(f'PEAR_PRESENT_CYCLE cycle={cycle} resize_callbacks=3 destroy_callbacks=1')
    lines.append('PEAR_PRESENT_END cycles=3 frames=18 passed=1')
    return ('\n'.join(lines)+'\n').encode()


class PresentationBindings(unittest.TestCase):
    def test_complete_terminal_has18frames3cycles(self):
        result = presentation.terminal(presentation_terminal())
        self.assertEqual((result['frames'], result['cycles']), (18, 3))
        self.assertEqual(len(result['ready']), 9)

    def test_missing_frame_failed_operation_or_unknown_record_refuses(self):
        raw = presentation_terminal()
        missing = b'PEAR_PRESENT_FRAME cycle=3 phase=2 frame=1 width=64 height=64 gpu=1\n'
        for bad in (raw.replace(missing, b''), raw.replace(b'hr=00000000', b'hr=80004005', 1),
                    raw.replace(missing, b'UNEXPECTED RECORD\n')):
            with self.subTest(raw=bad[:100]), self.assertRaises(Error):
                presentation.terminal(bad)

    def test_wrong_resize_callback_cannot_pass(self):
        raw = presentation_terminal().replace(b'PEAR_PRESENT_SIZE cycle=2 width=96 height=80 count=2',
                                              b'PEAR_PRESENT_SIZE cycle=2 width=64 height=64 count=2')
        with self.assertRaisesRegex(Error, 'present_resize_callback'):
            presentation.terminal(raw)

    def test_explicit_capture_producer_must_match_record(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d).resolve()
            original = original_frames.VisibleFrames()
            _, _, windows = original.packet(root)
            with self.assertRaisesRegex(Error, 'present_frame_capture_producer'):
                presentation.visible_frames(root, windows, Path(__file__))


if __name__ == '__main__':
    unittest.main()
