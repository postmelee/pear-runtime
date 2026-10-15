# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit final-operation admission and unchanged synthetic prefix controls."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import admission


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.candidate = self.root/'candidate'; self.candidate.mkdir()
        self.operation = self.root/'operation.json'
        self.operation_id = str(uuid.uuid4())
        self.value = {'passed': True, 'diagnostic_only': True, 'runtime_qualified': False,
            'execution_authorized_by_this_record': False, 'game_qualified': False,
            'development_assembly': {}, 'assembly_operation': {'path': str(self.operation), 'operation_id': self.operation_id}}
        build.write_json(self.candidate/'runtime.json', self.value)
        self.runtime_ref = build.fact(self.candidate/'runtime.json')
        self.record = {'schema_version': 1, 'scope': 'development_candidate_assembly_operation',
            'operation_id': self.operation_id, 'status': 'passed', 'runtime_ref': self.runtime_ref,
            'lock': {'released': True}, 'plan': {'output': str(self.candidate), 'operation_output': str(self.root)}}
        self.write_operation()

    def write_operation(self):
        build.write_json(self.operation, self.record)
        self.operation_ref = build.fact(self.operation)

    def invoke(self, operation_ref=None):
        return admission.current(self.runtime_ref, operation_ref if operation_ref is not None else self.operation_ref,
                                 {'private': 'unavailable synthetic profile'}, self.root/'helper', self.root/'authority')

    def test_exact_refs_forwarded_and_result_unchanged(self):
        refs = [object() for _ in range(5)]; result = object()
        with patch.object(admission.assembly, 'verify_current_authority', return_value=result) as verify:
            self.assertIs(admission.current(*refs), result)
        verify.assert_called_once_with(refs[0], refs[2], refs[3], refs[4], operation_ref=refs[1])

    def test_current_failure_object_is_preserved(self):
        failure = Error('integration_current_profile_changed')
        with patch.object(admission.assembly, 'verify_current_authority', side_effect=failure):
            with self.assertRaises(Error) as raised: self.invoke()
        self.assertIs(raised.exception, failure)

    def test_successful_join_reaches_fresh_authority_instead_of_saved_pass(self):
        with patch.object(admission.assembly, 'SourcePack', side_effect=RuntimeError('fresh authority required')):
            with self.assertRaisesRegex(RuntimeError, 'fresh authority required'): self.invoke()

    def test_missing_operation_reference_refused_before_host_calls(self):
        with patch.object(admission.assembly, 'SourcePack') as source:
            with self.assertRaisesRegex(Error, 'assembly_operation_reference_required'):
                admission.current(self.runtime_ref, None, {}, self.root/'helper', self.root/'authority')
            source.assert_not_called()

    def test_failed_running_unreleased_or_mismatched_operation_refused(self):
        variants = [('status', 'failed'), ('status', 'running'), ('lock', {'released': False}),
                    ('runtime_ref', {**self.runtime_ref, 'sha256': '0'*64}), ('operation_id', str(uuid.uuid4()))]
        for key, value in variants:
            with self.subTest(key=key, value=value):
                old = self.record[key]; self.record[key] = value; self.write_operation()
                with patch.object(admission.assembly, 'SourcePack') as source:
                    with self.assertRaises(Error): self.invoke()
                    source.assert_not_called()
                self.record[key] = old

    def test_changed_operation_cannot_be_rehashed_into_reviewed_ref(self):
        reviewed = self.operation_ref
        self.record['extra'] = 'after review'; self.write_operation()
        with self.assertRaisesRegex(Error, 'assembly_reference_changed'): self.invoke(reviewed)

    def test_old_runtime_pass_flag_is_not_current_authority(self):
        self.value.pop('development_assembly'); build.write_json(self.candidate/'runtime.json', self.value)
        self.runtime_ref = build.fact(self.candidate/'runtime.json')
        with self.assertRaisesRegex(Error, 'assembly_current_scope'): self.invoke()

    def test_prefix_inventory_preserves_exact_bytes_modes_and_two_wine_links(self):
        root = self.root/'prefix'; root.mkdir(); (root/'drive_c').mkdir(); (root/'dosdevices').mkdir()
        (root/'drive_c/test').write_bytes(b'synthetic\0bytes'); (root/'drive_c/test').chmod(0o600)
        (root/'dosdevices/c:').symlink_to('../drive_c'); (root/'dosdevices/z:').symlink_to('/')
        rows = {r['path']: r for r in admission.prefix_inventory(root)}
        self.assertEqual(rows['drive_c/test']['sha256'], hashlib.sha256(b'synthetic\0bytes').hexdigest())
        self.assertEqual(rows['drive_c/test']['mode'], 0o600)
        self.assertEqual(rows['dosdevices/z:'], {'path':'dosdevices/z:', 'kind':'link', 'target':'/'})
        (root/'dosdevices/c:').unlink(); (root/'dosdevices/c:').symlink_to('/')
        with self.assertRaisesRegex(Error, 'integration_prefix_link'): admission.prefix_inventory(root)

    def test_prefix_special_file_refused_without_opening_it(self):
        root = self.root/'prefix'; root.mkdir(); os.mkfifo(root/'fifo')
        with self.assertRaisesRegex(Error, 'integration_prefix_special_file'): admission.prefix_inventory(root)


if __name__ == '__main__': unittest.main()
