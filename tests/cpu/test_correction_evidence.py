# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Reject successful no-op patch commands and mixed correction artifacts."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from tests.cpu.cpu_legacy import correction as fex_build
from pear_runtime.fixtures.controls.corpus import digest
from pear_runtime.assembly._common import encoded


class CorrectionEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.repo=Path(temp.name);self.root=self.repo/'build';self.root.mkdir()
        self.addCleanup(patch.stopall);patch.object(fex_build,'REPO',self.repo).start()
        target=self.repo/fex_build.PATCH;target.parent.mkdir(parents=True);target.write_bytes(b'patch')
        self.series=target.parent/'series.json'
        self.series.write_bytes(encoded(dict(patch=target.name,files=[dict(path='case.h',before=digest(b'old'),after=digest(b'new'))])))
        (self.root/'source').mkdir();(self.root/'wire').mkdir();(self.root/'source/case.h').write_bytes(b'new')
        (self.root/'producer.py').write_bytes(b'producer');(self.root/'deployment.dll').write_bytes(b'corrected DLL')
        (self.root/'command.log').write_bytes(b'success')
        self.record=dict(kind='cpu_fex_correction_build',passed=True,baseline_receipts={'fex':'baseline'},patch_path=str(fex_build.PATCH),
            patch_sha256=digest(b'patch'),patch_series_sha256=digest(self.series.read_bytes()),producer_sha256=digest(b'producer'),
            dll_sha256=digest(b'corrected DLL'),commands=[dict(id=x,exit_code=0,log='command.log',log_sha256=digest(b'success')) for x in
                ['clone-source','clone-wire','patch-check','patch','arm64ec.configure','arm64ec.build','strip']])
        self.snapshot()

    def snapshot(self):
        raw=encoded(dict(source=fex_build.inventory(self.root/'source'),wire=[]))
        (self.root/'inputs.json').write_bytes(raw);self.record['inputs_sha256']=digest(raw)
        (self.root/'build.json').write_bytes(encoded(self.record))

    def admit(self):
        return fex_build.admit_correction(self.root,{'fex':'baseline'})

    def test_complete_exact_correction_is_admitted(self):
        self.assertEqual(self.admit()['dll_sha256'],digest(b'corrected DLL'))

    def test_successful_noop_patch_is_rejected_even_with_consistent_inventory(self):
        (self.root/'source/case.h').write_bytes(b'old');self.snapshot()
        with self.assertRaisesRegex(Exception,'correction_patch_not_applied'):self.admit()

    def test_failed_command_or_missing_strip_cannot_pass(self):
        self.record['commands'][5]['exit_code']=1;self.snapshot()
        with self.assertRaisesRegex(Exception,'correction_command'):self.admit()
        self.record['commands'][5]['exit_code']=0;self.record['commands'].pop();self.snapshot()
        with self.assertRaisesRegex(Exception,'correction_recipe'):self.admit()

    def test_different_binary_cannot_reuse_correction_receipt(self):
        (self.root/'deployment.dll').write_bytes(b'original DLL')
        with self.assertRaisesRegex(Exception,'correction_binary_changed'):self.admit()


if __name__=='__main__':unittest.main()
