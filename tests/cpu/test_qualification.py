# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Reject mixed component/configuration and undeclared fixture-bundle changes."""
import copy
import unittest
from tests.cpu.cpu_legacy.qualification import CONFIGURATION,same_configuration,normalized_inventory

class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.value={key:{'bound':'same'} for key in CONFIGURATION}
        self.value.update(passed=True,kind='cpu_corpus_development_runtime',
            cpu_correction=dict(scope='arm64ec_fex_only',dll_sha256='a'),
            fixtures={'case':{'path':'PearWineLoader.app/Contents/Resources/runtime/libexec/pear-cpu/case.exe'}},
            native_images=[{'path':'PearWineLoader.app/Contents/MacOS/wine'}],
            bundle_inventory=[dict(path=p,kind='file',mode=493,sha256='old',size_bytes=4) for p in
                ['Contents/MacOS/wine','Contents/_CodeSignature/CodeResources','Contents/Resources/runtime/lib/wine/aarch64-windows/xtajit64.dll','Contents/Resources/runtime/libexec/pear-cpu/case.exe']])
    def test_same_component_contract_is_admitted(self):same_configuration(self.value,copy.deepcopy(self.value))
    def test_different_translator_or_memory_policy_is_rejected(self):
        for key in ('cpu_correction','memory_profile','input_receipts'):
            changed=copy.deepcopy(self.value);changed[key]={'different':'component'}
            with self.assertRaisesRegex(ValueError,'candidate_configuration'):same_configuration(self.value,changed)
    def test_signature_bytes_only_can_differ_after_code_origin_check(self):
        changed=copy.deepcopy(self.value)
        for row in changed['bundle_inventory'][:2]:row.update(sha256='new',size_bytes=8)
        self.assertEqual(normalized_inventory(self.value),normalized_inventory(changed))
    def test_modified_pe_runtime_component_is_not_hidden(self):
        changed=copy.deepcopy(self.value);changed['bundle_inventory'][2]['sha256']='different engine'
        self.assertNotEqual(normalized_inventory(self.value),normalized_inventory(changed))
    def test_undeclared_extra_fixture_is_not_ignored(self):
        changed=copy.deepcopy(self.value)
        changed['bundle_inventory'].append(dict(path='Contents/Resources/runtime/libexec/pear-cpu/undeclared.exe',kind='file',sha256='extra',size_bytes=4,mode=493))
        self.assertNotEqual(normalized_inventory(self.value),normalized_inventory(changed))
    def test_fixture_cannot_hide_a_runtime_library(self):
        changed=copy.deepcopy(self.value);changed['fixtures']['case']['path']='PearWineLoader.app/Contents/Resources/runtime/lib/wine/xtajit64.dll'
        with self.assertRaisesRegex(ValueError,'fixture_path_scope'):normalized_inventory(changed)

if __name__=='__main__':unittest.main()
