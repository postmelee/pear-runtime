# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit canonical provider admission; invoke with FEX on PYTHONPATH."""
from pathlib import Path
import importlib.util
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from pear_runtime.fixtures.controls import corpus


class CPUProviderTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(importlib.util.find_spec('Pear.Tools.CPU.adapt').origin).parents[3]
        self.pin=corpus._provider_pin()

    def bind(self):return corpus.bind_provider(self.root,self.pin['commit'])

    def test_explicit_provider_matches_both_canonical_snapshots(self):
        provider=self.bind();self.assertEqual(provider.root,self.root);self.assertIs(provider.recheck(),provider)

    def test_wrong_commit_refuses_before_import(self):
        with patch.object(corpus.importlib.util,'find_spec') as load:
            with self.assertRaisesRegex(ValueError,'cpu_provider_commit'):
                corpus.bind_provider(self.root,'0'*40)
            load.assert_not_called()

    def test_relative_or_alias_root_is_refused(self):
        for root in (Path('.'),self.root/'..'/self.root.name):
            with self.subTest(root=root),self.assertRaisesRegex(ValueError,'cpu_provider_root_alias'):
                corpus.bind_provider(root,self.pin['commit'])

    def test_changed_source_refuses_before_loading_code(self):
        with patch.object(corpus,'read_relative',return_value=b'changed'),patch.object(corpus.importlib.util,'find_spec') as load:
            with self.assertRaisesRegex(ValueError,'cpu_provider_source_changed'):self.bind()
            load.assert_not_called()

    def test_foreign_import_location_has_no_path_fallback(self):
        with patch.object(corpus.importlib.util,'find_spec',return_value=SimpleNamespace(origin='/foreign/adapt.py')):
            with self.assertRaisesRegex(ValueError,'cpu_provider_import_root'):self.bind()

    def test_derived_snapshot_change_is_rejected(self):
        provider=self.bind()
        with patch.object(corpus,'_contract',return_value={}):
            with self.assertRaisesRegex(ValueError,'cpu_provider_snapshot_changed'):provider.recheck()

    def test_single_fex_function_receives_explicit_rules(self):
        provider=self.bind();case=next(x for x in corpus.manifest()['cases'] if x['id']=='absolute-displacement')
        with patch.object(provider.module,'rules',side_effect=AssertionError('ambient rules read')):
            actual=corpus.effective_case(case,provider=provider)
        self.assertEqual(actual['contract']['expectations'][:-1],case['contract']['expectations'])
        self.assertEqual(len(actual['contract']['expectations']),len(case['contract']['expectations'])+1)
