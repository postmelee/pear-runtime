# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pear_runtime.errors import Error
from pear_runtime.fixtures.native import provider
from pear_runtime.fixtures.inputs import digest
from pear_runtime.fixtures.supervision import prefix_inventory

REGISTRY=(b'WINE REGISTRY Version 2\n\n'
          b'[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices] 1\n'
          b'"winemenubuilder"="C:\\\\windows\\\\system32\\\\winemenubuilder.exe -a -r"\n'
          b'"other-service"="unchanged"\n\n[Other] 2\n"winemenubuilder-other"="kept"\n')


class MenuPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.original=self.root/'seed/run/prefix';self.clone=self.root/'clone';self.original.mkdir(parents=True);self.clone.mkdir()
        for root in (self.original,self.clone):
            (root/'system.reg').write_bytes(REGISTRY);(root/'untouched.txt').write_bytes(b'keep')
        self.seed=SimpleNamespace(seed=self.root/'seed',base={'seed_inventory':prefix_inventory(self.original)})
    def test_exact_one_entry_change_only_on_clone(self):
        before=prefix_inventory(self.original)
        record=provider.configure_menu(self.seed,self.clone)
        expected=REGISTRY.replace(b'"winemenubuilder"="C:\\\\windows\\\\system32\\\\winemenubuilder.exe -a -r"\n',b'')
        self.assertEqual((self.clone/'system.reg').read_bytes(),expected)
        self.assertEqual(prefix_inventory(self.original),before)
        self.assertEqual((self.clone/'untouched.txt').read_bytes(),b'keep')
        self.assertEqual(record,{'scope':'synthetic_native_four_prefix_only',
            'operation':'disable_optional_XDG_desktop_menu_autorun','registry_path':'system.reg',
            'removed_entries':1,'before_sha256':digest(REGISTRY),'after_sha256':digest(expected),
            'original_seed_unchanged':True})
    def test_original_seed_cannot_be_mutation_target(self):
        with self.assertRaisesRegex(Error,'native_menu_clone_scope'):provider.configure_menu(self.seed,self.original)
        self.assertEqual((self.original/'system.reg').read_bytes(),REGISTRY)
    def test_changed_clone_preimage_refused(self):
        (self.clone/'system.reg').write_bytes(REGISTRY+b'changed')
        with self.assertRaisesRegex(Error,'native_menu_registry_preimage'):provider.configure_menu(self.seed,self.clone)
    def test_wrong_section_value_missing_duplicate_refused(self):
        variants=[REGISTRY.replace(b'RunServices',b'Run'),REGISTRY.replace(b' -a -r',b' -x'),
                  REGISTRY.replace(b'"winemenubuilder"=',b'"different"='),REGISTRY+REGISTRY]
        for raw in variants:
            with self.subTest(raw=raw):
                with self.assertRaises(Exception):provider.menu_configuration(raw)
    def test_no_unrelated_clone_mutation_accepted(self):
        original=provider.menu_configuration
        def mutate(raw):
            (self.clone/'untouched.txt').write_bytes(b'changed');return original(raw)
        with patch.object(provider,'menu_configuration',side_effect=mutate):
            with self.assertRaisesRegex(Error,'native_menu_copy_scope'):provider.configure_menu(self.seed,self.clone)
    def test_original_seed_change_is_detected(self):
        original=provider.menu_configuration
        def mutate(raw):
            (self.original/'untouched.txt').write_bytes(b'changed');return original(raw)
        with patch.object(provider,'menu_configuration',side_effect=mutate):
            with self.assertRaisesRegex(Error,'native_menu_seed_changed'):provider.configure_menu(self.seed,self.clone)

if __name__=='__main__':unittest.main()
