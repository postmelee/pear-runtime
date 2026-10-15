# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
from pathlib import Path
from tempfile import TemporaryDirectory
import copy
import os
import unittest
from unittest.mock import patch

from pear_runtime.errors import Error
from pear_runtime.assembly.helpers import PAYLOAD
from pear_runtime.fixtures.inputs import fact,save
from pear_runtime.fixtures.native.context import NativeContext
from pear_runtime.fixtures import supervision


class SeedAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.seed=self.root/'seed';self.prefix=self.seed/'run/prefix';self.system=self.prefix/'drive_c/windows/system32';self.system.mkdir(parents=True)
        self.runtime=self.root/'runtime';selected=self.runtime/PAYLOAD/'lib/wine/aarch64-windows';selected.mkdir(parents=True)
        inf=self.runtime/PAYLOAD/'share/wine/wine.inf';inf.parent.mkdir(parents=True);inf.write_bytes(b'inf');os.utime(inf,(123,123))
        (self.prefix/'.update-timestamp').write_text('123\n')
        modules={}
        for name in ('ntdll.dll','xtajit64.dll'):
            (self.system/name).write_bytes(b'old'+name.encode());(selected/name).write_bytes(b'new'+name.encode())
            modules[name]={'seed_sha256':fact(self.system/name)['sha256'],'selected_ref':fact(selected/name)}
        self.origin={'scope':'translated_graphics','fixture_id':'device','outcome':'exited','error':None,
                     'cleanup':{'complete':True},'sentinel_survived':True,'cleanup_errors':[],'passed':False}
        save(self.seed/'case.json',self.origin)
        self.base={'runtime_ref':{'runtime':1},'operation_ref':{'op':1},'profile_ref':{'profile':1},'provider_root':'explicit',
                   'seed_root':str(self.seed),'seed_ref':fact(self.seed/'case.json'),
                   'seed_inventory':supervision.prefix_inventory(self.prefix),'modules':modules}
        self.value={'tool_refs':{}};self.context=object.__new__(NativeContext)
        self.context.value={key:self.base[key] for key in ('runtime_ref','operation_ref','profile_ref','provider_root')}
        self.context.value['seed_context_ref']={}
    def admit(self):
        with patch('pear_runtime.fixtures.native.context.seed_descriptor',return_value=(self.value,self.base)):
            self.context._admit_seed(self.runtime)
    def test_exact_immutable_synthetic_seed_admitted_without_qualification_claim(self):
        self.admit();self.assertEqual(self.context.seed,self.seed)
        self.assertEqual(self.context.seed_adapter.base,self.base)
        self.assertFalse(self.origin['passed'])
    def test_other_candidate_operation_refused(self):
        self.base['operation_ref']={'other':1}
        with self.assertRaisesRegex(Error,'native_seed_candidate_join'):self.admit()
    def test_mutated_seed_refused(self):
        (self.system/'ntdll.dll').write_bytes(b'changed')
        with self.assertRaisesRegex(Error,'native_seed_changed'):self.admit()
    def test_module_wrong_current_artifact_refused(self):
        self.base['modules']['ntdll.dll']['selected_ref']['sha256']='0'*64
        with self.assertRaisesRegex(Error,'native_seed_module'):self.admit()
    def test_old_update_timestamp_refused(self):
        (self.prefix/'.update-timestamp').write_text('122\n')
        self.base['seed_inventory']=supervision.prefix_inventory(self.prefix)
        with self.assertRaisesRegex(Error,'native_seed_update_timestamp'):self.admit()
    def test_seed_origin_failure_or_missing_cleanup_refused(self):
        for key,value in [('outcome','timeout'),('error','error'),('sentinel_survived',False),('cleanup_errors',['error'])]:
            with self.subTest(key=key):
                origin=copy.deepcopy(self.origin);origin[key]=value;save(self.seed/'case.json',origin)
                self.base['seed_ref']=fact(self.seed/'case.json')
                with self.assertRaisesRegex(Error,'native_seed_origin'):self.admit()
    def test_unrelated_origin_path_refused(self):
        save(self.root/'unrelated.json',self.origin);self.base['seed_ref']=fact(self.root/'unrelated.json')
        with self.assertRaisesRegex(Error,'native_seed_origin_path'):self.admit()

if __name__=='__main__':unittest.main()
