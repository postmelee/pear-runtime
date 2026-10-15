# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Complete source closure and capture/refusal tests, with no host execution."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import producers

REPO=Path(__file__).resolve().parents[2]
PROVIDER=REPO/'pear_runtime/providers/pear_legacy'


class ProducerTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name).resolve()
        self.code=self.root/'code';self.code.mkdir();self.source=self.code/'source.py';self.source.write_bytes(b'# synthetic source\n')
        self.refs={('runtime','source.py'):build.fact(self.source)}
        self.raw={('runtime','source.py'):self.source.read_bytes()}
        self.value={'schema_version':1,'scope':'fixture_producer_sources','roots':{'runtime':str(self.code)},
                    'files':[dict(root='runtime',path='source.py',sha256=self.refs[('runtime','source.py')]['sha256'],size_bytes=self.source.stat().st_size)]}
        self.manifest=self.root/'manifest.json';self.freeze()
        self.required=patch.object(producers,'required_sources',return_value=({'runtime':self.code},self.refs,self.raw))
        self.required.start();self.addCleanup(self.required.stop)
        self.loaded=patch.object(producers,'_loaded_sources');self.loaded.start();self.addCleanup(self.loaded.stop)
        self.provider=patch.object(producers.supervision,'source_refs',return_value={});self.provider.start();self.addCleanup(self.provider.stop)

    def freeze(self):build.write_json(self.manifest,self.value);self.ref=build.fact(self.manifest)
    def capture(self):return producers.capture(self.ref,self.code/producers.PROVIDER_PREFIX)

    def test_exact_manifest_captures_bytes_and_preserves_original_assess_shape(self):
        captured=self.capture();output=self.root/'output';output.mkdir()
        rows=captured.preserve(output)
        self.assertEqual(len(rows),2)
        self.assertEqual(json.loads((output/'producers.json').read_text()),rows)
        for row in rows:
            self.assertEqual(set(row),{'original','snapshot'})
            self.assertEqual(build.fact(row['snapshot']['path']),row['snapshot'])
            self.assertEqual(row['snapshot']['sha256'],row['original']['sha256'])
        self.assertEqual((output/'producer-sources/runtime/source.py').read_bytes(),self.raw[('runtime','source.py')])
        self.assertEqual((output/'producer-sources/manifest.json').read_bytes(),self.manifest.read_bytes())

    def test_missing_or_extra_rows_refused(self):
        for files in ([],self.value['files']+[dict(root='runtime',path='unconsumed.py',sha256='a'*64,size_bytes=0)]):
            with self.subTest(files=len(files)):
                self.value['files']=files;self.freeze()
                with self.assertRaises(Error):self.capture()

    def test_duplicate_and_unsafe_paths_refused(self):
        row=self.value['files'][0].copy()
        for files in ([row,row],[dict(row,path='../source.py')],[dict(row,path='/source.py')]):
            with self.subTest(files=files):
                self.value['files']=files;self.freeze()
                with self.assertRaises(Error):self.capture()

    def test_mutated_digest_size_and_boolean_size_refused(self):
        original=self.value['files'][0].copy()
        for key,value in [('sha256','a'*64),('size_bytes',0),('size_bytes',True)]:
            self.value['files']=[dict(original,**{key:value})];self.freeze()
            with self.subTest(key=key,value=value),self.assertRaises(Error):self.capture()

    def test_stale_manifest_ref_refused(self):
        self.manifest.write_bytes(self.manifest.read_bytes()+b'\n')
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):self.capture()

    def test_wrong_provider_binding_refused(self):
        with self.assertRaisesRegex(Error,'fixture_producer_provider_binding'):
            producers.capture(self.ref,self.root/'old-helper-pack')

    def test_snapshot_existing_file_or_alias_not_overwritten(self):
        output=self.root/'output';output.mkdir();(output/'producer-sources').symlink_to(self.code,target_is_directory=True)
        with self.assertRaises(FileExistsError):self.capture().preserve(output)
        self.assertEqual(self.source.read_bytes(),self.raw[('runtime','source.py')])

    def test_output_inside_source_root_refused(self):
        output=self.code/'out';output.mkdir()
        with self.assertRaisesRegex(Error,'fixture_producer_output'):self.capture().preserve(output)

    def test_post_snapshot_source_drift_fails(self):
        captured=self.capture();output=self.root/'output';output.mkdir()
        original=producers.capture;calls=0
        def change_after_copy(*args, **kwargs):
            nonlocal calls
            calls+=1
            if calls==2:raise Error('fixture_producer_incomplete_or_changed')
            return original(*args, **kwargs)
        with patch.object(producers,'capture',side_effect=change_after_copy):
            with self.assertRaisesRegex(Error,'fixture_producer_incomplete_or_changed'):captured.preserve(output)
        self.assertTrue((output/'producers.json').is_file())

    def test_real_closure_has_relative_and_dynamic_imports_without_glob(self):
        self.required.stop();self.loaded.stop();self.provider.stop()
        with patch.object(Path,'rglob',side_effect=AssertionError('no tree glob')):
            value=producers.manifest_for_roots({'runtime':str(REPO)})
        paths={r['path'] for r in value['files']}
        for path in ('pear_runtime/fixtures/supervision.py','pear_runtime/fixtures/assessment/early_wait.py',
                     'pear_runtime/assembly/_transport.py','pear_runtime/providers/pear_legacy/tools/sources/validate_inventory.py',
                     'provenance/fixture-context-import.json'):
            self.assertIn(path,paths)
        self.assertEqual(set(value['roots']),{'runtime'})
        build.write_json(self.manifest,value)
        # Combined unit discovery may have imported unrelated control packages;
        # actual CLI verifies loaded modules in its fresh process.
        with patch.object(producers,'_loaded_sources'):
            captured=producers.capture(build.fact(self.manifest),PROVIDER)
        self.assertEqual(len(captured.refs),len(value['files']))

    def test_extended_scope_survives_recheck_and_cannot_use_default_admission(self):
        self.required.stop();self.loaded.stop();self.provider.stop()
        entries=producers.ENTRY_MODULES+('pear_runtime.fixtures.release',)
        dynamic=producers.DYNAMIC_PATHS+('provenance/fixture-release-import.json',)
        options=dict(entry_modules=entries,dynamic_paths=dynamic,scope='fixture_controls_producer_sources')
        value=producers.manifest_for_roots({'runtime':str(REPO)},**options)
        paths={row['path'] for row in value['files']}
        self.assertIn('pear_runtime/fixtures/release.py',paths)
        self.assertIn('provenance/fixture-release-import.json',paths)
        build.write_json(self.manifest,value);ref=build.fact(self.manifest)
        with self.assertRaisesRegex(Error,'fixture_producer_manifest'):
            producers.capture(ref,PROVIDER)
        with patch.object(producers,'_loaded_sources'):
            captured=producers.capture(ref,PROVIDER,**options)
            captured.recheck()
            self.assertEqual(captured.scope,options['scope'])
            # An explicit dynamic input disappearing cannot pass after capture.
            with patch.object(producers,'DYNAMIC_PATHS',()):captured.recheck()
            with patch.object(producers,'required_sources',return_value=({'runtime':REPO},{},{})):
                with self.assertRaisesRegex(Error,'fixture_producer_incomplete_or_changed'):captured.recheck()

    def test_duplicate_unsafe_or_unknown_closure_options_refused(self):
        bad=[dict(entry_modules=()),dict(entry_modules=('pear_runtime.fixtures.driver',)*2),
             dict(entry_modules=('os',)),dict(dynamic_paths=('../outside.py',)),
             dict(dynamic_paths=('same.py','same.py')),dict(scope='unreviewed')]
        for options in bad:
            with self.subTest(options=options),self.assertRaises((Error,ValueError)):
                producers.manifest_for_roots({'runtime':str(self.code)},**options)

    def test_fex_cpu_provider_is_an_explicit_owned_module(self):
        path=self.code/'Pear/Tools/CPU';path.mkdir(parents=True)
        (path/'adapt.py').write_text('VALUE=1\n')
        self.assertEqual(producers._module_location('Pear.Tools.CPU.adapt',{'fex':self.code}),
                         ('fex','Pear/Tools/CPU/adapt.py'))
        self.assertIsNone(producers._module_location('Pear.Tools',{'fex':self.code}))
        with self.assertRaisesRegex(Error,'fixture_producer_fex_root_required'):
            producers._module_location('Pear.Tools.CPU.adapt',{})
        with self.assertRaisesRegex(Error,'fixture_producer_module_missing'):
            producers._module_location('Pear.Tools.CPU.missing',{'fex':self.code})

    def test_real_root_alias_and_extra_unused_root_refused(self):
        self.required.stop();alias=self.root/'alias';alias.symlink_to(REPO,target_is_directory=True)
        with self.assertRaisesRegex(Error,'fixture_producer_root_alias'):
            producers.manifest_for_roots({'runtime':str(alias)})
        with self.assertRaisesRegex(Error,'fixture_producer_unused_root'):
            producers.manifest_for_roots({'runtime':str(REPO),'fex':str(self.code)})


if __name__=='__main__':unittest.main()
