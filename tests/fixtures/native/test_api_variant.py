# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
import copy
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from pear_runtime.errors import Error
from pear_runtime.fixtures.inputs import fact,save
from pear_runtime.fixtures.native import api_variant


class VariantAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.wine=self.root/'wine';(self.wine/'pear/tests/fixtures').mkdir(parents=True)
        self.source=self.wine/'pear/tests/fixtures/api_pe.c';self.source.write_bytes(b'original C')
        self.generator=self.wine/'pear/native_api_variant.py'
        self.generator.write_text("ORIGINAL_SHA256='pinned'\nORIGINAL_SIZE=10\nVARIANT='arm64ec-class181-arm64-i386-v1'\nOLD=b'a'\nNEW=b'b'\ndef generate(raw):return raw+b' variant'\ndef expected_architecture():return {'exact':'query'}\ndef provenance(raw):return {'generated':generate(raw).decode()}\ndef tool_input_rows(manifest):return []\nraise RuntimeError('top-level execution forbidden')\n")
        self.built_root=self.root/'build';self.built_root.mkdir()
        self.policy={'schema_version':1,'scope':'selected_wine_api_fixture_variant','variant':api_variant.VARIANT,
            'original':self.relative(self.source),'generator':self.relative(self.generator),
            'generated_sha256':hashlib.sha256(b'original C variant').hexdigest(),'expected_architecture':{'exact':'query'}}
        self.recipe={};self.bindings={};self.original={};self.operation={'scope':'task56_component_build','operation_id':'one','released':True}
        self.inputs={'wine_source_ref':{'path':str(self.wine/'pear/source-manifest.json')},'source_refs':{'api_pe.c':fact(self.source)}}
        self.built={'scope':'development_component_build','status':'passed','variant':api_variant.VARIANT,
            'runtime_eligible':False,'game_qualified':False,'source_ref':fact(self.source),'generator_ref':fact(self.generator),
            'operation_id':'one'}
    def relative(self,path):return {**fact(path),'path':str(path.relative_to(self.wine))}
    def write(self,path,value):save(path,value);return fact(path)
    def request(self, mutate=None):
        value={'schema_version':1,'scope':'development_native_api_variant','policy_ref':self.write(self.wine/'pear/native-api-variant.json',self.policy),
            'recipe_ref':self.write(self.root/'recipe.json',self.recipe),'bindings_ref':self.write(self.root/'bindings.json',self.bindings),
            'operation_ref':self.write(self.built_root/'operation.json',self.operation),'fixture_ref':{}}
        self.inputs['build_ref']=self.write(self.root/'original.json',self.original)
        built={**self.built,'recipe_sha256':value['recipe_ref']['sha256'],'recipe_ref':value['recipe_ref'],
            'bindings_ref':value['bindings_ref'],'original_build_ref':self.inputs['build_ref']}
        if mutate:mutate(built,value)
        value['build_ref']=self.write(self.built_root/'build.json',built)
        return self.write(self.root/'binding.json',value)
    def verify(self,ref):return api_variant.verify(ref,self.inputs,self.root,{},self.root)
    def test_capture_executes_selected_functions_only(self):
        owner=api_variant._generator(self.generator,fact(self.generator))
        self.assertEqual(owner['generate'](b'C'),b'C variant')
        self.assertEqual(owner['generate'].__code__.co_filename,str(self.generator))
    def test_changed_generator_refused_before_any_execution(self):
        row=fact(self.generator);self.generator.write_bytes(self.generator.read_bytes()+b'changed')
        with self.assertRaisesRegex(Error,'native_api_generator_changed'):api_variant._generator(self.generator,row)
    def test_matching_independent_recipe_reaches_input_admission(self):
        ref=self.request()
        with patch.object(api_variant,'_recipe_inputs',side_effect=Error('input-admission-reached')) as admit:
            with self.assertRaisesRegex(Error,'input-admission-reached'):self.verify(ref)
            admit.assert_called_once()
    def test_receipt_cannot_supply_its_own_expected_recipe_hash(self):
        ref=self.request(lambda built,value:built.update(recipe_sha256='0'*64))
        with self.assertRaisesRegex(Error,'native_api_variant_build_join'):self.verify(ref)
    def test_receipt_bindings_differ_from_explicit_input_refused(self):
        ref=self.request(lambda built,value:built.update(bindings_ref=value['recipe_ref']))
        with self.assertRaisesRegex(Error,'native_api_variant_build_join'):self.verify(ref)
    def test_unreleased_or_wrong_operation_refused(self):
        for key,value in [('released',False),('released',1),('operation_id','other'),('scope','assembly')]:
            with self.subTest(key=key,value=value):
                self.operation={'scope':'task56_component_build','operation_id':'one','released':True};self.operation[key]=value
                with self.assertRaisesRegex(Error,'native_api_variant_operation'):self.verify(self.request())
    def test_old_native_only_expected_row_refused(self):
        self.policy['expected_architecture']={'old':'native-only'}
        with self.assertRaisesRegex(Error,'native_api_variant_contract'):self.verify(self.request())
    def test_source_change_refused(self):
        ref=self.request();self.source.write_bytes(b'changed C')
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):self.verify(ref)


class RecipeInputTests(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()
        self.roots={name:str(self.root/name) for name in ('wine','runtime','tools','baseline','configuration','host')}
        for path in self.roots.values():Path(path).mkdir()
        self.file=Path(self.roots['tools'])/'header.h';self.file.write_bytes(b'header')
        self.row={'root':'tools','path':'header.h',**{k:v for k,v in fact(self.file).items() if k!='path'}}
    def verify(self,rows):
        root_specs={name:{'kind':'files'} for name in self.roots}
        recipe={'roots':root_specs,'inputs':rows};built={'roots':{name:{'path':path,**root_specs[name]} for name,path in self.roots.items()},'inputs':copy.deepcopy(rows)}
        return api_variant._recipe_inputs(recipe,{'roots':self.roots},built)
    def test_exact_input_and_alias_target(self):
        link=Path(self.roots['tools'])/'alias.h';link.symlink_to('header.h')
        roots,expected,refs=self.verify([self.row,{'root':'tools','path':'alias.h','kind':'symlink','target':'header.h'}])
        self.assertEqual(refs,[fact(self.file)]);self.assertEqual(len(expected),2)
    def test_duplicate_or_changed_input_refused(self):
        with self.assertRaisesRegex(Error,'native_api_recipe_input'):self.verify([self.row,self.row])
        self.file.write_bytes(b'changed')
        with self.assertRaisesRegex(Error,'native_api_build_input_changed'):self.verify([self.row])
    def test_alias_escape_refused(self):
        link=Path(self.roots['tools'])/'alias.h';link.symlink_to('../wine')
        with self.assertRaisesRegex(Error,'native_api_input_escape'):
            self.verify([{'root':'tools','path':'alias.h','kind':'symlink','target':'../wine'}])

if __name__=='__main__':unittest.main()
