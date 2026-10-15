# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Required-header identities and real depfile tokens; no native execution."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
import json
from unittest.mock import patch
from pear_runtime import build, header_use
from pear_runtime.build import fact as read_fact
from pear_runtime.errors import Error as Rejected
from pear_runtime.header_use import derive_fex_headers, require_fex_header_use
from pear_runtime.recipes import fex
from tests.fixtures.header_fixture import SelectedFixture
REPO=Path(__file__).resolve().parents[2]


class HeaderUseTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='headers-')
        self.addCleanup(temp.cleanup);self.base=Path(temp.name).resolve()
        self.fixture=SelectedFixture(self.base,json.loads((REPO/'pear_runtime/fixtures/capabilities/d36.json').read_text()))
        self.roots=self.fixture.roots;self.output=self.fixture.output
        self.wire,self.abort,self.phase=self.fixture.wire,self.fixture.abort,self.fixture.phase
        self.recipe,self.bindings,self.private=self.fixture.recipe,self.fixture.bindings,self.fixture.private
        self.contract=self.derive()
        self.parse_dependencies=build.parse_depfile

    def write(self,path,data):
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);return path

    def derive(self):
        return derive_fex_headers(self.recipe,self.bindings,self.private,output_root=self.output)

    def deps(self,unit):
        return [deepcopy(self.contract['sources'][unit]),*(deepcopy(self.contract['roles'][r]) for r in self.fixture.policy[unit])]

    def slots(self):
        return [(unit,role) for unit,roles in self.fixture.policy.items() for role in roles]

    def check(self,unit,deps,paths=None):
        paths=[row['path'] for row in deps] if paths is None else paths
        dep=self.output/'observed.d'
        escaped=[p.replace('\\','\\\\').replace(' ','\\ ') for p in paths]
        dep.write_text('owned.obj: '+' '.join(escaped)+'\n')
        return require_fex_header_use(self.contract,unit,deps,
            depfile_paths=self.parse_dependencies(dep),cwd=self.output)

    def test_positive_three_units_require_seven_exact_header_uses(self):
        self.assertEqual(len(self.slots()),7)
        for unit in self.contract['sources']:
            with self.subTest(unit=unit):
                got=self.check(unit,self.deps(unit))
                self.assertEqual(got['matched_roles'],list(self.fixture.policy[unit]))

    def test_each_required_header_omission_refused(self):
        for unit,role in self.slots():
            deps=self.deps(unit);deps.remove(self.contract['roles'][role])
            with self.subTest(unit=unit,role=role),self.assertRaises(Rejected):self.check(unit,deps)

    def test_each_required_header_wrong_hash_refused(self):
        for unit,role in self.slots():
            deps=self.deps(unit);next(r for r in deps if r==self.contract['roles'][role])['sha256']='0'*64
            with self.subTest(unit=unit,role=role),self.assertRaises(Rejected):self.check(unit,deps)

    def test_each_required_header_wrong_size_or_boolean_refused(self):
        for unit,role in self.slots():
            for value in (True,self.contract['roles'][role]['size_bytes']+1):
                deps=self.deps(unit);next(r for r in deps if r==self.contract['roles'][role])['size_bytes']=value
                with self.subTest(unit=unit,role=role,size=value),self.assertRaises(Rejected):self.check(unit,deps)

    def test_independently_readable_registered_shadow_cannot_replace_true_header(self):
        for unit,role in self.slots():
            expected=self.contract['roles'][role]
            for data in (b'different bytes',Path(expected['path']).read_bytes()):
                path=self.write(self.output/'generated'/unit/role/Path(expected['path']).name,data)
                admitted=read_fact(path)  # exact regular bytes, sufficient for an independently admitted output ref
                self.assertEqual(admitted,read_fact(path))
                deps=self.deps(unit);deps[deps.index(expected)]=admitted
                with self.subTest(unit=unit,role=role,same_bytes=data==Path(expected['path']).read_bytes()),self.assertRaises(Rejected):
                    self.check(unit,deps)

    def test_shadow_alongside_correct_header_and_duplicate_ref_refused(self):
        for unit,role in self.slots():
            expected=self.contract['roles'][role]
            shadow=read_fact(self.write(self.output/'other'/unit/role/Path(expected['path']).name,b'shadow'))
            for extra in (shadow,deepcopy(expected)):
                with self.subTest(unit=unit,role=role,extra=extra['path']),self.assertRaises(Rejected):
                    self.check(unit,[*self.deps(unit),extra])

    def test_private_phase_header_is_module_only(self):
        for unit in ('core','memory'):
            with self.subTest(unit=unit),self.assertRaisesRegex(Rejected,'header_unexpected_private_use'):
                self.check(unit,[*self.deps(unit),self.contract['roles']['phase']])

    def test_source_use_is_exact_and_required(self):
        for unit in self.contract['sources']:
            for mutation in ('omit','hash','duplicate'):
                deps=self.deps(unit)
                if mutation=='omit':deps.pop(0)
                elif mutation=='hash':deps[0]['sha256']='0'*64
                else:deps.append(deepcopy(deps[0]))
                with self.subTest(unit=unit,mutation=mutation),self.assertRaises(Rejected):self.check(unit,deps)

    def test_correct_recorded_header_rows_do_not_replace_missing_or_shadow_depfile_tokens(self):
        for unit,role in self.slots():
            deps=self.deps(unit);expected=self.contract['roles'][role]
            paths=[row['path'] for row in deps if row!=expected]
            shadow=self.write(self.output/'raw-shadow'/unit/role/Path(expected['path']).name,b'admitted shadow')
            for raw in (paths,[*paths,str(shadow)]):
                with self.subTest(unit=unit,role=role,raw=raw),self.assertRaisesRegex(Rejected,'header_required_token'):
                    self.check(unit,deps,raw)

    def test_owner_export_and_abort_public_identity_cannot_be_self_declared_by_dependencies(self):
        original=deepcopy(self.recipe)
        mutations=(lambda r:r['shared_headers'][0].update(sha256='0'*64),
                   lambda r:r['source_exports'][0].update(root='runtime'),
                   lambda r:r['source_exports'][0].update(output='generated/wine/pear_fex_memory.h'),
                   lambda r:r['inputs'][0].update(size_bytes=True),
                   lambda r:r['inputs'][0].update(sha256='0'*64))
        for i,mutate in enumerate(mutations):
            self.recipe=deepcopy(original);mutate(self.recipe)
            with self.subTest(i=i),self.assertRaises(Rejected):self.derive()

    def test_private_manifest_exact_root_hash_size_and_type_required(self):
        original=deepcopy(self.private)
        mutations=(lambda r:r.update(schema_version=True),lambda r:r.update(root=str(self.output)),
                   lambda r:r['files'][0].update(sha256='0'*64),lambda r:r['files'][0].update(size_bytes=True),
                   lambda r:r['files'][0].update(path='different.h'))
        for i,mutate in enumerate(mutations):
            self.private=deepcopy(original);mutate(self.private)
            with self.subTest(i=i),self.assertRaises(Rejected):self.derive()

    def test_export_and_owner_source_drift_are_refused(self):
        export=Path(self.contract['roles']['wire']['path'])
        for path in (export,self.wire,self.abort,self.phase):
            original=path.read_bytes();path.write_bytes(b'changed')
            with self.subTest(path=path.name),self.assertRaises(Rejected):self.derive()
            path.write_bytes(original)

    def test_owner_export_and_private_ancestor_aliases_refused(self):
        for path in (self.wire,self.abort,self.phase,self.fixture.export):
            parent=path.parent;relocated=parent.with_name(parent.name+'-real')
            parent.rename(relocated);parent.symlink_to(relocated,target_is_directory=True)
            try:
                with self.subTest(role=path.name),self.assertRaisesRegex(Rejected,'header_alias'):
                    self.derive()
            finally:
                parent.unlink();relocated.rename(parent)

    def test_private_root_inside_repository_and_public_private_identity_refused(self):
        marker=self.base/'.git';marker.write_text('gitdir: synthetic')
        with self.assertRaisesRegex(Rejected,'header_private_inside_repository'):self.derive()
        marker.unlink()
        self.recipe['inputs'].append(dict(root='private',**self.private['files'][0]))
        with self.assertRaisesRegex(Rejected,'header_public_private_identity'):self.derive()

    def test_source_only_group_and_forged_canonical_rows_without_tokens_refused(self):
        for unit in self.fixture.policy:
            with self.subTest(unit=unit),self.assertRaisesRegex(Rejected,'header_required_use'):
                self.check(unit,[self.contract['sources'][unit]])
            deps=self.deps(unit)
            with self.subTest(unit=unit),self.assertRaisesRegex(Rejected,'header_required_token'):
                self.check(unit,deps,[self.contract['sources'][unit]['path']])

    def test_context_admitted_same_name_shadow_is_not_the_wire_export(self):
        expected=Path(self.contract['roles']['wire']['path'])
        shadow=self.write(self.output/'generated/wine/pear_fex_memory.h',expected.read_bytes())
        inputs=[dict(root='retained',path=str(p.relative_to(self.output)),
                     sha256=read_fact(p)['sha256'],size_bytes=read_fact(p)['size_bytes']) for p in (expected,shadow)]
        recipe=dict(schema_version=1,name='finite-admission',roots={'retained':{'kind':'input'}},inputs=inputs,
                    budget=dict(additional_bytes=4096,floor_bytes=0))
        ctx=build.Context(recipe,{'retained':str(self.output)},self.base/'never-built',lock_path=self.base/'unused-lock')
        ctx.validate_inputs()
        canonical=ctx._admit_path(expected);admitted=ctx._admit_path(shadow)
        self.assertEqual(canonical,self.contract['roles']['wire'])
        for rows in ([admitted],[canonical,admitted]):
            deps=[r for r in self.deps('core') if r!=canonical]+rows
            with self.subTest(extra=len(rows)),self.assertRaisesRegex(Rejected,'header_required_use:wire'):
                self.check('core',deps)

    def test_depfile_identity_and_change_during_parser_are_required(self):
        dep=self.output/'bound.d';self.fixture.write_depfile(dep,[r['path'] for r in self.deps('module')])
        ref=read_fact(dep);parser=build.parse_depfile
        def drift(path):
            result=parser(path);path.write_text('changed.obj: missing.h\n');return result
        with patch.object(build,'parse_depfile',side_effect=drift):
            with self.assertRaisesRegex(Rejected,'header_depfile_changed'):header_use.depfile_paths(ref)
        with self.assertRaisesRegex(Rejected,'header_depfile_changed'):header_use.depfile_paths(ref)

    def test_builder_capture_contains_current_neutral_helper(self):
        rows=fex.builder_sources()
        expected=read_fact(Path(header_use.__file__).resolve())
        self.assertEqual([row for row in rows if row['path']==expected['path']],[expected])
        self.assertEqual(len({Path(row['path']).name for row in rows}),len(rows))
        self.assertEqual(header_use.expanded_recipe_sha256(self.recipe,self.bindings,self.private),
                         self.fixture.built['recipe_sha256'])
