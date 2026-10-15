# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Mandatory retained header proof and independent assembly-request authority."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pear_runtime import build, header_use
from pear_runtime.errors import Error
from pear_runtime.fixtures import context
from tests.fixtures.header_fixture import SelectedFixture

REPO = Path(__file__).resolve().parents[2]


class FixtureSetup:
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='header-binding-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        catalog = json.loads((REPO / 'pear_runtime/fixtures/capabilities/d36.json').read_text())
        self.fixture = SelectedFixture(self.base, catalog)
        self.built, self.catalog = self.fixture.built, self.fixture.catalog


class RetainedHeaderTests(FixtureSetup, unittest.TestCase):
    def test_missing_metadata_cannot_select_a_legacy_bypass(self):
        for name in ('public_recipe', 'bindings_manifest', 'private_manifest'):
            value = copy.deepcopy(self.built)
            value.pop(name)
            with self.subTest(name=name), self.assertRaisesRegex(Error, 'fixture_capability_metadata'):
                context.compiled_capabilities(value, self.catalog)

    def test_forged_recorded_canonical_headers_do_not_replace_actual_tokens(self):
        for group in self.built['dependencies']:
            dep = Path(group['depfile']['path'])
            original = dep.read_bytes()
            for replacement in ('omit', 'shadow'):
                paths = [row['path'] for row in group['files'] if Path(row['path']).name != 'pear_fex_memory.h']
                if replacement == 'shadow':
                    shadow = self.fixture.write(self.fixture.output / 'generated/wine/pear_fex_memory.h', b'shadow')
                    paths.append(str(shadow))
                self.fixture.write_depfile(dep, paths)
                group['depfile'] = build.fact(dep)
                with self.subTest(unit=dep.name, replacement=replacement), self.assertRaisesRegex(Error, 'header_required_token:wire'):
                    context.compiled_capabilities(self.built, self.catalog)
            dep.write_bytes(original)
            group['depfile'] = build.fact(dep)

    def test_recorded_and_actual_shadow_agreement_is_still_refused(self):
        group = self.built['dependencies'][0]
        index = next(i for i, row in enumerate(group['files']) if Path(row['path']).name == 'pear_fex_memory.h')
        shadow = self.fixture.write(self.fixture.output / 'shadow/wine/pear_fex_memory.h', self.fixture.wire.read_bytes())
        group['files'][index] = build.fact(shadow)
        dep = Path(group['depfile']['path'])
        self.fixture.write_depfile(dep, [row['path'] for row in group['files']])
        group['depfile'] = build.fact(dep)
        with self.assertRaisesRegex(Error, 'header_required_use:wire'):
            context.compiled_capabilities(self.built, self.catalog)

    def test_source_recipe_root_and_expansion_pins_are_required(self):
        for mutation, code in (
            (lambda b: b.update(recipe_sha256='0' * 64), 'fixture_capability_expanded_recipe'),
            (lambda b: b['roots']['fex'].update(commit='0' * 40), 'fixture_capability_root_binding'),
            (lambda b: b['roots']['runtime'].update(path=str(self.fixture.output)), 'fixture_capability_root_binding'),
        ):
            value = copy.deepcopy(self.built)
            mutation(value)
            with self.subTest(code=code), self.assertRaisesRegex(Error, code):
                context.compiled_capabilities(value, self.catalog)
        catalog = copy.deepcopy(self.catalog)
        catalog['public_recipe_sha256'] = '0' * 64
        with self.assertRaisesRegex(Error, 'fixture_capability_recipe_pin'):
            context.compiled_capabilities(self.built, catalog)

    def test_retained_private_boundary_is_required_even_with_matching_expansion(self):
        self.fixture.recipe['inputs'].append(dict(root='private', **self.fixture.private['files'][0]))
        self.fixture.refresh_metadata()
        with self.assertRaisesRegex(Error, 'header_public_private_identity'):
            context.compiled_capabilities(self.built, self.catalog)
        self.fixture.recipe['inputs'].pop()
        self.fixture.refresh_metadata()
        (self.base / '.git').write_text('synthetic repository marker')
        with self.assertRaisesRegex(Error, 'header_private_inside_repository'):
            context.compiled_capabilities(self.built, self.catalog)

    def test_compiler_cwd_id_and_recipe_depfile_output_are_bound(self):
        for field, value in (('cwd', str(self.base)), ('id', 'unreviewed-unit')):
            built = copy.deepcopy(self.built)
            built['commands'][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(Error, 'fixture_capability_compile_binding'):
                context.compiled_capabilities(built, self.catalog)
        dep = self.fixture.output / 'different.d'
        dep.write_bytes(Path(self.built['dependencies'][0]['depfile']['path']).read_bytes())
        self.built['dependencies'][0]['depfile'] = build.fact(dep)
        argv = self.built['commands'][0]['argv']
        argv[argv.index('-MF') + 1] = str(dep)
        with self.assertRaisesRegex(Error, 'fixture_capability_depfile_output'):
            context.compiled_capabilities(self.built, self.catalog)

    def test_header_and_metadata_drift_after_initial_admission_refused(self):
        targets = [self.fixture.wire, self.fixture.export, self.fixture.abort, self.fixture.phase,
                   *(Path(self.built[name]['path']) for name in ('public_recipe', 'bindings_manifest', 'private_manifest'))]
        original_check = header_use.require_fex_header_use
        for target in targets:
            raw, changed = target.read_bytes(), []
            def check(*args, **kwargs):
                result = original_check(*args, **kwargs)
                if not changed:
                    target.write_bytes(raw + b' ')
                    changed.append(True)
                return result
            try:
                with self.subTest(target=target.name), patch.object(header_use, 'require_fex_header_use', side_effect=check):
                    with self.assertRaisesRegex(Error, 'header_changed|assembly_reference_changed'):
                        context.compiled_capabilities(self.built, self.catalog)
            finally:
                target.write_bytes(raw)

    def test_depfile_drift_after_its_unit_check_is_refused(self):
        group = self.built['dependencies'][0]
        dep = Path(group['depfile']['path'])
        check = header_use.require_fex_header_use
        def later_change(*args, **kwargs):
            result = check(*args, **kwargs)
            if args[1] == 'memory':
                dep.write_bytes(dep.read_bytes() + b' ')
            return result
        with patch.object(header_use, 'require_fex_header_use', side_effect=later_change):
            with self.assertRaisesRegex(Error, 'assembly_reference_changed'):
                context.compiled_capabilities(self.built, self.catalog)


class CapabilityAuthorityTests(FixtureSetup, unittest.TestCase):
    def check(self):
        with patch.object(context, 'CAPABILITY_CATALOG', Path(self.fixture.catalog_ref['path'])):
            return context.capability_binding(self.fixture.capabilities_ref, self.fixture.runtime)

    def test_fully_bound_review_accepts_without_current_git_head_or_native_calls(self):
        self.assertEqual(self.check(), self.catalog['capabilities'])

    def test_missing_or_duplicate_review_membership_refused(self):
        assembly = self.fixture.runtime['development_assembly']
        original = list(assembly['review_refs'])
        for name in ('public_recipe', 'bindings_manifest', 'private_manifest'):
            for duplicate in (False, True):
                ref = self.built[name]
                assembly['review_refs'] = original + [ref] if duplicate else [r for r in original if r != ref]
                with self.subTest(name=name, duplicate=duplicate), self.assertRaisesRegex(Error, 'fixture_capability_review_binding'):
                    self.check()
        assembly['review_refs'] = []
        with self.assertRaisesRegex(Error, 'fixture_capability_review_refs'):
            self.check()

    def test_assembly_request_scope_and_exact_single_build_entry_required(self):
        for key, value in (('schema_version', True), ('scope', 'other')):
            old = self.fixture.request[key]
            self.fixture.request[key] = value
            self.fixture.refresh_request()
            with self.subTest(key=key), self.assertRaisesRegex(Error, 'fixture_capability_review_scope'):
                self.check()
            self.fixture.request[key] = old
        original = self.fixture.request['inputs']['builds']
        for entries in ([], [*original, copy.deepcopy(original[0])]):
            self.fixture.request['inputs']['builds'] = entries
            self.fixture.refresh_request()
            with self.assertRaisesRegex(Error, 'fixture_capability_review_build'):
                self.check()

    def test_external_review_refs_cannot_be_replaced_by_build_self_declarations(self):
        for key, field in (('public_recipe_ref', 'public_recipe'), ('bindings_ref', 'bindings_manifest'),
                           ('private_manifest_ref', 'private_manifest')):
            old = self.fixture.entry['recipe_review'][key]
            path = self.fixture.write(self.fixture.metadata / ('other-' + field + '.json'), Path(old['path']).read_bytes())
            replacement = build.fact(path)
            self.fixture.entry['recipe_review'][key] = replacement
            self.fixture.refresh_request()
            self.fixture.runtime['development_assembly']['review_refs'].append(replacement)
            with self.subTest(field=field), self.assertRaisesRegex(Error, 'fixture_capability_review_binding'):
                self.check()
            self.fixture.entry['recipe_review'][key] = old

    def test_independent_source_and_expansion_pins_cannot_follow_build_mutations(self):
        pins = self.fixture.entry['source_commits']
        for name in pins:
            old = pins[name]
            pins[name] = '0' * 40
            self.fixture.refresh_request()
            with self.subTest(root=name), self.assertRaisesRegex(Error, 'fixture_capability_review_source_pins'):
                self.check()
            pins[name] = old
        self.fixture.entry['recipe_sha256'] = '0' * 64
        self.fixture.refresh_request()
        with self.assertRaisesRegex(Error, 'fixture_capability_review_expanded_recipe'):
            self.check()

    def test_artifact_output_must_equal_independently_bound_build_parent(self):
        other = self.fixture.write(self.base / 'other-output/deployment.dll', b'synthetic unexecuted artifact')
        self.built['artifacts']['fex_pe'] = build.fact(other)
        self.fixture.bind_review()
        with self.assertRaisesRegex(Error, 'fixture_capability_output_binding'):
            self.check()

    def test_catalog_and_review_mode_are_not_optional(self):
        self.fixture.entry['recipe_review']['mode'] = 'file_sha256'
        self.fixture.refresh_request()
        with self.assertRaisesRegex(Error, 'fixture_capability_review_shape'):
            self.check()
        self.fixture.entry['recipe_review']['mode'] = 'expanded_dict_sha256'
        self.fixture.refresh_request()
        Path(self.fixture.catalog_ref['path']).write_bytes(b'{}\n')
        with self.assertRaisesRegex(Error, 'fixture_capability_catalog'):
            self.check()

    def test_review_build_catalog_and_binding_postcheck_drift_refused(self):
        compiled = context.compiled_capabilities
        targets = [Path(self.fixture.runtime['development_assembly']['review_refs'][0]['path']),
                   Path(self.fixture.build_ref['path']), Path(self.fixture.catalog_ref['path']),
                   Path(self.fixture.capabilities_ref['path'])]
        for target in targets:
            raw = target.read_bytes()
            def drift(*args):
                result = compiled(*args)
                target.write_bytes(raw + b' ')
                return result
            try:
                with self.subTest(target=target.name), patch.object(context, 'compiled_capabilities', side_effect=drift):
                    with self.assertRaisesRegex(Error, 'assembly_reference_changed'):
                        self.check()
            finally:
                target.write_bytes(raw)
