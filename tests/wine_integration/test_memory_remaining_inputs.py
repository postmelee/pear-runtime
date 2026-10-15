# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Current compile-set and root-relative input refusals; no host execution."""
import copy
from pathlib import Path
import unittest
import tempfile

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.assembly import core
from pear_runtime.fixtures import context
from tests.fixtures import test_context as context_fixtures


class RemainingInputCases(unittest.TestCase):
    def test_each_required_compile_command_omission_refused(self):
        fixture = context_fixtures.CompiledTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        context.compiled_capabilities(fixture.built, fixture.catalog)
        for index, unit in enumerate(fixture.catalog['compile_units']):
            value = copy.deepcopy(fixture.built)
            value['commands'].pop(index)
            with self.subTest(unit=unit['path']), self.assertRaisesRegex(
                    Error, 'fixture_capability_compile_set'):
                context.compiled_capabilities(value, fixture.catalog)

    def test_complete_root_relative_path_refusal_matrix(self):
        for value in ('/a', '../a', './a', 'a/../a', 'a//b', 'a/', ''):
            with self.subTest(value=value), self.assertRaisesRegex(Error, 'build_relative_path'):
                build.relative(value)
        self.assertEqual(build.relative('a/b'), Path('a/b'))

    def test_positive_receipt_refuses_current_failure_markers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for name, raw in [('stdout', b'synthetic output'), ('stderr', b''),
                              ('artifact', b'synthetic artifact')]:
                (root / name).write_bytes(raw)
            output = build.fact(root / 'artifact')
            receipt = dict(
                schema_version=1, scope='development_component_build', status='passed',
                runtime_eligible=False, game_qualified=False, recipe_sha256='a' * 64,
                operation_id='synthetic-operation',
                roots={'fex': {'kind': 'git', 'commit': 'b' * 40}},
                commands=[dict(id='synthetic', exit_code=0, error=None,
                               logs={s: build.fact(root / s) for s in ('stdout', 'stderr')})],
                outputs={'artifact': output}, artifacts={'fex_pe': output})
            build.write_json(root / 'operation.json', dict(
                scope='task56_component_build', operation_id=receipt['operation_id'],
                released=True))

            def admit(extra):
                value = dict(receipt, **extra)
                build.write_json(root / 'build.json', value)
                return core._build_artifacts(dict(
                    ref=build.fact(root / 'build.json'), recipe_sha256='a' * 64,
                    source_commits={'fex': 'b' * 40}))

            for extra in ({}, {'failure': None}, {'failure_code': None},
                          {'failure': None, 'failure_code': None}):
                with self.subTest(positive=extra):
                    value, operation_ref = admit(extra)
                    self.assertEqual(value, dict(receipt, **extra))
                    self.assertEqual(operation_ref, build.fact(root / 'operation.json'))
            for field in ('failure', 'failure_code'):
                for marker in ('observed failure', False, {}, [], 0):
                    with self.subTest(field=field, marker=marker), self.assertRaisesRegex(
                            Error, 'assembly_build_failure'):
                        admit({field: marker})
