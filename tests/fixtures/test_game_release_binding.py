# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Current release adaptation admission with all host observations mocked."""
import copy
from contextlib import ExitStack
from pathlib import Path
import unittest
from unittest.mock import patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import release_controls as checker
from tests.fixtures import test_release_controls as test_support


class CurrentCheckerTests(unittest.TestCase):
    def setUp(self):
        self.fixture=test_support.ReleaseInputsTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.request_ref=self.fixture.prepare()
        root=Path(checker.__file__).resolve().parents[2]
        self.provenance_ref=build.fact(root/'provenance/fixture-controls-release-import.json')
        self.provenance=checker.core.read_ref(self.provenance_ref)
        self.current=build.fact(Path(checker.release.__file__).resolve())

    def inspect(self,provenance=None,*,late_change=False):
        raw_read=checker.core.read_ref;raw_check=checker.core.checked_ref
        def read(ref,*args,**kwargs):
            if ref==self.provenance_ref and provenance is not None:return copy.deepcopy(provenance)
            return raw_read(ref,*args,**kwargs)
        def check(ref,*args,**kwargs):
            if late_change and ref==self.current:raise Error('synthetic_late_checker_change')
            return raw_check(ref,*args,**kwargs)
        with ExitStack() as stack:
            stack.enter_context(patch.object(checker.core,'read_ref',side_effect=read))
            stack.enter_context(patch.object(checker.core,'checked_ref',side_effect=check))
            probe=stack.enter_context(patch.object(checker.release,'DarwinProbe'))
            probe.return_value.observe.return_value=dict(processes={},groups={},provider_ref=self.fixture.runtime)
            stack.enter_context(patch.object(checker.release,'handles',return_value=dict(handles=[],tool_ref=self.fixture.runtime)))
            stack.enter_context(patch.object(checker.release,'lock_probe',return_value=dict(available=True,immediately_released=True)))
            result=checker.inspect(self.request_ref)
        return result,probe

    def test_current_reviewed_adaptation_reaches_both_original_resource_observations(self):
        result,probe=self.inspect()
        self.assertEqual(result['status'],'passed');self.assertTrue(result['resource_release_passed'])
        self.assertEqual(probe.return_value.observe.call_count,2)
        self.assertEqual(result['checker_binding']['mode'],'reviewed_resource_oracle_extraction')
        self.assertEqual(result['checker_binding']['origin'],self.provenance['origin'])
        self.assertEqual(result['checker_binding']['current_checker'],self.current)
        self.assertEqual(len(result['checker_refs']),4)
        self.assertIn(self.provenance_ref,result['checker_refs'])

    def test_missing_adaptation_refuses_changed_checker_before_any_probe(self):
        value=copy.deepcopy(self.provenance);value.pop('stage5_current_checker_adaptation')
        result,probe=self.inspect(value)
        self.assertEqual(result['status'],'unknown');self.assertFalse(result['resource_release_passed'])
        self.assertEqual(result['error']['code'],'release_original_checker_changed');probe.assert_not_called()

    def test_stale_current_pin_and_wrong_original_binding_refuse_before_probe(self):
        for field in ('current_checker','previous_origin'):
            with self.subTest(field=field):
                value=copy.deepcopy(self.provenance);value['stage5_current_checker_adaptation'][field]['sha256']='0'*64
                result,probe=self.inspect(value)
                self.assertEqual(result['status'],'unknown');probe.assert_not_called()

    def test_adaptation_schema_is_closed_and_version_is_an_exact_integer(self):
        for change in ('version_bool','version_two','extra','scope','size_bool'):
            with self.subTest(change=change):
                value=copy.deepcopy(self.provenance);row=value['stage5_current_checker_adaptation']
                if change=='version_bool':row['schema_version']=True
                elif change=='version_two':row['schema_version']=2
                elif change=='extra':row['ignore_changed_source']=True
                elif change=='scope':row['scope']='unreviewed_change'
                else:row['current_checker']['size_bytes']=True
                result,probe=self.inspect(value)
                self.assertEqual(result['status'],'unknown');probe.assert_not_called()

    def test_missing_or_false_correspondence_cannot_admit_current_checker(self):
        for change in ('false','numeric','different_ast','missing','changed_definitions'):
            with self.subTest(change=change):
                value=copy.deepcopy(self.provenance);proof=value['stage5_current_checker_adaptation']['proof']
                if change=='false':proof['legacy_lock_behavior_preserved']=False
                elif change=='numeric':proof['resource_body_equal']=1
                elif change=='different_ast':proof['current_resource_ast_sha256']='0'*64
                elif change=='missing':proof.pop('resource_body_equal')
                else:proof['unchanged_definitions'].remove('handles')
                result,probe=self.inspect(value)
                self.assertEqual(result['status'],'unknown');probe.assert_not_called()

    def test_exact_original_mode_still_requires_the_original_bytes(self):
        value=copy.deepcopy(self.provenance);value.pop('stage5_current_checker_adaptation')
        original={**value['origin'],'path':self.current['path']}
        self.assertEqual(checker.checker_binding(value,original)['mode'],'exact_original')
        with self.assertRaisesRegex(Error,'release_original_checker_changed'):
            checker.checker_binding(value,self.current)

    def test_late_checker_change_cannot_turn_resource_observations_into_pass(self):
        result,probe=self.inspect(late_change=True)
        self.assertEqual(probe.return_value.observe.call_count,2)
        self.assertEqual(result['status'],'unknown');self.assertFalse(result['resource_release_passed'])
        self.assertEqual(result['error']['code'],'synthetic_late_checker_change')


if __name__=='__main__':unittest.main()
