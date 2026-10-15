# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable request, operation lease and failure-evidence contract tests."""
from contextlib import contextmanager, ExitStack, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import driver
from pear_runtime.fixtures.types import Selection


class RequestPolicy(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.path = self.root / 'request.json'
        self.descriptor_path = self.root / 'descriptor.json'
        build.write_json(self.descriptor_path, {'synthetic': True})
        self.value = dict(schema_version=1, scope='development_fixture_verification',
            descriptor_ref=build.fact(self.descriptor_path), fixture='tls-thread',
            output_name='fixture-1', options=dict(observations='off', trace='historical',
                signal_resume='historical', query_observation='historical',
                entry_observation='historical', link_observation='historical', abort_observation='off'),
            limits=dict(whole_timeout_seconds=120, worker_log_bytes=1024))
        self.manifest = dict(runtime_ref={'path':str(self.root/'runtime/runtime.json')},
                             output_root=str(self.root))
        self.describe = self.enterContext(patch.object(driver, 'descriptor', return_value=self.manifest))
        self.launch = self.enterContext(patch.object(driver.direct, 'run', side_effect=AssertionError('native execution')))

    def load(self, value=None):
        build.write_json(self.path, self.value if value is None else value)
        return driver.request(self.path)

    def test_complete_request_preserves_options_and_exact_ref(self):
        value, ref, manifest, candidate = self.load()
        self.assertEqual(value, self.value)
        self.assertEqual(ref, build.fact(self.path))
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(candidate, Selection('d25-game', self.root/'runtime'))
        self.launch.assert_not_called()

    def test_unknown_missing_fields_and_boolean_schema_refused(self):
        variants = []
        for field in self.value:
            value=deepcopy(self.value);del value[field];variants.append(value)
        variants.extend(({**self.value,'extra':'ignored?'}, {**self.value,'schema_version':True},
                         {**self.value,'scope':'game_execution'}))
        for value in variants:
            with self.subTest(value=value), self.assertRaisesRegex(Error,'fixture_request_shape'):
                self.load(value)
        self.describe.assert_not_called()
        self.launch.assert_not_called()

    def test_fixture_and_output_names_cannot_escape_declared_scope(self):
        for fixture in (None, 'phase-guest', 'game', 'rendering-external'):
            with self.subTest(fixture=fixture), self.assertRaisesRegex(Error,'fixture_request_case'):
                self.load({**self.value,'fixture':fixture})
        for name in ('', '.', '..', '../outside', '/absolute', 'white space', 'Uppercase', 'a/b', 7):
            with self.subTest(name=name), self.assertRaisesRegex(Error,'fixture_request_output'):
                self.load({**self.value,'output_name':name})
        self.describe.assert_not_called()

    def test_option_set_and_types_are_closed(self):
        for changes in ({'observations':True}, {'extra':'on'}):
            with self.subTest(changes=changes), self.assertRaisesRegex(Error,'fixture_request_options'):
                self.load({**self.value,'options':{**self.value['options'],**changes}})
        value=deepcopy(self.value);del value['options']['trace']
        with self.assertRaisesRegex(Error,'fixture_request_options'):
            self.load(value)
        self.describe.assert_not_called()

    def test_timeout_and_worker_log_limits_are_bounded_integers(self):
        for key, values in (('whole_timeout_seconds',(119,1801,True,120.0)),
                            ('worker_log_bytes',(1023,16*1024**2+1,False,1024.0))):
            for value in values:
                limits={**self.value['limits'],key:value}
                with self.subTest(key=key,value=value),self.assertRaisesRegex(Error,'fixture_request_limits'):
                    self.load({**self.value,'limits':limits})
        for limits in ({'whole_timeout_seconds':120}, {**self.value['limits'],'extra':1}):
            with self.assertRaisesRegex(Error,'fixture_request_limits'):
                self.load({**self.value,'limits':limits})
        self.describe.assert_not_called()

    def test_each_policy_is_validated_instead_of_accepting_arbitrary_strings(self):
        for key in driver.OPTIONS:
            with self.subTest(option=key),self.assertRaises(Error):
                self.load({**self.value,'options':{**self.value['options'],key:'unsupported'}})
        self.launch.assert_not_called()

    def test_descriptor_failure_is_preserved_and_cannot_start_execution(self):
        self.describe.side_effect=Error('fixture_context_runtime_scope')
        with self.assertRaisesRegex(Error,'fixture_context_runtime_scope'):
            self.load()
        self.launch.assert_not_called()

    def test_read_only_inspection_never_enters_lease_authority_or_native_run(self):
        self.load()
        output=self.root/self.value['output_name'];events=[];callbacks=[]
        context=SimpleNamespace(fresh_output=lambda p:p,storage_admission=lambda p:{'additional_peak_bytes':1024})
        def create_context(ref,candidate,interval):
            callbacks.append(interval);return context
        with patch.object(driver,'FixtureContext',side_effect=create_context), \
             patch.object(driver,'lease',side_effect=AssertionError('inspect took lease')) as lease, \
             patch.object(driver.os,'setpgid',side_effect=AssertionError('inspect changed group')) as group:
            before=set(self.root.iterdir())
            plan=driver.review(self.path)[3]
            self.assertFalse(plan['current_authority_assessed'])
            self.assertFalse(plan['runtime_execution_performed'])
            self.assertFalse(plan['game_qualified'])
            self.assertEqual(set(self.root.iterdir()),before)
            self.assertFalse(output.exists())
            with self.assertRaisesRegex(Error,'fixture_inspection_cannot_execute'):
                with callbacks[0](output):events.append('unexpected')
            with redirect_stdout(io.StringIO()):self.assertEqual(driver.main(['inspect','--request',str(self.path)]),0)
            lease.assert_not_called();group.assert_not_called()
        self.assertEqual(events,[])
        self.launch.assert_not_called()


class OperationLifecycle(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.output=self.root/'fixture-run'
        self.operation=self.root/'fixture-run.fixture-operation'
        self.request_path=self.root/'request.json';self.descriptor_path=self.root/'descriptor.json'
        build.write_json(self.descriptor_path,{'synthetic':True})
        self.value=dict(limits={'whole_timeout_seconds':120,'worker_log_bytes':1024},
                        descriptor_ref=build.fact(self.descriptor_path),fixture='tls-thread',options={})
        build.write_json(self.request_path,self.value);self.ref=build.fact(self.request_path)
        self.context=SimpleNamespace(candidate=Selection('d25-game',self.root/'runtime'),timings=[{'phase':'synthetic'}])
        self.context.finalize_assessment=Mock(side_effect=self.finalize_assessment)
        self.plan=dict(output=str(self.output),operation_output=str(self.operation))
        self.events=[];self.held=False;self.deadline_active=False;self.mode='pass'
        self.original_handlers={signal.SIGINT:object(),signal.SIGTERM:object()}
        self.handlers=dict(self.original_handlers)
        self.stack=self.enterContext(ExitStack())
        self.stack.enter_context(patch.object(driver.os,'getpid',return_value=123))
        self.stack.enter_context(patch.object(driver.os,'getpgrp',return_value=123))
        self.stack.enter_context(patch.object(driver.signal,'signal',side_effect=self.set_handler))
        self.request=self.stack.enter_context(patch.object(driver,'request',return_value=(self.value,self.ref,{},self.context.candidate)))
        self.review=self.stack.enter_context(patch.object(driver,'review',side_effect=self.reviewed))
        self.stack.enter_context(patch.object(driver,'lease',side_effect=self.lease))
        self.stack.enter_context(patch.object(driver,'deadline',side_effect=self.deadline))
        self.run=self.stack.enter_context(patch.object(driver.direct,'run',side_effect=self.run_case))
        self.check=self.stack.enter_context(patch.object(driver.checks,'fixture',side_effect=self.check_case))

    def set_handler(self,signum,handler):
        previous=self.handlers[signum];self.handlers[signum]=handler;return previous

    @contextmanager
    def lease(self):
        self.assertFalse(self.held);self.assertTrue(self.deadline_active)
        self.held=True;self.events.append('lease-enter')
        try:yield {'path':str(self.root/'synthetic.lock')}
        finally:self.events.append('lease-release');self.held=False

    @contextmanager
    def deadline(self,seconds):
        self.assertEqual(seconds,120);self.deadline_active=True;self.events.append('deadline-enter')
        try:yield
        finally:self.events.append('deadline-release');self.deadline_active=False

    def reviewed(self,path):
        self.assertTrue(self.held and self.deadline_active);self.events.append('review')
        return self.value,self.ref,self.context,self.plan

    def run_case(self,inputs,candidate,output,*,fixture,fixture_context,**options):
        self.assertTrue(self.held and self.deadline_active);self.assertIs(fixture_context,self.context)
        self.assertIsNone(inputs);self.assertEqual(output,self.output);self.events.append('run')
        if self.mode=='no-interval':
            self.output.mkdir();return
        actual=self.root/'wrong-path' if self.mode=='wrong-path' else output
        with fixture_context.execution_interval(actual):
            self.assertTrue(self.held);self.events.append('authority-launch-cleanup')
            output.mkdir()
            case=dict(launches=[{'role':'loader'}],cleanup={'complete':self.mode!='cleanup-failure'},sentinel_survived=True)
            build.write_json(output/'case.json',case)
            if self.mode in ('bad-case','bad-case-success'):(output/'case.json').write_text('{broken')
            if self.mode in ('cleanup-failure','bad-case'):raise Error('original_execution_error')
            if self.mode=='log-limit':print('x'*2048)
            if self.mode=='interrupt':
                try:self.handlers[signal.SIGTERM](signal.SIGTERM,None)
                finally:
                    self.events.append('interrupted-cleanup')
                    build.write_json(output/'case.json',case)
        if self.mode=='twice':
            with fixture_context.execution_interval(output):self.fail('second interval admitted')

    def check_case(self,output,description,*,fixture_context):
        self.assertTrue(self.held and self.deadline_active);self.assertIs(fixture_context,self.context)
        self.events.append('assessment')
        if self.mode=='assessment-failure':raise Error('original_assessment_error')
        result={'passed':True};build.write_json(output/'shared-fixture-assessment.json',result)
        return result

    def finalize_assessment(self,output):
        self.assertEqual(output,self.output)
        self.assertTrue(self.held and self.deadline_active)
        self.events.append('finalize-assessment')
        if self.mode=='producer-changed':raise Error('fixture_producer_changed_after_assessment')

    def execute(self):return driver.execute(self.request_path)

    def receipt(self):
        return build.load(self.operation/'operation.json')

    def test_one_lease_covers_review_execution_cleanup_and_assessment(self):
        result=self.execute();record=self.receipt()
        self.assertEqual(self.events,['deadline-enter','lease-enter','review','run','authority-launch-cleanup','assessment','finalize-assessment','lease-release','deadline-release'])
        self.assertFalse(self.held or self.deadline_active)
        self.assertEqual(result['status'],'passed');self.assertTrue(record['lock']['released'])
        self.assertEqual(len(record['intervals']),1)
        self.assertEqual(record['intervals'][0]['name'],'current_authority_owned_execution_cleanup')
        self.assertTrue(record['runtime_execution_attempted']);self.assertTrue(record['runtime_execution_performed'])
        self.assertTrue(record['cleanup']['complete']);self.assertTrue(record['sentinel_survived'])
        self.assertFalse(record['game_qualified'])
        self.assertEqual(self.handlers,self.original_handlers)
        self.assertEqual(result['operation_ref'],build.fact(self.operation/'operation.json'))

    def test_late_producer_change_prevents_success_after_checker_passes(self):
        self.mode='producer-changed'
        with self.assertRaisesRegex(Error,'fixture_producer_changed_after_assessment'):
            self.execute()
        record=self.receipt()
        self.assertEqual(record['status'],'failed')
        self.assertEqual(record['error']['code'],'fixture_producer_changed_after_assessment')
        self.assertTrue(record['lock']['released'])
        self.assertTrue(record['cleanup']['complete'])
        self.assertTrue(build.load(self.output/'shared-fixture-assessment.json')['passed'])
        self.assertNotIn('result_ref',record)
        self.assertLess(self.events.index('assessment'),self.events.index('finalize-assessment'))
        self.assertLess(self.events.index('finalize-assessment'),self.events.index('lease-release'))
        self.context.finalize_assessment.assert_called_once_with(self.output)

    def test_interval_rejects_a_different_output_before_any_case(self):
        self.mode='wrong-path'
        with self.assertRaisesRegex(Error,'fixture_live_interval_scope'):self.execute()
        record=self.receipt();self.assertEqual(record['status'],'failed')
        self.assertTrue(record['lock']['released']);self.assertEqual(record['intervals'],[])
        self.assertFalse(record['runtime_execution_performed']);self.assertFalse(self.output.exists())
        self.check.assert_not_called()

    def test_interval_is_single_use_and_retains_the_first_case(self):
        self.mode='twice'
        with self.assertRaisesRegex(Error,'fixture_live_interval_scope'):self.execute()
        record=self.receipt();self.assertEqual(record['status'],'failed')
        self.assertEqual(len(record['intervals']),1);self.assertTrue(record['lock']['released'])
        self.assertTrue(record['runtime_execution_performed']);self.assertTrue(record['cleanup']['complete'])
        self.check.assert_not_called()

    def test_passed_checker_cannot_hide_missing_execution_interval(self):
        self.mode='no-interval'
        with self.assertRaisesRegex(Error,'fixture_operation_incomplete'):self.execute()
        record=self.receipt();self.assertEqual(record['status'],'failed')
        self.assertFalse(record['runtime_execution_performed']);self.assertEqual(record['intervals'],[])
        self.assertTrue(record['lock']['released'])

    def test_execution_error_and_failed_cleanup_are_not_rewritten_as_success(self):
        self.mode='cleanup-failure'
        with self.assertRaisesRegex(Error,'original_execution_error'):self.execute()
        record=self.receipt();self.assertEqual(record['status'],'failed')
        self.assertEqual(record['error']['code'],'original_execution_error')
        self.assertFalse(record['cleanup']['complete']);self.assertTrue(record['sentinel_survived'])
        self.assertTrue(record['runtime_execution_performed']);self.assertTrue(record['lock']['released'])
        self.assertEqual(record['case_ref'],build.fact(self.output/'case.json'))
        self.assertEqual(set(record['logs']),{'stdout','stderr'});self.check.assert_not_called()

    def test_assessment_failure_retains_execution_and_cleanup_evidence(self):
        self.mode='assessment-failure'
        with self.assertRaisesRegex(Error,'original_assessment_error'):self.execute()
        record=self.receipt();self.assertEqual(record['error']['code'],'original_assessment_error')
        self.assertTrue(record['cleanup']['complete']);self.assertTrue(record['runtime_execution_performed'])
        self.assertTrue(record['lock']['released']);self.assertEqual(record['status'],'failed')

    def test_unreadable_case_is_unknown_and_does_not_replace_primary_error(self):
        self.mode='bad-case'
        with self.assertRaisesRegex(Error,'original_execution_error'):self.execute()
        record=self.receipt();self.assertEqual(record['error']['code'],'original_execution_error')
        self.assertEqual(record['runtime_execution_performed'],'unknown')
        self.assertTrue(record['evidence_errors']);self.assertTrue(record['lock']['released'])

    def test_worker_log_bound_preserves_failure_and_bounded_bytes(self):
        self.mode='log-limit'
        with self.assertRaisesRegex(Error,'assembly_worker_log_limit'):self.execute()
        record=self.receipt();self.assertEqual(record['status'],'failed')
        self.assertEqual(record['error']['code'],'assembly_worker_log_limit')
        self.assertEqual(sum(r['size_bytes'] for r in record['logs'].values()),1024)
        self.assertTrue(record['cleanup']['complete']);self.assertTrue(record['lock']['released'])

    def test_changed_request_ref_is_rejected_before_operation_and_run(self):
        original=self.review.side_effect
        def changed(path):
            value,ref,context,plan=original(path)
            return {**value,'changed':True},ref,context,plan
        self.review.side_effect=changed
        with self.assertRaisesRegex(Error,'fixture_request_changed'):self.execute()
        self.run.assert_not_called();self.assertFalse(self.operation.exists())
        self.assertFalse(self.held or self.deadline_active)

    def test_execution_requires_an_owned_worker_process_group(self):
        with patch.object(driver.os,'getpgrp',return_value=456):
            with self.assertRaisesRegex(Error,'fixture_worker_group_required'):self.execute()
        self.request.assert_not_called();self.run.assert_not_called()
        self.assertEqual(self.events,[]);self.assertFalse(self.operation.exists())

    def test_interruption_unwinds_run_cleanup_lease_and_original_handlers(self):
        self.mode='interrupt'
        with self.assertRaises(KeyboardInterrupt):self.execute()
        record=self.receipt();self.assertEqual(record['status'],'failed')
        self.assertEqual(record['error']['type'],'KeyboardInterrupt')
        self.assertTrue(record['cleanup']['complete']);self.assertTrue(record['lock']['released'])
        self.assertEqual(self.handlers,self.original_handlers)
        self.assertLess(self.events.index('interrupted-cleanup'),self.events.index('lease-release'))
        self.assertFalse(self.held or self.deadline_active);self.check.assert_not_called()

    def test_log_evidence_error_does_not_replace_primary_execution_failure(self):
        self.mode='cleanup-failure';original=driver.build.fact
        def failing(path):
            if Path(path)==self.operation/'stdout.log':raise Error('synthetic_log_fact_failure')
            return original(path)
        with patch.object(driver.build,'fact',side_effect=failing):
            with self.assertRaisesRegex(Error,'original_execution_error'):self.execute()
        record=self.receipt();self.assertEqual(record['error']['code'],'original_execution_error')
        self.assertEqual(record['evidence_errors'][0]['code'],'synthetic_log_fact_failure')
        self.assertFalse(record['cleanup']['complete']);self.assertTrue(record['lock']['released'])

    def test_log_evidence_failure_after_run_is_retained_as_failed_operation(self):
        original=driver.build.fact
        def failing(path):
            if Path(path)==self.operation/'stdout.log':raise Error('synthetic_log_fact_failure')
            return original(path)
        with patch.object(driver.build,'fact',side_effect=failing):
            with self.assertRaisesRegex(Error,'synthetic_log_fact_failure'):self.execute()
        record=self.receipt()
        self.assertEqual(record['status'],'failed')
        self.assertTrue(record['lock']['released'])
        self.assertTrue(record['cleanup']['complete'])
        self.assertTrue(record['runtime_execution_performed'])
        self.assertEqual(record['evidence_errors'][0]['code'],'synthetic_log_fact_failure')

    def test_case_load_failure_after_run_records_unknown_and_releases_operation(self):
        self.mode='bad-case-success'
        with self.assertRaises(json.JSONDecodeError):self.execute()
        record=self.receipt();self.assertEqual(record['status'],'failed')
        self.assertEqual(record['runtime_execution_performed'],'unknown')
        self.assertEqual(record['error']['type'],'JSONDecodeError')
        self.assertEqual(record['evidence_errors'][0]['type'],'JSONDecodeError')
        self.assertTrue(record['lock']['released']);self.assertEqual(self.handlers,self.original_handlers)

    def test_final_receipt_write_failure_cannot_replace_primary_error(self):
        self.mode='cleanup-failure';original=driver.build.write_json
        def failing(path,value):
            if Path(path)==self.operation/'operation.json' and value['status']=='failed':
                raise Error('synthetic_final_receipt_failure')
            return original(path,value)
        with patch.object(driver.build,'write_json',side_effect=failing):
            with self.assertRaisesRegex(Error,'original_execution_error') as caught:self.execute()
        self.assertTrue(any('synthetic_final_receipt_failure' in note for note in caught.exception.__notes__))
        self.assertFalse(self.held or self.deadline_active);self.assertEqual(self.handlers,self.original_handlers)
        self.assertEqual(build.load(self.output/'case.json')['cleanup'],{'complete':False})


class InterruptRestoration(unittest.TestCase):
    def test_both_handlers_restore_after_normal_exit_and_failure(self):
        for fail in (False,True):
            with self.subTest(fail=fail):
                original={signal.SIGINT:object(),signal.SIGTERM:object()};current=dict(original)
                def replace(signum,handler):
                    old=current[signum];current[signum]=handler;return old
                with patch.object(driver.signal,'signal',side_effect=replace):
                    try:
                        with driver.interrupts():
                            self.assertTrue(all(callable(handler) for handler in current.values()))
                            if fail:raise Error('body_failure')
                    except Error as error:self.assertEqual(error.code,'body_failure')
                self.assertEqual(current,original)

    def test_sigint_and_sigterm_callbacks_raise_for_cleanup_unwinding(self):
        for selected in (signal.SIGINT,signal.SIGTERM):
            original={signal.SIGINT:object(),signal.SIGTERM:object()};current=dict(original)
            def replace(signum,handler):
                old=current[signum];current[signum]=handler;return old
            with patch.object(driver.signal,'signal',side_effect=replace):
                with self.assertRaises(KeyboardInterrupt):
                    with driver.interrupts():current[selected](selected,None)
            self.assertEqual(current,original)

    def test_partial_handler_install_restores_the_first_handler(self):
        old=object();current={signal.SIGINT:old}
        def replace(signum,handler):
            if signum==signal.SIGTERM:raise Error('handler_install_failed')
            prior=current[signum];current[signum]=handler;return prior
        with patch.object(driver.signal,'signal',side_effect=replace):
            with self.assertRaisesRegex(Error,'handler_install_failed'):
                with driver.interrupts():self.fail('body entered after handler install failure')
        self.assertIs(current[signal.SIGINT],old)


if __name__ == '__main__':
    unittest.main()
