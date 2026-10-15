# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fixed CPU context/owned-session boundaries using synthetic native surfaces."""
from contextlib import contextmanager
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from pear_runtime.errors import Error
from pear_runtime.fixtures.controls import cpu_context as cc,cpu_execution as execution
from pear_runtime.fixtures.inputs import fact,read,save


class ContextRejections(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.context=cc.CPUContext.__new__(cc.CPUContext)
        self.context.value={'output_root':str(self.root)}
        self.context._active=self.context._completed=False
        self.context.execution_interval=Mock();self.context._admit=Mock(return_value=('runtime','value'))

    def test_fixed_table_has19_cpu_plus_one_ordering(self):
        self.assertEqual(len(cc.CPU_IDS),19);self.assertEqual(len(cc.CASES),20)
        self.assertEqual(cc.CASES[-1],'ordering');self.assertNotIn('game',cc.CASES)

    def test_unknown_or_external_case_never_admits(self):
        for name in ('game','phase-guest','device',None,'../tls-thread'):
            with self.subTest(case=name),self.assertRaisesRegex(Error,'cpu_single_execution'):
                self.context.begin(name,self.root/'out')
        self.context._admit.assert_not_called()

    def test_context_is_single_use_even_on_admission_failure(self):
        self.context._admit.side_effect=Error('changed_input')
        with self.assertRaisesRegex(Error,'changed_input'):self.context.begin('ordering',self.root/'out')
        with self.assertRaisesRegex(Error,'cpu_single_execution'):self.context.begin('ordering',self.root/'other')
        self.assertTrue(self.context._completed)

    def test_replay_context_cannot_start_a_live_interval(self):
        self.context.execution_interval=None
        with self.assertRaisesRegex(Error,'cpu_single_execution'):self.context.begin('ordering',self.root/'out')
        self.context._admit.assert_not_called()

    def test_existing_nested_and_alias_outputs_refuse(self):
        (self.root/'existing').mkdir()
        for output in (self.root/'existing',self.root/'nested'/'out',self.root/'..'/self.root.name/'out'):
            with self.subTest(output=output),self.assertRaisesRegex(Error,'cpu_fresh_output'):
                self.context.fresh_output(output)

    def test_finish_marks_failed_final_validation_completed(self):
        self.context._active=True;self.context._admit.side_effect=Error('late_changed')
        with self.assertRaisesRegex(Error,'late_changed'):self.context.finish()
        self.assertTrue(self.context._completed);self.assertFalse(self.context._active)

    def test_storage_keeps_reserve_without_assuming_clone_savings(self):
        self.context._producers=SimpleNamespace(recheck=lambda:None,logical_bytes=100)
        self.context.base={'seed_inventory':[dict(path='drive_c/windows/system32/ntdll.dll',kind='file',size=200,sha256='a')],
                           'modules':{'ntdll.dll':dict(seed_sha256='a',selected_ref={'size_bytes':300})}}
        self.context._extra_refs=lambda:{}
        with patch.object(cc.shutil,'disk_usage',return_value=SimpleNamespace(free=6*1024**3+100)):
            with self.assertRaisesRegex(Error,'cpu_storage_capacity'):self.context.storage_admission(self.root/'out')


class OwnedInterruption(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.output=self.root/'output';self.runtime=self.root/'runtime';self.runtime.mkdir();(self.runtime/'fixture.exe').write_bytes(b'fixture')
        self.value={'fixtures':{'tls-thread':{'path':'fixture.exe','sha256':fact(self.runtime/'fixture.exe')['sha256']}},
                    'entrypoints':{'sentinel':'sentinel','server':'server','bootstrap_helper':'bootstrap','loader':'loader'}}
        self.context=cc.CPUContext.__new__(cc.CPUContext);self.context.ref={};self.context.base={'runtime_ref':{'sha256':'f'*64},'operation_ref':{},'profile_ref':{}}
        self.context.value={'input_pack_ref':{},'producer_manifest_ref':{}};self.context._active=True
        self.context.provider_root_override=self.root
        self.context.base['provider_root']=str(self.root)
        self.context.storage_admission=Mock(return_value={});self.context.begin=Mock(return_value=(self.runtime,self.value))
        self.context.preserve_sources=Mock();self.context.current_authority=Mock();self.context.finish=Mock();self.context.mark=Mock()
        @contextmanager
        def interval(output):yield
        self.context.execution_interval=interval
        self.cleanup=Mock(return_value=({},dict(complete=True),dict(complete=True),[],True,[]))
        self.children={};self.calls=0
        self.session=SimpleNamespace(streams={('sentinel','stdout'):{'data':b'{}\n'},('loader','stderr'):{'data':b''}},
            events={'server':[{'event':'server_ready'}]},failure=None,children=self.children,
            observer=SimpleNamespace(registrations={},signal_observations=[]),endpoint='synthetic')
        def launch(role,args,env,**kwargs):
            child=SimpleNamespace(pid=101+len(self.children),identity=dict(pid=101+len(self.children)),exit_code=42,reaped=True,
                                  allowed_paths=[],exited=False)
            self.children[role]=child;return child
        def wait(predicate,timeout):
            self.calls+=1
            if self.calls==3:raise Error('assembly_worker_timeout')
            return True
        self.session.launch=launch;self.session.wait_for=wait
        self.helpers=SimpleNamespace(base=SimpleNamespace(STREAM_LIMIT=0,validate_helper=lambda *a:None,parse_lines=lambda *a:[{}]),
            api=SimpleNamespace(APISession=lambda *a,**k:self.session,graphical_session=lambda:{'status':0,'available':True}))
        @contextmanager
        def supervisor(root):yield SimpleNamespace(cleanup_session=self.cleanup),self.helpers
        self.enterContext(patch.object(execution.supervisor,'supervision',supervisor))
        self.enterContext(patch.object(execution.supervisor,'assessment_packet',return_value={}))
        self.enterContext(patch.object(execution.supervisor,'environment',return_value={}))
        self.enterContext(patch.object(execution,'clone_prefix',return_value={}))
        self.enterContext(patch.object(execution.evidence,'authority',return_value={'captured':True}))

    def test_actual_owned_session_deadline_cleans_up_and_skips_after_authority(self):
        with self.assertRaisesRegex(Error,'assembly_worker_timeout'):
            execution.run(self.context,'tls-thread',self.output)
        self.cleanup.assert_called_once()
        self.context.current_authority.assert_called_once_with(self.output/'before')
        case=read(self.output/'case.json');control=read(self.output/'control.json')
        self.assertEqual(case['error']['code'],'assembly_worker_timeout');self.assertTrue(case['cleanup']['complete'])
        self.assertEqual(control['status'],'failed');self.assertIsNone(control['after_ref'])
        self.assertIn('authority_after_not_started',control);self.context.finish.assert_called_once()

    def test_wrong_context_is_rejected_before_copy_or_session(self):
        with self.assertRaisesRegex(Error,'cpu_execution_context'):
            execution.run(SimpleNamespace(execution_interval=lambda:None),'tls-thread',self.output)
        self.cleanup.assert_not_called();self.assertFalse(self.output.exists())

    def test_unlisted_case_is_rejected_before_context_begin(self):
        with self.assertRaisesRegex(Error,'cpu_case_selection'):execution.run(self.context,'game',self.output)
        self.context.begin.assert_not_called();self.cleanup.assert_not_called()
