# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later AND MIT
"""Portable case admission, original-protocol and failure-preservation tests.

Every host launch, authority call and screenshot is mocked. These tests do not
produce native execution or synthetic runtime qualification evidence.
"""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import ast
import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest

from pear_runtime.errors import Error
from pear_runtime.fixtures.controls import context as contexts, execution as runner, capture
from pear_runtime.fixtures.inputs import fact, save, digest


class Temporary(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def write(self, path, data=b'fixture'):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return fact(path)

    def context(self):
        result = object.__new__(contexts.ControlsContext)
        result._active = result._completed = result._validated_end = False
        result._output = result._case = result._runtime = result._runtime_value = None
        result.execution_interval = lambda: None
        result.value = dict(output_root=str(self.root), device_ref=None)
        result._admit = Mock(return_value=(self.root/'runtime', {'fixture': 'selected'}))
        return result


class Admission(Temporary):
    def test_unextended_shared_producer_api_fails_without_fallback(self):
        def original(ref, provider):
            self.fail('old seven capture must not be called')
        with patch.object(contexts.producers, 'capture', original):
            with self.assertRaisesRegex(Error, 'controls_shared_producer_api_pending'):
                contexts.capture({}, self.root)

    def test_shared_capture_receives_only_fixed_controls_options(self):
        observed = []
        def extended(ref, provider, *, entry_modules, dynamic_paths, scope):
            observed.append((entry_modules, dynamic_paths, scope))
            return 'captured'
        with patch.object(contexts.producers, 'capture', extended):
            self.assertEqual(contexts.capture({}, self.root), 'captured')
        self.assertEqual(observed, [(contexts.ENTRY_MODULES, contexts.DYNAMIC_PATHS, contexts.PRODUCER_SCOPE)])

    def test_unselected_case_never_runs_admission(self):
        for name in ('tls-thread', 'pairing', 'ordering', 'presentation', '', None):
            with self.subTest(name=name):
                value = self.context()
                with self.assertRaises(Error):
                    value.begin(name, self.root/'new')
                value._admit.assert_not_called()

    def test_pairing_requires_a_new_device_reference(self):
        value = self.context()
        with self.assertRaisesRegex(Error, 'controls_current_device_required'):
            value.begin('native-pairing', self.root/'new')
        value._admit.assert_not_called()

    def test_case_identity_is_preserved_and_single_use(self):
        value = self.context()
        value.begin('presentation-original', self.root/'new')
        self.assertEqual(value._case, 'presentation-original')
        with self.assertRaises(Error):
            value.begin('device', self.root/'other')

    def test_replay_context_has_no_execution_interval(self):
        value = self.context()
        value.execution_interval = None
        with self.assertRaises(Error):
            value.begin('device', self.root/'new')
        value._admit.assert_not_called()

    def test_admission_failure_consumes_context(self):
        value = self.context()
        value._admit.side_effect = Error('changed_source')
        with self.assertRaisesRegex(Error, 'changed_source'):
            value.begin('device', self.root/'new')
        self.assertTrue(value._completed)
        self.assertFalse(value._active)

    def test_fresh_output_rejects_existing_nested_and_alias_paths(self):
        value = self.context()
        old = self.root/'old';old.mkdir()
        link = self.root/'alias';link.symlink_to(old)
        for path in (old, link, old/'nested', Path('relative')):
            with self.subTest(path=path):
                with self.assertRaises(Error):
                    value.fresh_output(path)
        self.assertEqual(value.fresh_output(self.root/'new'), self.root/'new')

    def test_failed_final_input_recheck_still_closes_context(self):
        value = self.context()
        value.begin('device', self.root/'new')
        value._admit.side_effect = Error('changed_source')
        with self.assertRaisesRegex(Error, 'changed_source'):
            value.finish()
        self.assertFalse(value._active)
        self.assertTrue(value._completed)
        self.assertFalse(value._validated_end)

    def test_storage_keeps_six_gib_reserve_and_full_seed_budget(self):
        value = self.context()
        value.base = dict(seed_inventory=[dict(path='drive_c/windows/system32/x',kind='file',size=1,sha256='a'*64)], modules={})
        value.ref = dict(size_bytes=10)
        for key in ('candidate_context_ref','arena_header_ref','arena_source_ref'):
            value.value[key] = dict(size_bytes=10)
        value._producers = SimpleNamespace(recheck=lambda:None, logical_bytes=50)
        with patch.object(contexts.shutil,'disk_usage',return_value=SimpleNamespace(free=20*1024**3)):
            budget = value.storage_admission(self.root/'new')
        self.assertEqual(budget['reserve_bytes'], 6*1024**3)
        self.assertFalse(budget['apfs_clone_savings_assumed'])
        self.assertGreaterEqual(budget['additional_peak_bytes'], 842557436+1024**3)
        with patch.object(contexts.shutil,'disk_usage',return_value=SimpleNamespace(free=budget['additional_peak_bytes']+6*1024**3-1)):
            with self.assertRaisesRegex(Error,'controls_storage_capacity'):
                value.storage_admission(self.root/'new')

    def test_pairing_storage_accounts_for_actual_current_device_prefix(self):
        value=self.context()
        value.base=dict(seed_inventory=[],modules={},runtime_ref={'path':'runtime'})
        value.ref=dict(size_bytes=10)
        for key in ('candidate_context_ref','arena_header_ref','arena_source_ref'):
            value.value[key]=dict(size_bytes=10)
        value.value['device_ref']={'path':'device-assessment'}
        value._producers=SimpleNamespace(recheck=lambda:None,logical_bytes=50)
        device=dict(passed=True,case_id='device',scope='development_runtime_control_assessment',
                    runtime_ref=value.base['runtime_ref'],observations=dict(synthetic_prefix_inventory=[
                        dict(path='large-device-cache',kind='file',mode=0o600,size=3*1024**3,sha256='a'*64)]))
        with patch.object(contexts.core,'read_ref',return_value=device),\
             patch.object(contexts.shutil,'disk_usage',return_value=SimpleNamespace(free=20*1024**3)):
            budget=value.storage_admission(self.root/'new')
        self.assertEqual(budget['seed_inventory_logical_bytes'],3*1024**3)
        self.assertGreater(budget['additional_peak_bytes'],4*1024**3)
        self.assertEqual(budget['seed_origin'],'current_device_post_run_prefix')


class PrefixAndProtocol(Temporary):
    def fixture_context(self):
        seed = self.root/'seed'
        template = seed/'run/prefix'
        modules = {}
        for name in ('ntdll.dll','xtajit64.dll'):
            old = self.write(template/'drive_c/windows/system32'/name, ('old '+name).encode())
            new = self.write(self.root/'runtime'/name, ('new '+name).encode())
            modules[name] = dict(seed_sha256=old['sha256'], selected_ref=new)
        self.write(template/'system.reg', b'registry')
        inventory = runner.prefix_inventory(template)
        prefix = self.root/'copy';prefix.mkdir()
        tool = self.write(self.root/'copy-tool')
        value = SimpleNamespace(seed=seed, base=dict(seed_ref={'path':'seed'},seed_inventory=inventory,modules=modules),
                                value=dict(tool_refs=dict(copy=tool)))
        return value, prefix

    def test_clone_changes_only_the_two_exact_selected_modules(self):
        value, prefix = self.fixture_context()
        def cp(argv, **kwargs):
            self.assertEqual(argv[1],'-cRp')
            self.assertTrue(kwargs['check'])
            self.assertEqual(kwargs['timeout'],30)
            shutil.copytree(value.seed/'run/prefix', prefix, dirs_exist_ok=True)
        with patch.object(runner.subprocess,'run',side_effect=cp):
            origin = runner.clone_prefix(value,prefix)
        self.assertFalse(origin['cold_prefix_initialization'])
        for name,row in value.base['modules'].items():
            self.assertEqual(fact(prefix/'drive_c/windows/system32'/name)['sha256'],row['selected_ref']['sha256'])
        self.assertEqual(runner.prefix_inventory(value.seed/'run/prefix'), value.base['seed_inventory'])
        self.assertEqual((prefix/'system.reg').read_bytes(),b'registry')

    def test_changed_seed_is_rejected_before_copy(self):
        value,prefix=self.fixture_context()
        (value.seed/'run/prefix/system.reg').write_bytes(b'changed')
        with patch.object(runner.subprocess,'run') as cp:
            with self.assertRaisesRegex(Error,'controls_seed_changed'):
                runner.clone_prefix(value,prefix)
            cp.assert_not_called()

    def test_copy_of_extra_unselected_file_is_rejected(self):
        value,prefix=self.fixture_context()
        def cp(*args,**kwargs):
            shutil.copytree(value.seed/'run/prefix',prefix,dirs_exist_ok=True)
            (prefix/'unrequested').write_bytes(b'changed')
        with patch.object(runner.subprocess,'run',side_effect=cp):
            with self.assertRaisesRegex(Error,'controls_prefix_clone'):
                runner.clone_prefix(value,prefix)

    def test_fixture_selection_does_not_mutate_runtime_packet(self):
        packet = dict(entrypoints=dict(fixture_pe='old'),fixtures={name:dict(path=name+'.exe') for name,_ in contexts.CASES.values()})
        original=copy.deepcopy(packet)
        selected=runner.selected_value(packet,'native-pairing')
        self.assertEqual(packet,original)
        self.assertEqual(selected['entrypoints']['fixture_pe'],'pairing.exe')
        self.assertEqual(contexts.CASES['native-pairing'][1],0)
        self.assertTrue(all(code==42 for name,(_,code) in contexts.CASES.items() if name!='native-pairing'))

    def test_no_implicit_or_historical_case_selection(self):
        with self.assertRaisesRegex(Error,'controls_case_selection'):
            runner.selected_value({},'tls-thread')

    def test_missing_or_legacy_device_result_is_not_current(self):
        value=SimpleNamespace(value=dict(device_ref=None),base=dict(runtime_ref={}))
        with self.assertRaisesRegex(Error,'controls_current_device_required'):
            runner.verify_device_input(value)
        path=self.root/'legacy.json'
        save(path,dict(passed=True,fixture_id='device',scope='translated_device_only'))
        value.value['device_ref']=fact(path)
        with self.assertRaisesRegex(Error,'controls_current_device_binding'):
            runner.verify_device_input(value)

    def test_captured_pairing_keeps_exit_zero_and_source_identity(self):
        provider=Path(runner.__file__).resolve().parents[2]/'providers/pear_legacy'
        source=provider/runner.supervisor.REUSE_PATH
        raw=source.read_bytes()
        life=SimpleNamespace(read_relative=lambda *args:raw,source_refs={runner.supervisor.REUSE_PATH:fact(source)},
                             cleanup_session=Mock(),validate_launches=Mock())
        namespace=runner.pairing_reader(life,provider)
        self.assertEqual(namespace['TIMEOUT_MS'],180000)
        record={name:None for name in namespace['CASE_FIELDS']}
        record.update(schema_version=1,record_kind='dxmt_pairing_case',case=dict(id='metal',timeout_ms=180000,expected_exit=42))
        with self.assertRaisesRegex(Error,'pair_case_scope'):
            namespace['assess_case'](record,{},self.root,{},None)
        life.source_refs[runner.supervisor.REUSE_PATH]['sha256']='0'*64
        with self.assertRaisesRegex(Error,'controls_pairing_provider_changed'):
            runner.pairing_reader(life,provider)


class Captures(Temporary):
    def test_frame_capture_targets_only_owned_window_and_deduplicates(self):
        frames=b'PEAR_PRESENT_FRAME cycle=1 phase=0 frame=0 width=64 height=64 gpu=1\n'
        windows=b'PEAR_PRESENT_WINDOW window=123 width=64 height=64 visible=1 title=1 main=1\n'
        def screen(argv,**kwargs):
            self.assertEqual(argv[:6],['/usr/sbin/screencapture','-x','-o','-l123','-t','png'])
            self.assertEqual(kwargs,dict(capture_output=True,timeout=3))
            Path(argv[-1]).write_bytes(b'PNG test bytes')
            return SimpleNamespace(returncode=0,stderr=b'')
        cap=capture.FrameCapture(self.root)
        with patch.object(capture.subprocess,'run',side_effect=screen) as process:
            cap.poll(frames,windows);cap.poll(frames,windows)
        self.assertEqual(process.call_count,1)
        self.assertTrue(cap.rows[0]['passed'])
        record=json.loads((self.root/'visible-frames.json').read_text())
        self.assertEqual(record['producer'],fact(capture.__file__))

    def test_missing_or_unowned_window_never_captures_screen(self):
        for windows in (b'',b'PEAR_PRESENT_WINDOW window=123 width=64 height=64 visible=0 title=1 main=1\n'):
            cap=capture.FrameCapture(self.root)
            with patch.object(capture.subprocess,'run') as process:
                cap.poll(b'PEAR_PRESENT_FRAME cycle=1 phase=0 frame=0 width=64 height=64 gpu=1\n',windows)
            process.assert_not_called()
            self.assertFalse(cap.rows[0]['passed'])

    def test_capture_failure_and_timeout_remain_failed(self):
        args=(b'PEAR_PRESENT_READY cycle=1 phase=0 width=64 height=64\n',
              b'PEAR_PRESENT_WINDOW window=123 width=64 height=64 visible=1 title=1 main=1\n')
        for error in (SimpleNamespace(returncode=1,stderr=b'denied'),subprocess.TimeoutExpired('capture',3)):
            cap=capture.Capture(self.root)
            with patch.object(capture.subprocess,'run',**({'side_effect':error} if isinstance(error,Exception) else {'return_value':error})):
                cap.poll(*args)
            self.assertFalse(cap.rows[0]['passed'])


class TranslationBoundary(Temporary):
    def boundary(self):
        runtime=self.root/'runtime';runtime.mkdir()
        self.write(runtime/'runtime.json',b'{}')
        events={'loader':[dict(event='native',cpu_type=16777228,translation_value=0,translation_error=0),
                          dict(event='image',cpu_type=16777228),dict(event='stage3_guest_exit',exit_code=42)]}
        value=dict(kind='translated_graphics_observation',runtime_sha256=digest(b'{}'),diagnostic_only=True,
                   qualification_scope='development_runtime_controls',outcome='exited',error=None,stream_error=None,cleanup_errors=[],
                   processes={'loader':dict(exit_code=42),'sentinel':dict(exit_code=0)},
                   cleanup=dict(complete=True,errors=[],observation_gap=False,reaped={'loader':True,'server':True}),
                   sentinel_cleanup=dict(complete=True,errors=[],observation_gap=False,reaped={'sentinel':True}),
                   sentinel_survived=True,authorization_before_after_passed=True,events=events)
        run=self.root/'run';run.mkdir()
        save(run/'case.json',value)
        self.operation_ref=self.write(self.root/'assembly-operation.json',b'{}')
        for side in ('before','after'):
            (run/side).mkdir();save(run/side/'control.json',dict(passed=True,runtime_sha256=value['runtime_sha256'],operation_ref=self.operation_ref))
        raw={('loader','events'):b''.join(json.dumps(r).encode()+b'\n' for r in events['loader'])}
        return run,runtime,value,raw

    def test_current_development_scope_keeps_exit_42_host_and_cleanup_gates(self):
        run,runtime,value,raw=self.boundary()
        with patch.object(runner,'_translated_logs',return_value=raw):
            self.assertEqual(runner.translated_boundary(run,runtime,{},operation_ref=self.operation_ref)[0],value)
        for key,changed in [('diagnostic_only',False),('qualification_scope','old-qualified'),('sentinel_survived',False),
                            ('outcome','timeout'),('error',{'code':'launch_failed'}),('cleanup_errors',['failed'])]:
            altered=copy.deepcopy(value);altered[key]=changed;save(run/'case.json',altered)
            with patch.object(runner,'_translated_logs',return_value=raw):
                with self.subTest(key=key),self.assertRaises(Error):
                    runner.translated_boundary(run,runtime,{},operation_ref=self.operation_ref)

    def test_current_authority_float_timings_preserve_bool_and_operation_gates(self):
        run,runtime,value,raw=self.boundary()
        # Exact phase timing values from the retained current-authority record.
        phase=dict(name='current_input_admission',seconds=0.5673929999975371,
                   started=dict(monotonic_seconds=37552.267512375,wall_utc='2026-10-15T17:36:15.685630+00:00'),
                   ended=dict(monotonic_seconds=37552.834905375,wall_utc='2026-10-15T17:36:16.252999+00:00'))
        good=dict(passed=True,runtime_sha256=value['runtime_sha256'],operation_ref=self.operation_ref,phases=[phase])
        for side in ('before','after'):
            save(run/side/'control.json',good)
        with patch.object(runner,'_translated_logs',return_value=raw):
            self.assertEqual(runner.translated_boundary(run,runtime,{},operation_ref=self.operation_ref)[0],value)
        for key,changed in [('passed',1),('passed',False),('runtime_sha256','0'*64),
                            ('operation_ref',{**self.operation_ref,'sha256':'0'*64})]:
            altered=copy.deepcopy(good);altered[key]=changed;save(run/'after/control.json',altered)
            with patch.object(runner,'_translated_logs',return_value=raw):
                with self.subTest(key=key,changed=changed),self.assertRaisesRegex(Error,'translated_authorization_pair'):
                    runner.translated_boundary(run,runtime,{},operation_ref=self.operation_ref)

    def test_native_exit_zero_cannot_satisfy_translated_control(self):
        run,runtime,value,raw=self.boundary()
        value['processes']['loader']['exit_code']=0;save(run/'case.json',value)
        with patch.object(runner,'_translated_logs',return_value=raw):
            with self.assertRaisesRegex(Error,'translated_execution_failed'):
                runner.translated_boundary(run,runtime,{},operation_ref=self.operation_ref)

    def test_changed_event_log_and_non_arm64_image_are_rejected(self):
        run,runtime,value,raw=self.boundary()
        with patch.object(runner,'_translated_logs',return_value={('loader','events'):b'{}\n'}):
            with self.assertRaisesRegex(Error,'translated_events_changed'):
                runner.translated_boundary(run,runtime,{},operation_ref=self.operation_ref)
        value['events']['loader'][1]['cpu_type']=7;save(run/'case.json',value)
        raw={('loader','events'):b''.join(json.dumps(r).encode()+b'\n' for r in value['events']['loader'])}
        with patch.object(runner,'_translated_logs',return_value=raw):
            with self.assertRaisesRegex(Error,'translated_image_not_arm64'):
                runner.translated_boundary(run,runtime,{},operation_ref=self.operation_ref)


class RunFailures(Temporary):
    def runnable(self):
        value=self.context()
        runtime=self.root/'runtime';runtime.mkdir()
        value.ref=self.write(self.root/'context.json',b'{}')
        runtime_ref=self.write(runtime/'runtime.json',b'{}')
        operation_ref=self.write(self.root/'assembly-operation.json',b'{}')
        value.base=dict(runtime_ref=runtime_ref,operation_ref=operation_ref,profile_ref={})
        value.value.update(fixture_refs={name:{} for name in contexts.CASES},producer_manifest_ref={})
        selected=dict(entrypoints={},fixtures={name:dict(path=name+'.exe') for name,_ in contexts.CASES.values()})
        value.begin=Mock(return_value=(runtime,selected))
        value.storage_admission=Mock(return_value={})
        value.preserve_sources=Mock()
        value.finish=Mock()
        events=[]
        @contextmanager
        def interval(output):
            self.assertEqual(Path(output),self.root/'new')
            events.append('acquired')
            try:yield
            finally:events.append('released')
        value.execution_interval=interval
        def authority(output):
            events.append(output.name)
            output.mkdir();save(output/'control.json',dict(passed=True,runtime_sha256=runtime_ref['sha256'],operation_ref=operation_ref))
        value.current_authority=authority
        return value,events

    def test_primary_launch_error_survives_after_authority_failure(self):
        value,events=self.runnable()
        authority=value.current_authority
        def fail_after(output):
            if output.name=='after':raise Error('after_failed')
            return authority(output)
        value.current_authority=fail_after
        with patch.object(runner,'clone_prefix',return_value={}),patch.object(runner,'_translated_session',side_effect=Error('launch_failed')):
            with self.assertRaisesRegex(Error,'launch_failed'):
                runner.run(value,'device',self.root/'new')
        self.assertEqual(events[-1],'released')
        value.finish.assert_called_once()
        record=json.loads((self.root/'new/control.json').read_text())
        self.assertEqual(record['error']['code'],'launch_failed')
        self.assertEqual(record['secondary_errors'][0]['code'],'after_failed')
        self.assertFalse(json.loads((self.root/'new/controls-assessment.json').read_text())['passed'])

    def test_before_authority_refusal_prevents_any_session(self):
        value,events=self.runnable()
        value.current_authority=Mock(side_effect=Error('grant_refused'))
        with patch.object(runner,'_translated_session') as session:
            with self.assertRaisesRegex(Error,'grant_refused'):
                runner.run(value,'device',self.root/'new')
            session.assert_not_called()
        self.assertEqual(events,['acquired','released'])

    def test_oracle_failure_cannot_become_successful_assessment(self):
        value,events=self.runnable()
        def execute(context,runtime,selected,output,case_id,origin):
            result=dict(error=None,authorization_before_after_passed=False)
            save(output/'case.json',result)
            return result
        with patch.object(runner,'clone_prefix',return_value={}),patch.object(runner,'_translated_session',side_effect=execute),\
             patch.object(runner,'assess',side_effect=Error('missing_frame')):
            with self.assertRaisesRegex(Error,'missing_frame'):
                runner.run(value,'presentation-frames',self.root/'new')
        case=json.loads((self.root/'new/case.json').read_text())
        self.assertTrue(case['authorization_before_after_passed'])
        result=json.loads((self.root/'new/controls-assessment.json').read_text())
        self.assertFalse(result['passed'])
        self.assertEqual(result['error']['code'],'missing_frame')
        self.assertEqual(events[-1],'released')

    def test_corrupt_partial_case_does_not_replace_primary_error(self):
        value,events=self.runnable()
        def failed(context,runtime,selected,output,case_id,origin):
            (output/'case.json').write_bytes(b'{"partial":')
            raise Error('original_launch_failure')
        with patch.object(runner,'clone_prefix',return_value={}),patch.object(runner,'_translated_session',side_effect=failed):
            with self.assertRaisesRegex(Error,'original_launch_failure'):
                runner.run(value,'device',self.root/'new')
        record=json.loads((self.root/'new/control.json').read_text())
        self.assertEqual(record['error']['code'],'original_launch_failure')
        self.assertTrue(record['secondary_errors'])
        self.assertEqual(events[-1],'released')


class OriginalSession(Temporary):
    def session(self,fail_loader=False):
        calls=[]
        session=SimpleNamespace(output=self.root/'run',endpoint='/private/tmp/pear-stage3-test/control',
            failure=None,events={},streams={},children={},
            observer=SimpleNamespace(registrations={},signal_observations=[]))
        def launch(role,argv,env,**options):
            calls.append((role,argv,dict(env),options))
            if role=='loader' and fail_loader:raise Error('owned_loader_failure')
            paths=options.get('allowed_paths',[argv[0]])
            child=SimpleNamespace(pid=100+len(calls),identity={'pid':100+len(calls)},
                                  exited=role=='loader',exit_code=42 if role=='loader' else 0,reaped=True,
                                  allowed_paths={str(p) for p in paths})
            session.children[role]=child
            session.streams[(role,'stdout')]={'data':b'{}\n'}
            session.streams[(role,'stderr')]={'data':b''}
            session.events[role]=[{'event':'server_ready'}] if role=='server' else []
            return child
        session.launch=launch
        session.wait_for=lambda condition,timeout: condition()
        cleanup=Mock(return_value=({}, {'complete':True}, {'complete':True}, [], True, []))
        helpers=SimpleNamespace(api=SimpleNamespace(APISession=Mock(return_value=session),
            graphical_session=lambda:dict(status=0,available=True)),
            base=SimpleNamespace(validate_helper=lambda *args:None,parse_lines=lambda *args:[{}]))
        @contextmanager
        def supervision(root):yield SimpleNamespace(cleanup_session=cleanup),helpers
        runtime=self.root/'runtime';runtime.mkdir()
        output=self.root/'output';output.mkdir()
        (output/'run/work').mkdir(parents=True)
        (output/'run/work/tmp').mkdir()
        (output/'run/prefix').mkdir()
        value=dict(entrypoints={k:k for k in ('loader','server','sentinel','bootstrap_helper','fixture_pe','ntdll_native')},
                   fixtures={'device':dict(path='device.exe',sha256='a'*64)},native_images=[],baseline_loader_capacity={})
        context=SimpleNamespace(provider_root=self.root,base={'runtime_ref':{'sha256':'b'*64}})
        return context,runtime,value,output,supervision,helpers,cleanup,calls

    def test_original_session_selects_device_and_metal_before_launch(self):
        context,runtime,value,output,supervision,helpers,cleanup,calls=self.session()
        with patch.object(runner.supervisor,'supervision',supervision),patch.object(runner.os,'pipe',return_value=(40,41)),\
             patch.object(runner.os,'close'):
            result=runner._translated_session(context,runtime,value,output,'device',{})
        self.assertEqual(result['fixture_id'],'device')
        self.assertEqual(result['expected_exit'],42)
        self.assertFalse(result['authorization_before_after_passed'])
        self.assertEqual([row[0] for row in calls],['sentinel','server','loader'])
        self.assertEqual(calls[-1][1],[str(runtime/'bootstrap_helper'),'--exec-4k',str(runtime/'loader'),str(runtime/'fixture_pe')])
        self.assertEqual(calls[-1][2]['MTL_DEBUG_LAYER'],'1')
        self.assertEqual(calls[-1][2]['MTL_SHADER_VALIDATION'],'1')
        self.assertEqual(calls[-1][2]['WINEDLLOVERRIDES'],'d3d11,dxgi,d3d10core,winemetal=b;mscoree=')
        cleanup.assert_called_once()

    def test_owned_session_failure_still_preserves_cleanup_and_original_error(self):
        context,runtime,value,output,supervision,helpers,cleanup,calls=self.session(True)
        with patch.object(runner.supervisor,'supervision',supervision),patch.object(runner.os,'pipe',return_value=(40,41)),\
             patch.object(runner.os,'close'):
            result=runner._translated_session(context,runtime,value,output,'device',{})
        self.assertEqual(result['outcome'],'error')
        self.assertEqual(result['error']['code'],'owned_loader_failure')
        cleanup.assert_called_once()
        self.assertTrue((output/'case.json').is_file())


class IdentityJoins(Temporary):
    def test_current_authority_requires_exact_assembly_operation(self):
        runtime_ref=self.write(self.root/'runtime.json',b'{}')
        operation_ref=self.write(self.root/'operation.json',b'{}')
        different_ref=self.write(self.root/'other-operation.json',b'{}')
        (self.root/'before').mkdir()
        path=self.root/'before/control.json'
        save(path,dict(passed=True,runtime_sha256=runtime_ref['sha256'],operation_ref=operation_ref))
        self.assertEqual(runner._authority(self.root,'before',runtime_ref,operation_ref),fact(path))
        save(path,dict(passed=True,runtime_sha256=runtime_ref['sha256'],operation_ref=different_ref))
        with self.assertRaisesRegex(Error,'controls_current_authority'):
            runner._authority(self.root,'before',runtime_ref,operation_ref)

    def test_selected_arena_uses_lowercase_fork_path_and_current_owner(self):
        owner=self.root/'wine'
        header_ref=self.write(owner/contexts.ARENA_PATH,b'_Static_assert(PEAR_ARENA_MAPPING_BYTES == UINT64_C(1588985856), "geometry");\n')
        manifest=owner/'pear/source-manifest.json'
        manifest.parent.mkdir()
        save(manifest,dict(component='pear-wine',selected_files=[dict(path=contexts.ARENA_PATH,
             sha256=header_ref['sha256'],size_bytes=header_ref['size_bytes'])]))
        artifact=self.write(self.root/'native.so')
        built=self.root/'build.json'
        save(built,dict(status='passed',roots={'wine':dict(kind='git',path=str(owner))},artifacts={'wine_native':artifact}))
        runtime=dict(baseline_loader_capacity={'integrated_jit_mapping_bytes':contexts.ARENA_BYTES},
                     development_assembly=dict(builds=[fact(built)],artifacts={'wine_native':artifact}))
        value=dict(arena_header_ref=header_ref,arena_source_ref=fact(manifest))
        contexts._arena(value,runtime)
        data=json.loads(manifest.read_text());data['component']='wine';save(manifest,data)
        value['arena_source_ref']=fact(manifest)
        with self.assertRaisesRegex(Error,'controls_arena_source_binding'):
            contexts._arena(value,runtime)
        data['component']='pear-wine';save(manifest,data)
        value['arena_source_ref']=fact(manifest)
        runtime['baseline_loader_capacity']['integrated_jit_mapping_bytes']-=1
        with self.assertRaisesRegex(Error,'controls_arena_mapping_source'):
            contexts._arena(value,runtime)

    def operation(self):
        output=self.root/'device';output.mkdir()
        operation=output.with_name(output.name+'.controls-operation');operation.mkdir()
        context_ref=self.write(self.root/'context.json',b'{}')
        runtime_ref=self.write(self.root/'runtime.json',b'{}')
        case_ref=self.write(output/'case.json',b'{}')
        control_ref=self.write(output/'control.json',b'{}')
        request_path=self.root/'request.json'
        save(request_path,dict(scope='development_control_verification',descriptor_ref=context_ref,case_id='device',output_name='device'))
        result_path=output/'controls-assessment.json'
        save(result_path,dict(passed=True,scope='development_runtime_control_assessment',context_ref=context_ref,
                             case_id='device',runtime_ref=runtime_ref,case_ref=case_ref,control_ref=control_ref))
        result_ref=fact(result_path)
        record=dict(scope='development_controls_operation',status='passed',result_ref=result_ref,
                    lock={'released':True},runtime_execution_performed=True,game_qualified=False,
                    request_ref=fact(request_path),case_ref=case_ref,
                    plan=dict(request_ref=fact(request_path),descriptor_ref=context_ref,case_id='device',
                              output=str(output),operation_output=str(operation),runtime_ref=runtime_ref),
                    worker=dict(pid=123,process_group=123,interpreter_ref=self.write(self.root/'python')),
                    intervals=[{}],runtime_execution_attempted=True,
                    logs={name:self.write(operation/(name+'.log'),b'') for name in ('stdout','stderr')})
        path=operation/'operation.json';save(path,record)
        return path,result_ref,context_ref,output,record

    def test_device_requires_completed_released_and_exact_operation_result(self):
        path,result,context,output,record=self.operation()
        contexts.completed_control_operation(fact(path),result,context,'device',output)
        for field,wrong in [('status','running'),('lock',{'released':False}),('result_ref',context),
                            ('runtime_execution_performed',False),('logs',{})]:
            changed=copy.deepcopy(record);changed[field]=wrong;save(path,changed)
            with self.subTest(field=field),self.assertRaises(Error):
                contexts.completed_control_operation(fact(path),result,context,'device',output)

    def test_operation_wrong_case_output_and_unbound_case_are_rejected(self):
        path,result,context,output,record=self.operation()
        for section,field,wrong in [('plan','case_id','native-pairing'),('plan','output',str(self.root/'other')),
                                    ('worker','process_group',999)]:
            changed=copy.deepcopy(record);changed[section][field]=wrong;save(path,changed)
            with self.subTest(field=field),self.assertRaises(Error):
                contexts.completed_control_operation(fact(path),result,context,'device',output)
        record['case_ref']=self.write(output/'other-case.json',b'{}');save(path,record)
        with self.assertRaisesRegex(Error,'controls_operation_result'):
            contexts.completed_control_operation(fact(path),result,context,'device',output)


class ExactImports(unittest.TestCase):
    def test_original_selected_units_match_import_receipt(self):
        root=Path(runner.__file__).resolve().parents[3]
        receipt=json.loads((root/'provenance/fixture-controls-execution-import.json').read_text())
        replacements={'terminal':'device_terminal','verify_logs':'_translated_logs','boundary':'translated_boundary','run':'_translated_session'}
        for row in receipt['sources']:
            path=root/row['destination'];raw=path.read_text();lines=raw.splitlines(keepends=True)
            name=replacements.get(row['symbol'],row['symbol'])
            node=next(n for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name==name)
            selected=''.join(lines[node.lineno-1:node.end_lineno])
            with self.subTest(symbol=name):
                self.assertEqual(hashlib.sha256(selected.encode()).hexdigest(),row['imported_sha256'])


if __name__=='__main__':
    unittest.main()
