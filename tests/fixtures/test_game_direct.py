# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the actual shared owner with mocked native surfaces and fixed game facts."""
from contextlib import contextmanager,ExitStack
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import direct,game_types,game_release
from pear_runtime.fixtures.types import Selection


class SharedGameOwnerTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.output=self.root/'out';self.output.mkdir();self.work=self.output/'run';self.work.mkdir()
        game=self.output/'game';game.mkdir();exe=game/'Megabonk.exe';exe.write_bytes(b'synthetic')
        target=game/'GameAssembly.dll';target.write_bytes(b'target');snapshot=self.root/'snapshot';snapshot.write_text('{}')
        refs=[]
        for i in range(69):
            p=self.root/f'source-{i}';p.write_text(str(i));refs.append(build.fact(p))
        info=target.stat();self.prepared=game_types.PreparedGame(game,build.fact(exe),
            dict(dev=info.st_dev,ino=info.st_ino,bytes=info.st_size,sha256=build.fact(target)['sha256']),refs,build.fact(snapshot))
        self.context=SimpleNamespace(value={'game_files':[dict(relative=f'f{i}',ref=r) for i,r in enumerate(refs)],
            'snapshot_ref':build.fact(snapshot)},recheck_prepared=Mock())
        self.context.recheck_prepared.side_effect=lambda output:self.events.append('prepared-recheck')
        play=self.output/'play';play.mkdir();build.write_json(play/'companion-result.json',{})
        build.write_json(play/'owned-companion-processes.json',{})
        self.events=[];self.launches=[];self.result={'applied':{}}
        self.session=SimpleNamespace(output=self.work,endpoint='synthetic-control',failure=None,
            streams={('sentinel','stdout'):{'data':b'ready\n'},('loader','stderr'):{'data':b''}},
            events={'server':[{'event':'server_ready'}],'loader':[]},children={},
            observer=SimpleNamespace(registrations={},signal_observations=[]))
        def launch(role,argv,environment,**kwargs):
            self.events.append('launch-'+role);self.launches.append((role,argv,kwargs))
            child=SimpleNamespace(pid=90001+len(self.launches),exited=role=='loader',identity=dict(pid=90001+len(self.launches),ppid=90000,start_sec=100,start_usec=0),
                exit_code=77 if role=='loader' else 0,reaped=True,allowed_paths=set())
            self.session.children[role]=child;return child
        self.session.launch=launch;self.session.wait_for=lambda predicate,timeout:predicate()
        self.adapter=SimpleNamespace(snapshot=lambda:{},done=False,continue_supervision=False,
            close=lambda:self.events.append('adapter-close'))
        def started(loader):
            self.assertEqual(self.events[-1],'launch-loader');self.assertEqual(self.session.output,self.work)
            self.events.append('started')
        self.adapter.started=started
        self.factory=Mock(return_value=self.adapter)
        self.owner=SimpleNamespace(operation_id='synthetic',assert_current=Mock(),
            bind_factory=Mock(return_value=self.factory),validate_adapter=Mock())
        self.helpers=SimpleNamespace(base=SimpleNamespace(STREAM_LIMIT=0,parse_lines=lambda *a:[{}],validate_helper=lambda *a:None),
            api=SimpleNamespace(APISession=Mock(return_value=self.session),graphical_session=lambda:{'status':0,'available':True}))
        def cleanup(*args):
            self.events.append('main-cleanup');return {},{'complete':True},{'complete':True},[],True,[]
        self.life=SimpleNamespace(cleanup_session=cleanup,companion_factory=object())
        @contextmanager
        def supervise(root):yield self.life,self.helpers
        self.stack=self.enterContext(ExitStack())
        self.stack.enter_context(patch.object(direct.supervisor,'supervision',supervise))
        self.stack.enter_context(patch.object(direct.supervisor,'assessment_packet',return_value={}))
        self.stack.enter_context(patch.object(direct,'SampleWindows',return_value=SimpleNamespace(rows=[],cancel=lambda:self.events.append('sampler-cancel'))))
        self.stack.enter_context(patch.object(direct.os,'pipe',return_value=(100,101)))
        self.stack.enter_context(patch.object(direct.os,'close'))
        self.stack.enter_context(patch.object(direct,'finish_reason',return_value=None))
        self.stack.enter_context(patch.object(direct,'attached',return_value=False))
        self.stack.enter_context(patch.object(direct,'pump_observations',side_effect=lambda *a:self.events.append('first-poll')))
        self.stack.enter_context(patch.object(game_release,'capture_companions',return_value=build.fact(play/'owned-companion-processes.json')))
        self.kwargs=dict(reuse=self.root,selected_limit=64*1024**2,work=self.work,runtime=self.root,
            value={'entrypoints':{k:k for k in ('sentinel','server','loader','bootstrap_helper')}},
            selected_trace='-all',selected_env={},selected_signal={},selected_query={},selected_entry={},selected_link={},
            abort_env={},fixture=None,result=self.result,seconds=300,output=self.output,prefix=self.work/'prefix',
            samples=(),candidate=Selection('d25-game',self.root),target=self.prepared.target,selected={'attach_observer':True},
            play_adapter_factory=object(),game_context=self.context,prepared=self.prepared,game_operation=self.owner)

    def test_fixed_game_arguments_and_started_before_first_poll(self):
        direct._execute_owned(**self.kwargs)
        argv=next(row[1] for row in self.launches if row[0]=='loader')
        self.assertEqual(argv,[str(self.root/'bootstrap_helper'),'--exec-4k',str(self.root/'loader'),
            str(self.output/'game/Megabonk.exe'),'-force-d3d11','-screen-fullscreen','0','-screen-width','960',
            '-screen-height','540','-logFile',str(self.output/'Player.log')])
        self.assertLess(self.events.index('prepared-recheck'),self.events.index('launch-loader'))
        self.assertLess(self.events.index('started'),self.events.index('first-poll'))
        self.assertEqual(self.events.count('started'),1)
        self.assertLess(self.events.index('adapter-close'),self.events.index('main-cleanup'))
        self.assertNotIn('diagnostic_fixture',self.result)
        self.assertEqual(self.result['processes']['loader']['exit_code'],77)
        self.assertEqual(self.result['observed']['stream_limit_bytes'],64*1024**2)

    def test_changed_other_copied_input_refuses_before_loader_and_keeps_cleanup(self):
        self.context.recheck_prepared.side_effect=Error('game_copy_changed')
        direct._execute_owned(**self.kwargs)
        self.assertFalse(any(row[0]=='loader' for row in self.launches));self.assertNotIn('started',self.events)
        self.assertEqual(self.result['error']['code'],'game_copy_changed')
        self.assertEqual(self.events[-1],'main-cleanup');self.assertTrue((self.output/'case.json').is_file())

    def test_interruption_after_started_preserves_case_then_reraises(self):
        with patch.object(direct,'pump_observations',side_effect=Error('assembly_worker_timeout')):
            with self.assertRaisesRegex(Error,'assembly_worker_timeout'):direct._execute_owned(**self.kwargs)
        self.assertEqual(self.events[-1],'main-cleanup')
        self.assertEqual(build.load(self.output/'case.json')['error']['code'],'assembly_worker_timeout')

    def test_factory_failure_still_cleans_main_owner_without_guest_launch(self):
        self.factory.side_effect=Error('companion_constructor_failure')
        direct._execute_owned(**self.kwargs)
        self.assertEqual(self.launches,[]);self.assertEqual(self.events[-1],'main-cleanup')
        self.assertEqual(self.result['error']['code'],'companion_constructor_failure')


if __name__=='__main__':unittest.main()
