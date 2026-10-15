# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact-window metadata and unchanged capture behavior, with no native calls."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import json
import subprocess
import tempfile
import unittest

from pear_runtime.errors import Error
from pear_runtime.fixtures.controls import capture, capture_diagnostics as diagnostics, execution


def number(value):
    return dict(kind='number', value=value)


def dictionary(values):
    return dict(kind='dictionary', values=values)


class CoreGraphicsScope(unittest.TestCase):
    def setUp(self):
        self.values = {'kCGWindowNumber': number(123), 'kCGWindowOwnerPID': number(456),
            'kCGWindowBounds': dict(kind='dictionary', rect=(10, 20, 640, 480)),
            'kCGWindowIsOnscreen': dict(kind='boolean', value=True),
            'kCGWindowLayer': number(0), 'kCGWindowAlpha': number(1.0),
            'kCGWindowSharingState': number(1), 'kCGWindowStoreType': number(2)}
        self.array = dict(kind='array', rows=[dictionary(self.values)])
        self.reads = []; self.released = []
        def get_value(row, key):
            self.reads.append(key)
            return row['values'].get(key)
        def get_number(value, kind, pointer):
            pointer._obj.value = value['value']
            return value.get('convert', True)
        def bounds(value, pointer):
            rect = pointer._obj
            rect.origin.x, rect.origin.y, rect.size.width, rect.size.height = value['rect']
            return True
        self.api = diagnostics._CoreGraphics.__new__(diagnostics._CoreGraphics)
        self.api.keys = {key:key for key in self.values}
        self.api.cf = SimpleNamespace(CFGetTypeID=lambda value:value['kind'], CFArrayGetTypeID=lambda:'array',
            CFDictionaryGetTypeID=lambda:'dictionary', CFNumberGetTypeID=lambda:'number',
            CFBooleanGetTypeID=lambda:'boolean', CFArrayGetCount=lambda array:len(array['rows']),
            CFArrayGetValueAtIndex=Mock(side_effect=lambda array,index:array['rows'][index]),
            CFDictionaryGetValue=get_value, CFNumberGetValue=get_number,
            CFBooleanGetValue=lambda value:value['value'], CFRelease=lambda value:self.released.append(value))
        self.api.cg = SimpleNamespace(CGPreflightScreenCaptureAccess=Mock(return_value=True),
            CGWindowListCopyWindowInfo=Mock(return_value=self.array), CGRectMakeWithDictionaryRepresentation=bounds)

    def test_only_exact_window_is_queried_and_owned_array_released(self):
        result = self.api.inspect(123, 456)
        self.api.cg.CGWindowListCopyWindowInfo.assert_called_once_with(1 << 3, 123)
        self.assertTrue(result['ownership_confirmed'])
        self.assertEqual(result['window']['bounds'], dict(x=10, y=20, width=640, height=480))
        self.assertEqual(result['window']['owner_pid'], 456)
        self.assertEqual(self.released, [self.array])
        self.assertNotIn('kCGWindowName', self.reads)
        self.assertNotIn('kCGWindowOwnerName', self.reads)

    def test_multiple_returned_windows_are_not_inspected(self):
        self.array['rows'].append(dictionary(self.values))
        result = self.api.inspect(123, 456)
        self.assertFalse(result['ownership_confirmed'])
        self.assertEqual(result['window']['reason'], 'exact_window_count')
        self.assertEqual(self.reads, [])
        self.api.cf.CFArrayGetValueAtIndex.assert_not_called()
        self.assertEqual(self.released, [self.array])

    def test_other_owner_refuses_before_geometry_or_names_are_read(self):
        self.values['kCGWindowOwnerPID'] = number(999)
        result = self.api.inspect(123, 456)
        self.assertFalse(result['ownership_confirmed'])
        self.assertEqual(result['window'], dict(available=False, reason='loader_owner_mismatch'))
        self.assertEqual(self.reads, ['kCGWindowNumber', 'kCGWindowOwnerPID'])
        self.assertNotIn('999', json.dumps(result))
        self.assertEqual(self.released, [self.array])

    def test_wrong_window_id_is_not_used_as_a_fallback(self):
        self.values['kCGWindowNumber'] = number(789)
        result = self.api.inspect(123, 456)
        self.assertFalse(result['ownership_confirmed'])
        self.assertEqual(self.reads, ['kCGWindowNumber'])
        self.assertEqual(self.released, [self.array])

    def test_owner_conversion_failure_still_releases_array(self):
        self.values['kCGWindowOwnerPID']['convert'] = False
        with self.assertRaisesRegex(ValueError, 'number_conversion'):
            self.api.inspect(123, 456)
        self.assertEqual(self.released, [self.array])

    def test_null_window_array_is_unavailable_without_release(self):
        self.api.cg.CGWindowListCopyWindowInfo.return_value = None
        result = self.api.inspect(123, 456)
        self.assertFalse(result['ownership_confirmed'])
        self.assertEqual(self.reads, []); self.assertEqual(self.released, [])

    def test_preflight_is_advisory_and_never_requests_permission(self):
        self.api.cg.CGPreflightScreenCaptureAccess.return_value = False
        result = self.api.inspect(123, 456)
        self.assertEqual(result['preflight'], dict(available=True, granted=False))
        self.assertTrue(result['ownership_confirmed'])
        self.assertFalse(hasattr(self.api.cg, 'CGRequestScreenCaptureAccess'))

    def test_invalid_optional_metadata_is_bounded_unavailable(self):
        self.values['kCGWindowBounds']['rect'] = (0, 0, float('nan'), 480)
        del self.values['kCGWindowIsOnscreen']
        result = self.api.inspect(123, 456)
        self.assertTrue(result['ownership_confirmed'])
        self.assertIsNone(result['window']['bounds'])
        self.assertFalse(result['window']['onscreen'])
        self.assertEqual(result['window']['unavailable_fields'], ['bounds'])
        json.dumps(result, allow_nan=False)


class FacadeScope(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.output = Path(temp.name).resolve()
        self.capture = capture.Capture(self.output)
        self.diagnostics = diagnostics.CaptureDiagnostics(self.output, 456)
        self.original_subprocess = capture.subprocess
        self.api = SimpleNamespace(inspect=Mock(return_value=dict(ownership_confirmed=True,
            preflight=dict(available=True, granted=True), window=dict(available=True, number=123, owner_pid=456))))
        self.enterContext(patch.object(diagnostics, '_CoreGraphics', return_value=self.api))
        self.stdout = b'PEAR_PRESENT_READY cycle=1 phase=0 width=64 height=64\n'
        self.stderr = b'PEAR_PRESENT_WINDOW window=123 width=64 height=64 visible=1 title=1 main=1\n'

    def poll(self):
        return self.diagnostics.poll(self.capture, self.stdout, self.stderr)

    def saved(self):
        return json.loads((self.output/'capture-diagnostics.json').read_text())

    def test_original_argv_result_and_image_are_unchanged(self):
        real_run = subprocess.run
        def run(argv, **kwargs):
            self.assertEqual(argv, ['/usr/sbin/screencapture','-x','-o','-l123','-t','png',str(self.output/'visible-1-0.png')])
            self.assertEqual(kwargs, dict(capture_output=True, timeout=3))
            self.assertIsNot(capture.subprocess, subprocess)
            self.assertIs(subprocess.run, mocked)
            Path(argv[-1]).write_bytes(b'original mock capture pixels')
            return subprocess.CompletedProcess(argv, 0, stdout=b'', stderr=b'')
        with patch.object(subprocess, 'run', side_effect=run) as mocked:
            self.poll()
        self.assertIs(capture.subprocess, self.original_subprocess)
        self.assertIs(subprocess.run, real_run)
        self.assertTrue(self.capture.rows[0]['passed'])
        row = self.saved()['attempts'][0]
        self.assertTrue(row['subprocess_called']); self.assertEqual(row['exit_code'], 0)
        self.assertLessEqual(row['started']['monotonic_ns'], row['metadata_ended']['monotonic_ns'])
        self.assertLessEqual(row['metadata_ended']['monotonic_ns'], row['capture_started']['monotonic_ns'])
        self.assertLessEqual(row['capture_started']['monotonic_ns'], row['ended']['monotonic_ns'])
        self.api.inspect.assert_called_once_with(123, 456)

    def test_original_capture_failure_is_not_substituted(self):
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([],1,b'',b'could not create image from window')):
            self.poll()
        self.assertFalse(self.capture.rows[0]['passed'])
        self.assertEqual(self.capture.rows[0]['stderr'], 'could not create image from window')
        self.assertEqual(self.saved()['attempts'][0]['exit_code'], 1)
        self.assertFalse(list(self.output.glob('*.png')))

    def test_unavailable_ownership_never_calls_capture(self):
        self.api.inspect.return_value = dict(ownership_confirmed=False,
            preflight=dict(available=True, granted=True), window=dict(available=False, reason='loader_owner_mismatch'))
        with patch.object(subprocess, 'run') as run:
            self.poll()
        run.assert_not_called()
        self.assertFalse(self.capture.rows[0]['passed']); self.assertEqual(self.capture.rows[0]['exit_code'], 125)
        self.assertFalse(self.saved()['attempts'][0]['subprocess_called'])
        self.assertIs(capture.subprocess, self.original_subprocess)

    def test_unavailable_framework_is_recorded_without_capture(self):
        with patch.object(diagnostics, '_CoreGraphics', side_effect=OSError('missing framework')), \
             patch.object(subprocess, 'run') as run:
            self.poll()
        run.assert_not_called()
        self.assertEqual(self.saved()['attempts'][0]['metadata']['window']['reason'], 'metadata_unavailable')
        self.assertFalse(self.capture.rows[0]['passed'])

    def test_timeout_keeps_original_failure_and_restores_binding(self):
        with patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired('exact capture',3)):
            self.poll()
        self.assertEqual(self.capture.rows[0]['error'], 'capture_timeout')
        self.assertFalse(self.capture.rows[0]['passed'])
        self.assertIs(capture.subprocess, self.original_subprocess)
        self.assertEqual(self.saved()['attempts'][0]['error_type'], 'TimeoutExpired')

    def test_primary_exception_survives_diagnostic_save_failure(self):
        error = RuntimeError('original failure')
        with patch.object(subprocess, 'run', side_effect=error), patch.object(diagnostics, 'save', side_effect=OSError('write')):
            with self.assertRaises(RuntimeError) as caught:
                self.poll()
        self.assertIs(caught.exception, error)
        self.assertIs(capture.subprocess, self.original_subprocess)
        self.assertTrue(any('evidence write' in note for note in error.__notes__))

    def test_non_original_command_is_rejected_before_query(self):
        self.capture.rows.append(dict(native_window=dict(id=123)))
        for argv in (
            ['/usr/sbin/screencapture','-x','-o','-l456','-t','png',str(self.output/'visible-1-0.png')],
            ['/usr/sbin/screencapture','-x','-o','-l0','-t','png',str(self.output/'visible-1-0.png')],
            ['/usr/sbin/screencapture','-x','-o','-l123','-t','png',str(self.output.parent/'outside.png')]):
            with self.subTest(argv=argv), self.assertRaises(Error):
                self.diagnostics._run(self.capture, subprocess, argv, dict(capture_output=True,timeout=3))
        self.api.inspect.assert_not_called()

    def test_capture_count_and_record_data_are_bounded(self):
        with patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'failed')) as run:
            for cycle in range(1, diagnostics.MAX_ATTEMPTS+2):
                self.stdout = ('PEAR_PRESENT_READY cycle=%d phase=0 width=64 height=64\n'%cycle).encode()
                self.poll()
        saved = self.saved()
        self.assertEqual(run.call_count, diagnostics.MAX_ATTEMPTS)
        self.assertEqual(len(saved['attempts']), diagnostics.MAX_ATTEMPTS)
        self.assertEqual(saved['suppressed_attempts'], 1)
        self.assertLess((self.output/'capture-diagnostics.json').stat().st_size, 256*1024)
        self.assertFalse(any(row['passed'] for row in self.capture.rows))

    def test_frame_capture_class_uses_same_scoped_facade(self):
        self.capture = capture.FrameCapture(self.output)
        self.stdout = b'PEAR_PRESENT_FRAME cycle=1 phase=0 frame=0 width=64 height=64 gpu=1\n'
        with patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'failed')) as run:
            self.poll()
        self.assertEqual(run.call_args.args[0][-1],str(self.output/'frame-1-0-0.png'))
        self.assertFalse(self.capture.rows[0]['passed'])
        self.assertIs(capture.subprocess,self.original_subprocess)


class SessionBinding(unittest.TestCase):
    def test_actual_session_passes_owned_loader_pid_to_diagnostics(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);output=Path(temp.name).resolve()
        work=output/'run';work.mkdir()
        children={};waits=[]
        session=SimpleNamespace(streams={('sentinel','stdout'):{'data':b'{}\n'},('loader','stdout'):{'data':b''},
            ('loader','stderr'):{'data':b''}},events={'server':[{'event':'server_ready'}]},failure=None,
            observer=SimpleNamespace(registrations={},signal_observations=[]),children=children,endpoint='owned')
        def launch(role,*args,**kwargs):
            child=SimpleNamespace(pid=100+len(children),identity={},exit_code=42,reaped=True,allowed_paths=[],exited=role=='loader')
            children[role]=child;return child
        session.launch=launch
        session.wait_for=lambda predicate,timeout:(waits.append(timeout) or predicate())
        helpers=SimpleNamespace(api=SimpleNamespace(APISession=lambda *args,**kwargs:session,
            graphical_session=lambda:dict(status=0,available=True)),base=SimpleNamespace(
            parse_lines=lambda *args:[{}],validate_helper=lambda *args:None))
        cleanup=Mock(return_value=({},dict(complete=True),{},[],True,[]))
        @contextmanager
        def supervision(root):yield SimpleNamespace(cleanup_session=cleanup),helpers
        value=dict(fixtures={'presentation-frames':{'sha256':'a'*64}},entrypoints={name:name for name in
            ('sentinel','server','bootstrap_helper','loader','fixture_pe')})
        context=SimpleNamespace(provider_root=output,base={'runtime_ref':{'sha256':'b'*64}})
        observer=Mock()
        with patch.object(execution.supervisor,'supervision',supervision), \
             patch.object(execution.supervisor,'assessment_packet',return_value={}), \
             patch.object(execution.supervisor,'environment',return_value={}), \
             patch.object(execution.os,'pipe',return_value=(17,18)),patch.object(execution.os,'close'), \
             patch.object(diagnostics,'CaptureDiagnostics',return_value=observer) as constructor, \
             patch.object(subprocess,'run',side_effect=AssertionError('no native process')):
            result=execution._translated_session(context,output,value,output,'presentation-frames',{})
        constructor.assert_called_once_with(output,children['loader'].pid)
        self.assertEqual(children['loader'].pid,102)
        observer.poll.assert_called_once()
        self.assertIsInstance(observer.poll.call_args.args[0],capture.FrameCapture)
        cleanup.assert_called_once();self.assertIsNone(result['error'])
