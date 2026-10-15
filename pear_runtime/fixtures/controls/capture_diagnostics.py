# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded metadata for the exact fixture window passed to original capture.

No image API, window enumeration, title query or permission-request API is used.
The temporary facade replaces only capture.py's subprocess binding during poll.
"""
import ctypes
import hashlib
import math
from pathlib import Path
import re
import subprocess
import time

from pear_runtime.errors import need
from pear_runtime.fixtures.inputs import fact, save

CORE_GRAPHICS = '/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics'
CORE_FOUNDATION = '/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation'
INCLUDING_WINDOW = 1 << 3
MAX_ATTEMPTS = 32
MAX_ARG_BYTES = 4096


class _Point(ctypes.Structure):
    _fields_ = [('x', ctypes.c_double), ('y', ctypes.c_double)]


class _Size(ctypes.Structure):
    _fields_ = [('width', ctypes.c_double), ('height', ctypes.c_double)]


class _Rect(ctypes.Structure):
    _fields_ = [('origin', _Point), ('size', _Size)]


class _CoreGraphics:
    """Small ctypes binding; every borrowed CF value dies with its one array."""
    def __init__(self):
        self.cg = ctypes.CDLL(CORE_GRAPHICS)
        self.cf = ctypes.CDLL(CORE_FOUNDATION)
        pointer = ctypes.c_void_p
        signatures = (
            (self.cg, 'CGPreflightScreenCaptureAccess', [], ctypes.c_bool),
            (self.cg, 'CGWindowListCopyWindowInfo', [ctypes.c_uint32, ctypes.c_uint32], pointer),
            (self.cg, 'CGRectMakeWithDictionaryRepresentation', [pointer, ctypes.POINTER(_Rect)], ctypes.c_bool),
            (self.cf, 'CFGetTypeID', [pointer], ctypes.c_ulong),
            (self.cf, 'CFArrayGetTypeID', [], ctypes.c_ulong),
            (self.cf, 'CFDictionaryGetTypeID', [], ctypes.c_ulong),
            (self.cf, 'CFNumberGetTypeID', [], ctypes.c_ulong),
            (self.cf, 'CFBooleanGetTypeID', [], ctypes.c_ulong),
            (self.cf, 'CFArrayGetCount', [pointer], ctypes.c_long),
            (self.cf, 'CFArrayGetValueAtIndex', [pointer, ctypes.c_long], pointer),
            (self.cf, 'CFDictionaryGetValue', [pointer, pointer], pointer),
            (self.cf, 'CFNumberGetValue', [pointer, ctypes.c_long, pointer], ctypes.c_ubyte),
            (self.cf, 'CFBooleanGetValue', [pointer], ctypes.c_ubyte),
            (self.cf, 'CFRelease', [pointer], None),
        )
        for library, name, arguments, result in signatures:
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result
        self.keys = {name: pointer.in_dll(self.cg, name).value for name in (
            'kCGWindowNumber', 'kCGWindowOwnerPID', 'kCGWindowBounds', 'kCGWindowIsOnscreen',
            'kCGWindowLayer', 'kCGWindowAlpha', 'kCGWindowSharingState', 'kCGWindowStoreType')}

    def _value(self, dictionary, name, type_id):
        value = self.cf.CFDictionaryGetValue(dictionary, self.keys[name])
        if not value or self.cf.CFGetTypeID(value) != type_id():
            raise ValueError('missing_or_invalid_field')
        return value

    def _number(self, dictionary, name, floating=False):
        value = self._value(dictionary, name, self.cf.CFNumberGetTypeID)
        number = ctypes.c_double() if floating else ctypes.c_int64()
        # CFNumber.h: Float64=6, SInt64=4. Failed/lossy conversion is unavailable.
        if not self.cf.CFNumberGetValue(value, 6 if floating else 4, ctypes.byref(number)):
            raise ValueError('number_conversion')
        result = number.value
        if not math.isfinite(result) or abs(result) > 2**53:
            raise ValueError('number_range')
        return result

    def inspect(self, window_id, loader_pid):
        result = dict(ownership_confirmed=False, preflight=dict(available=False, granted=None),
                      window=dict(available=False))
        try:
            result['preflight'] = dict(available=True, granted=bool(self.cg.CGPreflightScreenCaptureAccess()))
        except Exception as error:
            result['preflight']['error_type'] = type(error).__name__
        array = self.cg.CGWindowListCopyWindowInfo(INCLUDING_WINDOW, window_id)
        if not array:
            result['window']['reason'] = 'exact_window_unavailable'
            return result
        try:
            if self.cf.CFGetTypeID(array) != self.cf.CFArrayGetTypeID():
                raise ValueError('array_type')
            count = self.cf.CFArrayGetCount(array)
            if count != 1:
                result['window']['reason'] = 'exact_window_count'
                return result  # Do not inspect any entry of a multi-window result.
            row = self.cf.CFArrayGetValueAtIndex(array, 0)
            if not row or self.cf.CFGetTypeID(row) != self.cf.CFDictionaryGetTypeID():
                raise ValueError('window_dictionary_type')
            if self._number(row, 'kCGWindowNumber') != window_id:
                result['window']['reason'] = 'exact_window_id_mismatch'
                return result
            if self._number(row, 'kCGWindowOwnerPID') != loader_pid:
                result['window']['reason'] = 'loader_owner_mismatch'
                return result  # Do not retain other metadata from an unowned window.
            window = dict(available=True, number=window_id, owner_pid=loader_pid, unavailable_fields=[])
            result.update(ownership_confirmed=True, window=window)
            for key, field, floating in (
                ('kCGWindowLayer', 'layer', False), ('kCGWindowAlpha', 'alpha', True),
                ('kCGWindowSharingState', 'sharing_state', False), ('kCGWindowStoreType', 'store_type', False)):
                try:
                    window[field] = self._number(row, key, floating)
                except ValueError:
                    window[field] = None; window['unavailable_fields'].append(field)
            try:
                onscreen = self.cf.CFDictionaryGetValue(row, self.keys['kCGWindowIsOnscreen'])
                if onscreen and self.cf.CFGetTypeID(onscreen) != self.cf.CFBooleanGetTypeID():
                    raise ValueError('onscreen_type')
                window['onscreen'] = bool(self.cf.CFBooleanGetValue(onscreen)) if onscreen else False
            except ValueError:
                window['onscreen'] = None; window['unavailable_fields'].append('onscreen')
            try:
                bounds = self._value(row, 'kCGWindowBounds', self.cf.CFDictionaryGetTypeID)
                rectangle = _Rect()
                if not self.cg.CGRectMakeWithDictionaryRepresentation(bounds, ctypes.byref(rectangle)):
                    raise ValueError('bounds_conversion')
                values = (rectangle.origin.x, rectangle.origin.y, rectangle.size.width, rectangle.size.height)
                if not all(math.isfinite(v) and abs(v) <= 10**7 for v in values) or min(values[2:]) < 0:
                    raise ValueError('bounds_range')
                window['bounds'] = dict(zip(('x', 'y', 'width', 'height'), values))
            except ValueError:
                window['bounds'] = None; window['unavailable_fields'].append('bounds')
            return result
        finally:
            self.cf.CFRelease(array)


def _point():
    return dict(wall_time_ns=time.time_ns(), monotonic_ns=time.monotonic_ns())


class _Facade:
    def __init__(self, diagnostics, capture, original):
        self.diagnostics, self.capture, self.original = diagnostics, capture, original
        self.TimeoutExpired = original.TimeoutExpired

    def run(self, argv, **kwargs):
        return self.diagnostics._run(self.capture, self.original, argv, kwargs)


class CaptureDiagnostics:
    def __init__(self, output, loader_pid):
        self.output = Path(output)
        need(type(loader_pid) is int and 1 < loader_pid < 2**31, 'capture_diagnostic_loader')
        need(self.output.is_absolute() and self.output.is_dir() and
             self.output.resolve(strict=True) == self.output, 'capture_diagnostic_output')
        self.loader_pid = loader_pid
        self.attempts = []
        self.suppressed_attempts = 0
        self._api = None

    def _run(self, capture, original, argv, kwargs):
        need(type(argv) is list and len(argv) == 7 and all(type(a) is str for a in argv) and
             sum(len(a.encode()) for a in argv) <= MAX_ARG_BYTES and
             argv[:3] == ['/usr/sbin/screencapture', '-x', '-o'] and argv[4:6] == ['-t', 'png'] and
             re.fullmatch(r'-l[1-9][0-9]{0,9}', argv[3]) and
             kwargs == dict(capture_output=True, timeout=3), 'capture_diagnostic_command')
        target = Path(argv[-1])
        need(target.parent == self.output and re.fullmatch(r'(visible-\d+-\d+|frame-\d+-\d+-\d+)\.png', target.name),
             'capture_diagnostic_image_path')
        window_id = int(argv[3][2:])
        need(0 < window_id < 2**32 and capture.rows and
             capture.rows[-1].get('native_window', {}).get('id') == window_id, 'capture_diagnostic_declared_window')
        if len(self.attempts) >= MAX_ATTEMPTS:
            self.suppressed_attempts = min(self.suppressed_attempts+1, 2**31-1)
            return original.CompletedProcess(argv, 125, stdout=b'', stderr=b'capture diagnostic attempt limit')
        row = dict(argv=list(argv), loader_pid=self.loader_pid, declared_window_id=window_id,
                   started=_point(), capture_started=None, ended=None, subprocess_called=False, status='started')
        self.attempts.append(row)
        try:
            try:
                if self._api is None:
                    self._api = _CoreGraphics()
                row['metadata'] = self._api.inspect(window_id, self.loader_pid)
            except Exception as error:
                row['metadata'] = dict(ownership_confirmed=False, preflight=dict(available=False, granted=None),
                                       window=dict(available=False, reason='metadata_unavailable'),
                                       error_type=type(error).__name__)
            row['metadata_ended'] = _point()
            if row['metadata']['ownership_confirmed'] is not True:
                row['status'] = 'ownership_unavailable'
                return original.CompletedProcess(argv, 125, stdout=b'', stderr=b'capture diagnostic ownership unavailable')
            row.update(capture_started=_point(), subprocess_called=True)
            result = original.run(argv, **kwargs)
            row.update(status='completed', exit_code=result.returncode,
                       stderr_bytes=len(result.stderr), stderr_sha256=hashlib.sha256(result.stderr).hexdigest())
            return result
        except BaseException as error:
            row.update(status='error', error_type=type(error).__name__)
            raise
        finally:
            row['ended'] = _point()

    def poll(self, capture, stdout, stderr):
        from . import capture as module
        need(type(capture) in (module.Capture, module.FrameCapture) and capture.output == self.output,
             'capture_diagnostic_capture_binding')
        previous = module.subprocess
        need(previous is subprocess, 'capture_diagnostic_subprocess_binding')
        error = None
        counts = (len(self.attempts), self.suppressed_attempts)
        module.subprocess = _Facade(self, capture, previous)
        try:
            return capture.poll(stdout, stderr)
        except BaseException as failure:
            error = failure
            raise
        finally:
            module.subprocess = previous
            if counts != (len(self.attempts), self.suppressed_attempts):
                try:
                    save(self.output/'capture-diagnostics.json', dict(schema_version=1,
                        scope='exact_fixture_window_capture_diagnostics', loader_pid=self.loader_pid,
                        libraries=[CORE_GRAPHICS, CORE_FOUNDATION], max_attempts=MAX_ATTEMPTS,
                        attempts=self.attempts, suppressed_attempts=self.suppressed_attempts,
                        diagnostic_producer=fact(__file__), capture_producer=fact(module.__file__),
                        permission_request_performed=False, other_window_query_performed=False))
                except BaseException as evidence_error:
                    if error is None:
                        raise
                    error.add_note('Capture diagnostic evidence write also failed: '+type(evidence_error).__name__)
