#!/usr/bin/env python3
"""Owned, bounded native Wine bootstrap; no PE or game qualification.

Wine supplies the real handshake and native events. Original Pear helpers only
establish native ownership and test unrelated-process survival. A successful
synthetic lifecycle test never substitutes for signing.validate_prepared().
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
from pathlib import Path
import platform
import re
import select
import selectors
import signal
import stat
import struct
import subprocess
import sys
import time
import uuid

from common import Error, decode_json, encoded, load_json, need, read_relative, open_relative, relative, sha256
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[2]
MACH_ARM64 = 0x100000C
STREAM_LIMIT = 262144
EVENT_LIMIT = 2097152
PHASES = {'loader_entry', 'loader_reexec', 'ntdll_entry', 'server_ready', 'bootstrap_native',
          'image', 'images_end', 'server_peer', 'server_handshake', 'memory', 'bootstrap_stop',
          'bootstrap_hold', 'failure'}
SNAPSHOTS = {'loader_entry', 'ntdll_entry', 'server_ready', 'bootstrap_native'}


def create_output(path, repo=REPO):
    path = Path(path)
    path = path if path.is_absolute() else repo / path
    root = repo / '.build/task4'
    need(path != root and path.is_relative_to(root) and '..' not in path.parts, 'outside_task_root')
    current = repo
    for part in path.relative_to(repo).parts[:-1]:
        current /= part
        if current.exists():
            need(not current.is_symlink() and current.is_dir(), 'unsafe_output_ancestor')
        else:
            current.mkdir(mode=0o700)
    need(not path.exists() and not path.is_symlink(), 'destination_exists')
    path.mkdir(mode=0o700)
    return path


def write_new(path, value):
    with Path(path).open('xb') as stream:
        stream.write(encoded(value))


def environment(home, prefix, nonce):
    """No caller HOME, Steam/Wine/DYLD settings, inherited sockets or credentials."""
    need(re.fullmatch('[0-9a-f]{32}', nonce) is not None, 'invalid_nonce')
    return {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'TMPDIR': str(home / 'tmp'),
            'LANG': 'C', 'LC_ALL': 'C', 'WINEPREFIX': str(prefix), 'WINEDEBUG': '-all',
            'PEAR_BOOTSTRAP_NONCE': nonce, 'PEAR_BOOTSTRAP_GENERATION': '0'}


class BSDInfo(ctypes.Structure):
    # Public SDK sys/proc_info.h proc_bsdinfo. Only owned child PIDs are queried.
    _fields_ = [(name, ctypes.c_uint32) for name in
                ('flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid', 'ruid', 'rgid',
                 'svuid', 'svgid', 'reserved')] + [
        ('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32)] + [
        (name, ctypes.c_uint32) for name in ('nfiles', 'pgid', 'jobc', 'tdev', 'tpgid')] + [
        ('nice', ctypes.c_int32), ('start_sec', ctypes.c_uint64), ('start_usec', ctypes.c_uint64)]


class DarwinObserver:
    """Observe exit without reaping, keeping direct-child PIDs reserved until cleanup."""
    def __init__(self):
        need(sys.platform == 'darwin' and platform.machine() == 'arm64', 'native_arm64_host_required')
        need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'external_child_reaping')
        class Sigaction(ctypes.Structure):
            _fields_ = [('handler', ctypes.c_void_p), ('mask', ctypes.c_uint32), ('flags', ctypes.c_int)]
        system = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        system.sigaction.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(Sigaction)]
        system.sigaction.restype = ctypes.c_int
        action = Sigaction()
        need(system.sigaction(signal.SIGCHLD, None, ctypes.byref(action)) == 0 and
             action.handler is None and not action.flags & 0x0020, 'automatic_child_reaping')
        self.lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        self.lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                          ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_pidinfo.restype = ctypes.c_int
        self.lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.lib.proc_pidpath.restype = ctypes.c_int
        self.lib.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_listpids.restype = ctypes.c_int
        self.queue = select.kqueue()
        self.handles = {}

    def identity(self, pid):
        info = BSDInfo()
        count = self.lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
        need(count == ctypes.sizeof(info) and info.pid == pid, 'owned_identity_unavailable')
        return {'pid': pid, 'ppid': info.ppid, 'start_sec': info.start_sec, 'start_usec': info.start_usec}

    def executable(self, pid):
        data = ctypes.create_string_buffer(4096)
        need(self.lib.proc_pidpath(pid, data, len(data)) > 0, 'owned_executable_unavailable')
        return str(Path(os.fsdecode(data.value)).resolve())

    def add(self, child):
        child.identity = self.identity(child.pid)
        need(child.identity['ppid'] == os.getpid(), 'not_direct_child')
        need(self.executable(child.pid) in child.allowed_paths, 'unexpected_owned_executable')
        self.handles[child.pid] = child
        self.queue.control([select.kevent(child.pid, filter=select.KQ_FILTER_PROC,
                           flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                           fflags=select.KQ_NOTE_EXIT | select.KQ_NOTE_FORK | select.KQ_NOTE_EXEC)], 0, 0)

    def refresh(self):
        for event in self.queue.control(None, max(1, len(self.handles) * 2), 0):
            child = self.handles.get(event.ident)
            need(child is not None, 'unknown_process_event')
            child.exited |= bool(event.fflags & select.KQ_NOTE_EXIT)
            child.fork_seen |= bool(event.fflags & select.KQ_NOTE_FORK)

    def group_members(self, child):
        need(not child.reaped, 'group_leader_already_reaped')
        members = (ctypes.c_int * 1024)()
        ctypes.set_errno(0)
        count = self.lib.proc_listpids(2, child.pid, members, ctypes.sizeof(members))
        need(0 <= count < ctypes.sizeof(members) and count % ctypes.sizeof(ctypes.c_int) == 0 and
             ctypes.get_errno() == 0, 'owned_group_observation_failed')
        live = []
        for pid in members[:count // ctypes.sizeof(ctypes.c_int)]:
            if not pid or pid == child.pid:
                continue
            info = BSDInfo()
            got = self.lib.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
            if got != ctypes.sizeof(info):
                # A member may exit between enumeration and its owned-group query.
                need(ctypes.get_errno() in (0, 3), 'owned_group_member_unavailable')
                continue
            need(info.pid == pid and info.pgid == child.pid, 'owned_group_changed')
            if info.status != 5:  # SZOMB: terminated, awaiting its own parent's reap.
                live.append(pid)
        if live:
            child.fork_seen = True
        return live

    def signal_owned(self, child, number):
        need(not child.reaped and self.handles.get(child.pid) is child, 'ownership_not_retained')
        self.refresh()
        members = self.group_members(child)
        if child.exited and not members:
            return False
        if not child.exited:
            need(self.identity(child.pid) == child.identity, 'owned_generation_changed')
            need(self.executable(child.pid) in child.allowed_paths, 'unexpected_owned_executable')
        # Popen created a new session/group. Its directly owned leader remains
        # unreaped, reserving this group ID through descendant termination. This
        # cannot reach the separately session-owned sentinel or another prefix.
        try:
            os.killpg(child.pid, number)
        except ProcessLookupError:
            return False
        return True

    def close(self):
        self.queue.close()


class Child:
    def __init__(self, role, process, allowed_paths):
        self.role, self.process, self.pid = role, process, process.pid
        self.allowed_paths = {str(Path(path).resolve()) for path in allowed_paths}
        self.identity = None
        self.exited = self.fork_seen = self.reaped = False
        self.exit_code = None
        self.signals = []
        self.setup_error = None
        self.emergency_cleanup = None


class Session:
    """Bounded pipes plus directly owned children. Popen.poll is deliberately unused."""
    def __init__(self, output, observer=None):
        self.output = Path(output)
        self.observer = observer or DarwinObserver()
        self.selector = selectors.DefaultSelector()
        self.children, self.streams, self.events = {}, {}, {'server': [], 'loader': []}
        self.failure = None
        self.event_bytes = 0
        self.control = None

    def launch(self, role, argv, env, *, event_pipe=False, pass_fds=(), allowed_paths=None):
        need(role not in self.children, 'duplicate_process_role')
        read_fd = write_fd = None
        child_env = dict(env)
        if event_pipe:
            read_fd, write_fd = os.pipe()
            child_env['PEAR_BOOTSTRAP_FD'] = str(write_fd)
            pass_fds = (*pass_fds, write_fd)
        try:
            process = subprocess.Popen(argv, cwd=self.output, env=child_env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
                                       pass_fds=pass_fds, start_new_session=True)
        except OSError:
            if read_fd is not None:
                os.close(read_fd)
            raise Error('spawn_error') from None
        finally:
            if write_fd is not None:
                os.close(write_fd)
        child = Child(role, process, allowed_paths or [argv[0]])
        self.children[role] = child
        streams = [('stdout', process.stdout), ('stderr', process.stderr)]
        if read_fd is not None:
            streams.append(('events', os.fdopen(read_fd, 'rb', buffering=0)))
        try:
            self.observer.add(child)
            for channel, stream in streams:
                self.add_stream(role, channel, stream)
        except BaseException:
            child.setup_error = 'launch_observation_setup_failed'
            self.failure = self.failure or child.setup_error
            # Close both registered and not-yet-registered descriptors. A failed
            # stream registration must not strand the remaining pipe endpoints.
            for channel, stream in streams:
                try:
                    self.selector.unregister(stream)
                except (KeyError, ValueError):
                    pass
                stream.close()
                if (role, channel) in self.streams:
                    self.streams[(role, channel)]['eof'] = True
            child.emergency_cleanup = self.emergency_reap(child)
            raise Error(child.setup_error) from None
        return child

    @staticmethod
    def emergency_reap(child):
        """Terminal failure-only cleanup using kernel direct-child ownership.

        Session is the sole reaper and requires default SIGCHLD without
        SA_NOCLDWAIT. A waitpid return of zero retains this exact child's PID;
        an exited child is reaped once, and ECHILD forbids any subsequent signal.
        No successful runtime observation may be inferred from this fallback.
        """
        result = {'signals': [], 'errors': [], 'reaped': False}
        if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            result['errors'].append('external_child_reaping')
            return result
        for number, budget in [(signal.SIGTERM, 2), (signal.SIGKILL, 5)]:
            deadline, sent = time.monotonic() + budget, False
            while True:
                try:
                    pid, status = os.waitpid(child.pid, os.WNOHANG)
                except (ChildProcessError, OSError):
                    result['errors'].append('emergency_ownership_lost')
                    return result
                if pid == child.pid:
                    child.exit_code = os.waitstatus_to_exitcode(status)
                    child.process.returncode = child.exit_code
                    child.exited = child.reaped = result['reaped'] = True
                    return result
                if pid != 0:
                    result['errors'].append('emergency_wait_identity')
                    return result
                if not sent:
                    try:
                        os.kill(child.pid, number)
                        result['signals'].append(int(number))
                    except ProcessLookupError:
                        pass  # It may now be an unreaped zombie; only waitpid decides.
                    except OSError:
                        result['errors'].append('emergency_signal_refused')
                    sent = True
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.01)
        result['errors'].append('emergency_survivor')
        return result

    def add_stream(self, role, channel, stream):
        os.set_blocking(stream.fileno(), False)
        item = {'role': role, 'channel': channel, 'stream': stream, 'data': bytearray(),
                'pending': bytearray(), 'total_bytes': 0, 'eof': False}
        self.streams[(role, channel)] = item
        self.selector.register(stream, selectors.EVENT_READ, item)

    def pump(self, wait=0.02):
        self.observer.refresh()
        if any(child.fork_seen for child in self.children.values()):
            self.failure = self.failure or 'unexpected_descendant_observation_gap'
        for key, _ in self.selector.select(wait):
            item = key.data
            try:
                block = os.read(item['stream'].fileno(), 16384)
            except BlockingIOError:
                continue
            except OSError:
                self.failure = self.failure or 'pipe_read_error'
                block = b''
            if not block:
                item['eof'] = True
                self.selector.unregister(item['stream'])
                item['stream'].close()
                if item['channel'] == 'events' and item['pending']:
                    self.failure = self.failure or 'truncated_event'
                continue
            item['total_bytes'] += len(block)
            limit = EVENT_LIMIT if item['channel'] == 'events' else STREAM_LIMIT
            item['data'].extend(block[:max(0, limit + 1 - len(item['data']))])
            if item['channel'] == 'events':
                self.event_bytes += len(block)
            if item['total_bytes'] > limit or self.event_bytes > EVENT_LIMIT:
                self.failure = self.failure or 'output_limit'
                continue
            if item['channel'] == 'events':
                item['pending'].extend(block)
                while b'\n' in item['pending']:
                    line, _, remainder = item['pending'].partition(b'\n')
                    item['pending'] = bytearray(remainder)
                    try:
                        self.events[item['role']].append(decode_json(bytes(line), 32768))
                    except Error:
                        self.failure = self.failure or 'invalid_event'
                if len(item['pending']) > 32768:
                    self.failure = self.failure or 'event_line_limit'

    def wait_for(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        while True:
            self.pump(min(0.02, max(0, deadline - time.monotonic())))
            if self.failure:
                raise Error(self.failure)
            if predicate():
                return True
            if time.monotonic() >= deadline:
                return False

    def cleanup(self, roles, bounds, *, allow_interrupt=True):
        report = {'signals': [], 'errors': [], 'observation_gap': False, 'reaped': {}, 'complete': False}
        selected = [self.children[role] for role in roles if role in self.children]
        for child in selected:
            if child.setup_error:
                report['errors'].append({'role': child.role, 'code': child.setup_error})
                report['observation_gap'] = True
        # Server cleanup retains Wine's SIGINT/-k behavior by default. PE
        # clients can instead drain naturally: their SIGINT invokes Windows
        # CtrlRoutine and does not share the server's shutdown semantics.
        first_signal = signal.SIGINT if allow_interrupt else None
        for number, budget in [(first_signal, bounds['grace_ms']),
                               (signal.SIGTERM, bounds['terminate_ms']),
                               (signal.SIGKILL, bounds['kill_ms'])]:
            for child in selected:
                if child.reaped or number is None:
                    continue
                try:
                    if self.observer.signal_owned(child, number):
                        report['signals'].append({'role': child.role, 'signal': int(number)})
                except (Error, OSError) as exc:
                    report['errors'].append({'role': child.role, 'code': getattr(exc, 'code', 'signal_refused')})
            deadline = time.monotonic() + budget / 1000
            while time.monotonic() < deadline:
                try:
                    pending = [child for child in selected if not child.reaped and
                               (not child.exited or self.observer.group_members(child))]
                    if not pending:
                        break
                    self.pump(min(0.02, max(0, deadline - time.monotonic())))
                except (Error, OSError, KeyboardInterrupt):
                    report['errors'].append({'role': 'observer', 'code': 'cleanup_observation_failed'})
                    break
        for child in selected:
            if not child.reaped:
                try:
                    if self.observer.group_members(child):
                        report['errors'].append({'role': child.role, 'code': 'owned_group_survivor'})
                except Error:
                    report['errors'].append({'role': child.role, 'code': 'owned_group_observation_failed'})
            report['observation_gap'] |= child.fork_seen
            if child.exited and not child.reaped:
                try:
                    child.exit_code = child.process.wait(timeout=0)
                    child.reaped = True
                except (subprocess.TimeoutExpired, ChildProcessError):
                    report['errors'].append({'role': child.role, 'code': 'reap_failed'})
            report['reaped'][child.role] = child.reaped
        report['complete'] = not report['errors'] and not report['observation_gap'] and all(report['reaped'].values())
        return report

    def finish_logs(self, drain_ms):
        deadline = time.monotonic() + drain_ms / 1000
        while self.selector.get_map() and time.monotonic() < deadline:
            try:
                self.pump(min(0.02, max(0, deadline - time.monotonic())))
            except (Error, OSError, KeyboardInterrupt) as exc:
                self.failure = self.failure or getattr(exc, 'code', 'drain_observation_failed')
                break
        logs = []
        for (role, channel), item in self.streams.items():
            name = f'{role}.{channel}.log'
            write_error = None
            try:
                with (self.output / name).open('xb') as stream:
                    stream.write(item['data'])
            except OSError:
                write_error = 'log_write_failed'
                self.failure = self.failure or write_error
            logs.append({'role': role, 'channel': channel, 'path': name,
                         'sha256': hashlib.sha256(item['data']).hexdigest(),
                         'bytes': len(item['data']), 'observed_bytes': item['total_bytes'],
                         'eof': item['eof'], 'write_error': write_error})
            if not item['eof']:
                self.failure = self.failure or 'pipe_drain_incomplete'
            try:
                item['stream'].close()
            except OSError:
                self.failure = self.failure or 'pipe_close_failed'
        try:
            self.selector.close()
        except OSError:
            self.failure = self.failure or 'selector_close_failed'
        try:
            self.observer.close()
        except (Error, OSError):
            self.failure = self.failure or 'observer_close_failed'
        return logs


def event_identity(event, child, nonce):
    need(event.get('version') == 1 and type(event.get('version')) is int, 'event_version')
    need(event.get('role') == child.role and event.get('nonce') == nonce, 'event_scope')
    need(event.get('event') in PHASES, 'unknown_event')
    need(type(event.get('identity_error')) is int and event['identity_error'] == 0, 'event_identity_unavailable')
    need(all(event.get(key) == value and type(event.get(key)) is int for key, value in child.identity.items()),
         'event_process_identity')
    need(type(event.get('generation')) is int and event['generation'] in (0, 1), 'event_generation')


def native_snapshot(event, page):
    for key in ('cpu_type', 'translation_value', 'user_page', 'vm_page', 'kernel_error', 'kernel_page'):
        need(type(event.get(key)) is int, 'invalid_native_fact')
    error = event.get('translation_error', event.get('query_errno'))
    need(type(error) is int, 'invalid_native_fact')
    need(event.get('cpu_type') == MACH_ARM64, 'wrong_native_slice')
    need(event.get('translation_error', event.get('query_errno')) == 0 and
         event.get('translation_value') == 0, 'translation_not_proven')
    need(event.get('user_page') == page and event.get('vm_page') == page and
         event.get('kernel_error') == 0 and event.get('kernel_page') == 16384, 'page_geometry')


def validate_events(events, children, nonce, prefixes, expected):
    """Independently assess observed native events, never their producer's pass label."""
    for role in ('server', 'loader'):
        child = children[role]
        rows = events[role]
        need(rows, 'missing_process_events')
        generation, image_index, inventory_open = 0, 0, False
        for row in rows:
            event_identity(row, child, nonce)
            need(row['generation'] == generation, 'unannounced_generation')
            event = row['event']
            if event in SNAPSHOTS:
                need(all(type(row.get(key)) is int for key in
                         ('prefix_error', 'prefix_dev', 'prefix_ino', 'thread_main')), 'invalid_snapshot_fact')
                need(row['thread_main'] in (0, 1), 'invalid_thread_observation')
                native_snapshot(row, 4096 if role == 'loader' else 16384)
                need(row.get('prefix_error') == 0 and row.get('prefix_dev') == prefixes[role]['device'] and
                     row.get('prefix_ino') == prefixes[role]['inode'], 'wrong_prefix')
            if event == 'image':
                need(type(row.get('index')) is int and row['index'] == image_index, 'image_order')
                need(row.get('cpu_type') == MACH_ARM64 and isinstance(row.get('path'), str) and
                     Path(row['path']).is_absolute(), 'native_image_identity')
                need(isinstance(row.get('uuid'), str) and re.fullmatch('[0-9a-fA-F-]{32,36}', row['uuid']),
                     'native_image_uuid')
                image_index += 1
                inventory_open = True
            elif event == 'images_end':
                need(inventory_open and type(row.get('count')) is int and row['count'] == image_index, 'image_count')
                image_index, inventory_open = 0, False
            elif event == 'loader_reexec':
                need(role == 'loader' and generation == 0 and type(row.get('next_generation')) is int and row['next_generation'] == 1,
                     'invalid_reexecution')
                generation = 1
        need(not inventory_open, 'unfinished_image_inventory')
    server_rows, loader_rows = events['server'], events['loader']
    server_order = [row['event'] for row in server_rows if row['event'] != 'image']
    loader_order = [row['event'] for row in loader_rows if row['event'] != 'image']
    initial = ['loader_entry', 'ntdll_entry', 'loader_reexec', 'loader_entry', 'ntdll_entry']
    if expected == 'server_refused':
        need(server_order == ['server_ready', 'images_end'] and loader_order == initial + ['failure'],
             'unexpected_refusal_sequence')
    else:
        terminal = 'bootstrap_hold' if expected == 'timeout' else 'bootstrap_stop'
        need(server_order == ['server_ready', 'images_end', 'server_handshake'] and
             loader_order == initial + ['server_peer', 'server_handshake', 'bootstrap_native', 'memory',
                                       'images_end', terminal], 'unexpected_bootstrap_sequence')
    need(any(row['event'] == 'server_ready' for row in server_rows), 'missing_server_native_ready')
    if expected == 'server_refused':
        need(not any(row['event'] in ('server_handshake', 'bootstrap_stop') for row in loader_rows),
             'unexpected_server_acceptance')
        failures = [row for row in loader_rows if row['event'] == 'failure']
        need(len(failures) == 1 and failures[0].get('operation') == 'unowned_server_fallback' and
             type(failures[0].get('error')) is int and failures[0]['error'] == 1, 'missing_server_refusal')
        return
    server_handshakes = [row for row in server_rows if row['event'] == 'server_handshake']
    loader_handshakes = [row for row in loader_rows if row['event'] == 'server_handshake']
    need(len(server_handshakes) == len(loader_handshakes) == 1, 'missing_actual_handshake')
    server_handshake, loader_handshake = server_handshakes[0], loader_handshakes[0]
    need(server_handshake.get('peer_pid') == children['loader'].pid and
         loader_handshake.get('peer_pid') == children['server'].pid, 'wrong_server_peer')
    stamp = server_handshake.get('server_start')
    need(isinstance(stamp, str) and re.fullmatch('[1-9][0-9]{0,19}', stamp) and
         stamp == loader_handshake.get('server_start'), 'server_generation_mismatch')
    peers = [row for row in loader_rows if row['event'] == 'server_peer']
    need(len(peers) == 1 and type(peers[0].get('peer_error')) is int and peers[0]['peer_error'] == 0 and
         peers[0].get('peer_pid') == children['server'].pid, 'server_peer_query')
    need(any(row['event'] == 'loader_reexec' for row in loader_rows) and
         any(row['event'] == 'loader_entry' and row['generation'] == 1 for row in loader_rows),
         'missing_real_reexecution')
    need(any(row['event'] == 'ntdll_entry' for row in loader_rows) and
         any(row['event'] == 'bootstrap_native' and row.get('thread_main') == 0 for row in loader_rows),
         'missing_native_bootstrap')
    memory = [row for row in loader_rows if row['event'] == 'memory']
    need(len(memory) == 1, 'missing_memory_observation')
    memory = memory[0]
    need(all(type(memory.get(key)) is int for key in
             ('pagezero_address', 'pagezero_size', 'null_read_error', 'guard_end_read_error', 'low_address',
              'region_address', 'region_size', 'region_protection', 'region_error')), 'invalid_memory_fact')
    need(memory.get('pagezero_address') == 0 and memory.get('pagezero_size') == 65536 and
         type(memory.get('null_read_error')) is int and memory['null_read_error'] > 0 and
         type(memory.get('guard_end_read_error')) is int and memory['guard_end_read_error'] > 0,
         'null_guard_unproven')
    need(memory.get('low_address') == 0x7ffe0000 and memory.get('region_address') == 0x7ffe0000 and
         memory.get('region_size') == 4096 and memory.get('region_protection') == 1 and
         memory.get('region_error') == 0, 'owned_low_mapping_unproven')
    final = 'bootstrap_hold' if expected == 'timeout' else 'bootstrap_stop'
    terminals = [row for row in loader_rows if row['event'] == final]
    need(len(terminals) == 1, 'missing_bootstrap_terminal')
    if final == 'bootstrap_stop':
        need(terminals[0].get('pe_entered') is False and terminals[0].get('foreign_mode_entered') is False,
             'invalid_stage2_boundary')
    need(not any(row['event'] == 'failure' for row in server_rows + loader_rows), 'native_bootstrap_failure')


def prefix_identity(path):
    info = path.stat()
    namespace = Path('/private/tmp') / f'.wine-{os.getuid()}' / f'server-{info.st_dev:x}-{info.st_ino:x}'
    need(not namespace.exists() and not namespace.is_symlink(), 'preexisting_server_namespace')
    return {'device': info.st_dev, 'inode': info.st_ino, 'namespace': str(namespace)}


def parse_lines(session, role, channel='stdout'):
    data = session.streams[(role, channel)]['data']
    return [decode_json(line, 32768) for line in bytes(data).splitlines()]


def validate_helper(row, kind, child):
    need(row.get('record_kind') == kind and row.get('version') == 1, 'native_helper_record')
    need(all(row.get(key) == value for key, value in child.identity.items()), 'native_helper_identity')
    native_snapshot(row, 16384)


def validate_cases(cases):
    need(type(cases.get('schema_version')) is int and cases['schema_version'] == 1 and
         cases.get('record_kind') == 'wine_fixture_cases' and cases.get('suite') == 'bootstrap', 'unsupported_cases')
    expected = [
        {'id': 'bootstrap', 'mode': 'normal', 'timeout_ms': 120000, 'expected': 'bootstrap_stop'},
        {'id': 'bootstrap-timeout', 'mode': 'hold', 'timeout_ms': 1500, 'expected': 'timeout'},
        {'id': 'wrong-prefix-server', 'mode': 'wrong-prefix', 'timeout_ms': 30000, 'expected': 'server_refused'}]
    need(cases.get('cases') == expected and all(type(case['timeout_ms']) is int for case in cases['cases']),
         'unsupported_case_configuration')
    bounds = {'stdout_bytes': STREAM_LIMIT, 'stderr_bytes': STREAM_LIMIT, 'event_bytes': EVENT_LIMIT,
              'grace_ms': 3000, 'terminate_ms': 2000, 'kill_ms': 5000, 'drain_ms': 1000}
    need(cases.get('bounds') == bounds and all(type(value) is int for value in cases['bounds'].values()),
         'unsupported_runner_bounds')
    return cases


def bound_macho_uuid(path, expected_hash):
    """Bind a loaded owned image's UUID to the exact signed thin ARM64 bytes."""
    data = read_relative(path.parent, path.name, 1024 ** 3)
    need(hashlib.sha256(data).hexdigest() == expected_hash, 'unbound_loaded_image')
    need(len(data) >= 32 and data[:4] == b'\xcf\xfa\xed\xfe' and
         struct.unpack_from('<I', data, 4)[0] == MACH_ARM64, 'invalid_loaded_macho')
    commands, size = struct.unpack_from('<II', data, 16)
    need(commands <= 65536 and 32 + size <= len(data), 'invalid_loaded_commands')
    offset, found = 32, []
    for _ in range(commands):
        need(offset + 8 <= 32 + size, 'invalid_loaded_commands')
        kind, length = struct.unpack_from('<II', data, offset)
        need(length >= 8 and offset + length <= 32 + size, 'invalid_loaded_commands')
        if kind == 0x1b:
            need(length == 24, 'invalid_loaded_uuid')
            found.append(data[offset + 8:offset + 24].hex())
        offset += length
    need(offset == 32 + size and len(found) == 1, 'missing_loaded_uuid')
    return found[0]


def system_image_origin(observed, resolved):
    """Recognize OS library paths and their same-path OS Cryptex aliases.

    This is an origin policy, not independent signature/shared-cache attestation.
    A system-looking path resolving into arbitrary Preboot or user storage fails.
    """
    observed, resolved = Path(observed), Path(resolved)
    if not observed.is_absolute() or not resolved.is_absolute() or '..' in observed.parts or '..' in resolved.parts:
        return False
    roots = (Path('/usr/lib'), Path('/System/Library'))
    for root in roots:
        if not observed.is_relative_to(root) or observed == root:
            continue
        if any(resolved.is_relative_to(allowed) and resolved != allowed for allowed in roots):
            return True
        cryptex = Path('/System/Volumes/Preboot/Cryptexes/OS')
        return resolved == cryptex / observed.relative_to('/')
    return False


def validate_native_images(events, runtime, signed, expected):
    runtime = Path(runtime).resolve()
    known = {str((runtime / row['path']).resolve()): row for row in signed['native_images']}
    for role in ('server', 'loader'):
        rows = [row for row in events[role] if row['event'] == 'image']
        if role == 'loader' and expected == 'server_refused':
            need(not rows, 'unexpected_refusal_images')
            continue
        need(rows, 'missing_loaded_images')
        observed = set()
        for row in rows:
            path = Path(row['path']).resolve()
            if path.is_relative_to(runtime):
                need(str(path) in known and str(path) not in observed, 'unbound_loaded_image')
                native_uuid = bound_macho_uuid(path, known[str(path)]['sha256'])
                need(row.get('uuid', '').replace('-', '').lower() == native_uuid, 'loaded_uuid_mismatch')
                observed.add(str(path))
            else:
                need(system_image_origin(row['path'], path), 'external_loaded_image')
        expected_main = (runtime / signed['entrypoints'][role]).resolve()
        need(Path(rows[0]['path']).resolve() == expected_main and str(expected_main) in observed,
             'wrong_loaded_executable')
        if role == 'loader':
            need(str((runtime / signed['entrypoints']['ntdll']).resolve()) in observed, 'missing_loaded_ntdll')


def assess_case_record(result, raw_logs):
    """Reconstruct acceptance from source observations, ignoring passed/status labels.

    Caller binds case/config/runner/signed identities and verifies log bytes first.
    This pure function consumes those exact bytes; it never launches a process.
    """
    need(result.get('schema_version') == 1 and result.get('record_kind') == 'wine_bootstrap_case', 'case_record_version')
    need(result.get('error') is None and result.get('stream_error') is None, 'case_operation_failed')
    need(result.get('runtime_qualified') is False and result.get('pe_executed') is False, 'invalid_qualification')
    children = {role: SimpleNamespace(role=role, pid=row['identity']['pid'], identity=row['identity'])
                for role, row in result['processes'].items()}
    need(set(children) == {'server', 'loader', 'sentinel'}, 'process_coverage')
    for key, roles in [('cleanup', {'server', 'loader'}), ('sentinel_cleanup', {'sentinel'})]:
        cleanup = result[key]
        need(cleanup.get('errors') == [] and cleanup.get('observation_gap') is False and
             set(cleanup.get('reaped', {})) == roles and all(value is True for value in cleanup['reaped'].values()),
             'cleanup_incomplete')
        need(all(row.get('role') in roles and type(row.get('signal')) is int and
                 row['signal'] in (int(signal.SIGINT), int(signal.SIGTERM), int(signal.SIGKILL))
                 for row in cleanup['signals']), 'cleanup_signal_scope')
    need(result.get('sentinel_survived') is True and result['sentinel_cleanup']['signals'] == [],
         'unrelated_sentinel_lost')
    need(all(row.get('reaped') is True and row.get('fork_seen') is False
             for row in result['processes'].values()), 'process_cleanup_gap')
    lines = lambda role, channel: [decode_json(line, 32768) for line in raw_logs[(role, channel)].splitlines()]
    sentinel_rows = lines('sentinel', 'stdout')
    need(len(sentinel_rows) == 2, 'sentinel_record_count')
    validate_helper(sentinel_rows[0], 'pear_sentinel_ready', children['sentinel'])
    need(sentinel_rows[1] == {'version': 1, 'record_kind': 'pear_sentinel_done', 'signal': 0, 'command': 81} and
         result['processes']['sentinel']['exit_code'] == 0, 'unrelated_sentinel_changed')
    helper_rows = lines('loader', 'stdout')
    need(len(helper_rows) == 1, 'helper_record_count')
    validate_helper(helper_rows[0], 'pear_bootstrap_helper', children['loader'])
    for role in ('server', 'loader'):
        need(lines(role, 'events') == result['events'][role], 'event_log_mismatch')
    validate_events(result['events'], children, result['nonce'], result['prefixes'], result['case']['expected'])
    expected, outcome = result['case']['expected'], result['outcome']
    code = result['processes']['loader']['exit_code']
    if expected == 'timeout':
        need(outcome == 'timeout' and type(code) is int and code != 0, 'timeout_control_not_triggered')
    elif expected == 'server_refused':
        need(outcome == 'exited' and type(code) is int and code != 0, 'refusal_control_not_triggered')
    else:
        need(outcome == 'exited' and type(code) is int and code == 0, 'bootstrap_exit_failed')
    return True


def run_case(case, runtime, entrypoints, output, bounds):
    output.mkdir(mode=0o700)
    home, prefix = output / 'home', output / 'prefix'
    home.mkdir(mode=0o700)
    (home / 'tmp').mkdir(mode=0o700)
    prefix.mkdir(mode=0o700)
    server_prefix = prefix
    if case['mode'] == 'wrong-prefix':
        server_prefix = output / 'server-prefix'
        server_prefix.mkdir(mode=0o700)
    prefixes = {'server': prefix_identity(server_prefix), 'loader': prefix_identity(prefix)}
    nonce = uuid.uuid4().hex
    paths = {key: runtime.joinpath(*relative(value)) for key, value in entrypoints.items()}
    env = environment(home, prefix, nonce)
    session = Session(output)
    outcome, error = 'not_started', None
    cleanup, sentinel_cleanup = {}, {}
    read_fd, control = os.pipe()
    sentinel_survived = False
    start = time.monotonic()
    active_ms = 120000 if case['mode'] == 'hold' else case['timeout_ms']
    active_deadline = start + active_ms / 1000
    remaining = lambda ceiling: max(0, min(ceiling, active_deadline - time.monotonic()))
    try:
        sentinel = session.launch('sentinel', [str(paths['sentinel']), str(read_fd)], env, pass_fds=(read_fd,))
        os.close(read_fd)
        read_fd = None
        need(session.wait_for(lambda: b'\n' in session.streams[('sentinel', 'stdout')]['data'], remaining(5)),
             'sentinel_start_timeout')
        validate_helper(parse_lines(session, 'sentinel')[0], 'pear_sentinel_ready', sentinel)
        server_env = environment(home, server_prefix, nonce)
        server = session.launch('server', [str(paths['server']), '-f', '-p'], server_env, event_pipe=True)
        need(session.wait_for(lambda: any(row.get('event') == 'server_ready' for row in session.events['server'])
                             or server.exited, remaining(30)), 'server_start_timeout')
        need(not server.exited, 'server_early_exit')
        # Server-ready is only a scheduling event. Acceptance requires actual
        # init_first_thread events from both the selected server and Wine loader.
        for row in session.events['server']:
            event_identity(row, server, nonce)
        env['PEAR_BOOTSTRAP_SERVER_PID'] = str(server.pid)
        if case['mode'] == 'hold':
            env['PEAR_BOOTSTRAP_HOLD'] = '1'
        loader = session.launch('loader', [str(paths['bootstrap_helper']), '--exec-4k', str(paths['loader'])],
                                env, event_pipe=True, allowed_paths=[paths['bootstrap_helper'], paths['loader']])
        if case['mode'] == 'hold':
            need(session.wait_for(lambda: any(row.get('event') == 'bootstrap_hold' for row in session.events['loader'])
                                 or loader.exited, remaining(120)), 'bootstrap_arm_timeout')
            need(not loader.exited, 'bootstrap_early_exit')
        wait_budget = case['timeout_ms'] / 1000 if case['mode'] == 'hold' else remaining(case['timeout_ms'] / 1000)
        completed = session.wait_for(lambda: loader.exited, wait_budget)
        outcome = 'exited' if completed else 'timeout'
    except KeyboardInterrupt:
        outcome, error = 'interrupted', 'runner_interrupted'
    except (Error, OSError) as exc:
        outcome, error = 'error', getattr(exc, 'code', 'runner_os_error')
    finally:
        if read_fd is not None:
            os.close(read_fd)
        cleanup = session.cleanup(('loader', 'server'), bounds)
        if 'sentinel' in session.children:
            sentinel = session.children['sentinel']
            try:
                session.observer.refresh()
                sentinel_survived = not sentinel.exited and session.observer.identity(sentinel.pid) == sentinel.identity
                if sentinel_survived:
                    os.write(control, b'Q')
                    deadline = time.monotonic() + 3
                    while not sentinel.exited and time.monotonic() < deadline:
                        session.pump()
            except (Error, OSError):
                sentinel_survived = False
        os.close(control)
        sentinel_cleanup = session.cleanup(('sentinel',), bounds)
        logs = session.finish_logs(bounds['drain_ms'])
    assessment_error = None
    try:
        need(error is None and session.failure is None, error or session.failure or 'runner_error')
        need(cleanup.get('complete') and sentinel_cleanup.get('complete'), 'cleanup_incomplete')
        need(sentinel_survived, 'unrelated_sentinel_lost')
        sentinel_rows = parse_lines(session, 'sentinel')
        need(len(sentinel_rows) == 2 and sentinel_rows[1] ==
             {'version': 1, 'record_kind': 'pear_sentinel_done', 'signal': 0, 'command': 81} and
             session.children['sentinel'].exit_code == 0, 'unrelated_sentinel_changed')
        helper_rows = parse_lines(session, 'loader')
        need(helper_rows, 'missing_helper_observation')
        validate_helper(helper_rows[0], 'pear_bootstrap_helper', session.children['loader'])
        validate_events(session.events, session.children, nonce, prefixes, case['expected'])
        if case['expected'] == 'timeout':
            need(outcome == 'timeout', 'timeout_control_not_triggered')
        elif case['expected'] == 'server_refused':
            need(outcome == 'exited' and session.children['loader'].exit_code != 0, 'refusal_control_not_triggered')
        else:
            need(outcome == 'exited' and session.children['loader'].exit_code == 0, 'bootstrap_exit_failed')
    except (Error, KeyError) as exc:
        assessment_error = getattr(exc, 'code', 'missing_required_process')
    result = {'schema_version': 1, 'record_kind': 'wine_bootstrap_case', 'case': case,
              'nonce': nonce, 'prefixes': prefixes, 'outcome': outcome, 'error': error,
              'elapsed_ms': round((time.monotonic() - start) * 1000), 'stream_error': session.failure,
              'active_budget_ms': active_ms + (case['timeout_ms'] if case['mode'] == 'hold' else 0),
              'events': session.events, 'logs': logs, 'cleanup': cleanup,
              'sentinel_cleanup': sentinel_cleanup, 'sentinel_survived': sentinel_survived,
              'processes': {role: {'identity': child.identity, 'allowed_paths': sorted(child.allowed_paths),
                                  'exit_code': child.exit_code, 'reaped': child.reaped, 'fork_seen': child.fork_seen,
                                  'setup_error': child.setup_error, 'emergency_cleanup': child.emergency_cleanup}
                            for role, child in session.children.items()},
              'passed': assessment_error is None, 'assessment_error': assessment_error,
              'runtime_qualified': False, 'pe_executed': False,
              'ownership_scope': 'direct-children-and-their-reserved-session-groups',
              'observation_limitations': ['post-spawn-kqueue-registration', 'escaped-session-descendants-not-qualified']}
    if result['passed']:
        try:
            assess_case_record(result, {(role, channel): bytes(item['data'])
                                       for (role, channel), item in session.streams.items()})
        except (Error, KeyError, TypeError) as exc:
            result['passed'] = False
            result['assessment_error'] = getattr(exc, 'code', 'case_assessment_shape')
    write_new(output / 'case.json', result)
    return result


def run(suite, runtime, output, require_empty):
    if suite in ('api-abi', 'threads-memory-exceptions', 'mac-driver'):
        from api_runner import run as run_api
        return run_api(runtime, output, require_empty, suite)
    need(suite == 'bootstrap' and require_empty, 'explicit_bootstrap_empty_output_required')
    # Lazy import keeps portable data/lifecycle tests independent of signing tools.
    from signing import validate_prepared
    runtime = Path(runtime).resolve()
    signed = validate_prepared(runtime)  # Actual current grants and bytes; never injectable CLI receipts.
    for role in ('loader', 'server', 'bootstrap_helper', 'sentinel'):
        need(role in signed.get('entrypoints', {}), 'missing_signed_entrypoint')
    cases_path = REPO / 'tests/wine/cases.json'
    cases = load_json(cases_path)
    validate_cases(cases)
    output = create_output(output)
    results = []
    run_error = None
    for case in cases['cases']:
        case_result, gate_error = None, None
        try:
            need(validate_prepared(runtime) == signed, 'signed_runtime_changed')
            case_result = run_case(case, runtime, signed['entrypoints'], output / case['id'], cases['bounds'])
            need(validate_prepared(runtime) == signed, 'signed_runtime_changed')
            if case_result['passed']:
                validate_native_images(case_result['events'], runtime, signed, case['expected'])
        except KeyboardInterrupt:
            gate_error = 'runner_interrupted'
        except (Error, OSError) as exc:
            gate_error = getattr(exc, 'code', 'runner_os_error')
        if case_result is None:
            run_error = gate_error or 'case_not_recorded'
            break
        results.append(write_case_assessment(output, case['id'], case_result, gate_error))
        if gate_error or case_result['outcome'] == 'interrupted':
            run_error = gate_error or 'runner_interrupted'
            break
    result = {'schema_version': 1, 'record_kind': 'wine_bootstrap_run', 'suite': suite,
              'cases_sha256': sha256(cases_path), 'runner_sha256': sha256(Path(__file__)),
              'runtime_path': runtime.relative_to(REPO.resolve()).as_posix(),
              'producer_sha256': producer_hashes(), 'error': run_error,
              'signed_sha256': sha256(runtime / 'signed.json'),
              'cases': results, 'passed': run_error is None and len(results) == len(cases['cases']) and
                                        all(row['passed'] for row in results),
              'runtime_qualified': False, 'pe_executed': False}
    write_new(output / 'run.json', result)
    return result


def write_case_assessment(output, case_id, case_result, gate_error):
    """Keep completed raw observations immutable when a later authorization gate fails."""
    need('/' not in case_id, 'unsafe_case_id')
    relative(case_id)
    path = case_id + '/case.json'
    passed = case_result['passed'] and gate_error is None
    assessment = {'schema_version': 1, 'record_kind': 'wine_case_gate_assessment',
                  'case_sha256': sha256(output / path), 'passed': passed,
                  'error': gate_error or case_result['assessment_error']}
    assessment_path = case_id + '/assessment.json'
    write_new(output / assessment_path, assessment)
    return {'id': case_id, 'path': path, 'sha256': assessment['case_sha256'],
            'assessment_path': assessment_path, 'assessment_sha256': sha256(output / assessment_path),
            'passed': passed}


def producer_hashes():
    return {name: sha256(REPO / name) for name in
            ('tools/wine/run_fixtures.py', 'tests/wine/cases.json',
             'tests/wine/fixtures/bootstrap_native.c', 'tests/wine/fixtures/sentinel.c')}


def verify_case_logs(root, case_id, result):
    """Read only exact owned bounded log leaves; return bytes for semantic checks."""
    relative(case_id)
    need('/' not in case_id, 'unsafe_case_id')
    logs = result.get('logs')
    required = {(role, channel) for role in ('loader', 'server', 'sentinel') for channel in ('stdout', 'stderr')}
    required |= {('loader', 'events'), ('server', 'events')}
    need(isinstance(logs, list) and len(logs) == len(required) and
         {(log.get('role'), log.get('channel')) for log in logs} == required, 'log_coverage')
    raw_logs, event_bytes = {}, 0
    for log in logs:
        role, channel = log['role'], log['channel']
        leaf = role + '.' + channel + '.log'
        need(log.get('path') == leaf, 'log_path_mismatch')
        cap = EVENT_LIMIT if channel == 'events' else STREAM_LIMIT
        data = read_relative(root, case_id + '/' + leaf, cap)
        need(type(log.get('bytes')) is int and log['bytes'] == len(data) and
             type(log.get('observed_bytes')) is int and log['observed_bytes'] == len(data) and
             log.get('sha256') == hashlib.sha256(data).hexdigest() and log.get('eof') is True and
             log.get('write_error') is None,
             'log_integrity_mismatch')
        raw_logs[(role, channel)] = data
        if channel == 'events':
            event_bytes += len(data)
        need(not data or channel != 'events' or data.endswith(b'\n'), 'truncated_event_log')
    need(event_bytes <= EVENT_LIMIT, 'event_output_limit')
    return raw_logs


def _validate_runs(root, suite='bootstrap'):
    """Validate retained local evidence against current signed bytes and exact logs.

    This is evidence consistency, not cryptographic proof of historical execution.
    Returns a public-safe assessment containing no paths, PIDs, nonces or profiles.
    """
    from signing import owned, validate_prepared
    root = owned(root)
    need(suite == 'bootstrap', 'unsupported_run_suite')
    raw_run = read_relative(root, 'run.json')
    run_record = decode_json(raw_run)
    need(type(run_record.get('schema_version')) is int and run_record['schema_version'] == 1 and
         run_record.get('record_kind') == 'wine_bootstrap_run' and run_record.get('suite') == suite,
         'run_record_version')
    cases = validate_cases(load_json(REPO / 'tests/wine/cases.json'))
    need(run_record.get('producer_sha256') == producer_hashes() and
         run_record.get('runner_sha256') == sha256(Path(__file__)) and
         run_record.get('cases_sha256') == sha256(REPO / 'tests/wine/cases.json'), 'stale_run_producer')
    runtime = owned(REPO.joinpath(*relative(run_record.get('runtime_path'))))
    signed = validate_prepared(runtime)
    need(run_record.get('signed_sha256') == sha256(runtime / 'signed.json'), 'changed_signed_record')
    need(run_record.get('error') is None, 'run_operation_failed')
    need(run_record.get('runtime_qualified') is False and run_record.get('pe_executed') is False,
         'invalid_run_qualification')
    expected_cases = {case['id']: case for case in cases['cases']}
    rows = run_record.get('cases')
    need(isinstance(rows, list) and len(rows) == len(expected_cases) and
         [row.get('id') for row in rows] == list(expected_cases), 'run_case_coverage')
    summaries, nonces, prefixes_seen = [], set(), set()
    for row in rows:
        case_id, expected = row['id'], expected_cases[row['id']]
        name = case_id + '/case.json'
        need(row.get('path') == name, 'case_path_mismatch')
        raw_case = read_relative(root, name)
        need(hashlib.sha256(raw_case).hexdigest() == row.get('sha256'), 'changed_case_record')
        assessment_path = case_id + '/assessment.json'
        need(row.get('assessment_path') == assessment_path, 'case_assessment_path')
        assessment_bytes = read_relative(root, assessment_path)
        need(hashlib.sha256(assessment_bytes).hexdigest() == row.get('assessment_sha256'), 'case_assessment_changed')
        assessment = decode_json(assessment_bytes)
        need(assessment == {'schema_version': 1, 'record_kind': 'wine_case_gate_assessment',
                            'case_sha256': row['sha256'], 'passed': True, 'error': None}, 'case_gate_failed')
        result = decode_json(raw_case)
        need(result.get('case') == expected, 'case_configuration_mismatch')
        nonce = result.get('nonce')
        need(isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce) and nonce not in nonces,
             'case_nonce_reuse')
        nonces.add(nonce)
        for role in ('server', 'loader'):
            directory = case_id + '/' + ('server-prefix' if role == 'server' and expected['mode'] == 'wrong-prefix'
                                         else 'prefix')
            fd = open_relative(root, directory, directory=True)
            try:
                info = os.fstat(fd)
            finally:
                os.close(fd)
            namespace = str(Path('/private/tmp') / f'.wine-{os.getuid()}' / f'server-{info.st_dev:x}-{info.st_ino:x}')
            need(result['prefixes'][role] == {'device': info.st_dev, 'inode': info.st_ino, 'namespace': namespace},
                 'changed_owned_prefix')
            if role == 'loader':
                need((info.st_dev, info.st_ino) not in prefixes_seen, 'prefix_generation_reuse')
                prefixes_seen.add((info.st_dev, info.st_ino))
        raw_logs = verify_case_logs(root, case_id, result)
        processes = result.get('processes', {})
        need(set(processes) == {'server', 'loader', 'sentinel'}, 'process_coverage')
        identities = [value.get('identity') for value in processes.values()]
        need(all(isinstance(identity, dict) and set(identity) == {'pid', 'ppid', 'start_sec', 'start_usec'} and
                 all(type(value) is int and value >= 0 for value in identity.values()) and identity['pid'] > 1 and
                 identity['ppid'] > 1 and identity['start_sec'] > 0 and identity['start_usec'] < 1000000
                 for identity in identities), 'invalid_process_identity')
        need(len({identity['pid'] for identity in identities}) == 3 and
             len({identity['ppid'] for identity in identities}) == 1, 'direct_process_ownership')
        for role, process in processes.items():
            names = [role] if role != 'loader' else ['bootstrap_helper', 'loader']
            paths = sorted(str((runtime / signed['entrypoints'][name]).resolve()) for name in names)
            need(process.get('allowed_paths') == paths, 'changed_process_executables')
        budget = 121500 if expected['mode'] == 'hold' else expected['timeout_ms']
        need(type(result.get('active_budget_ms')) is int and result['active_budget_ms'] == budget and
             type(result.get('elapsed_ms')) is int and 0 <= result['elapsed_ms'] <= budget + 16000,
             'unbounded_case_duration')
        if expected['mode'] == 'hold':
            need(result['elapsed_ms'] >= expected['timeout_ms'], 'timeout_duration_unproven')
        assess_case_record(result, raw_logs)
        validate_native_images(result['events'], runtime, signed, expected['expected'])
        need(result.get('passed') is True and row.get('passed') is True, 'case_label_mismatch')
        summaries.append({'id': case_id, 'expected': expected['expected'], 'outcome': result['outcome'],
                          'case_sha256': row['sha256'], 'passed': True,
                          'native_process_count': 3, 'reexecution_count': 1,
                          'actual_handshake': expected['expected'] != 'server_refused',
                          'cleanup_complete': True, 'sentinel_survived': True})
    need(run_record.get('passed') is True, 'run_label_mismatch')
    need(validate_prepared(runtime) == signed, 'signed_runtime_changed')
    return {'schema_version': 1, 'record_kind': 'wine_bootstrap_assessment', 'suite': suite,
            'run_sha256': hashlib.sha256(raw_run).hexdigest(), 'signed_sha256': run_record['signed_sha256'],
            'producer_sha256': producer_hashes(), 'case_count': len(summaries), 'cases': summaries,
            'passed': True, 'pe_executed': False, 'runtime_qualified': False,
            'evidence_scope': 'retained-local-native-bootstrap-consistency'}


def validate_runs(root, suite='bootstrap'):
    try:
        if suite in ('api-abi', 'threads-memory-exceptions', 'mac-driver'):
            from api_runner import validate_runs as validate_api
            return validate_api(root, suite)
        return _validate_runs(root, suite)
    except Error:
        raise
    except (KeyError, TypeError, ValueError, OSError, AttributeError):
        raise Error('invalid_run_evidence') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=['bootstrap', 'api-abi', 'threads-memory-exceptions', 'mac-driver'], required=True)
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--require-empty', action='store_true')
    args = parser.parse_args()
    try:
        result = run(args.suite, args.runtime, args.output, args.require_empty)
        label = 'Native bootstrap' if args.suite == 'bootstrap' else 'Instrumented Windows API/ABI'
        print(label + (' checks passed.' if result['passed'] else ' checks failed; evidence preserved.'))
        return 0 if result['passed'] else 1
    except KeyboardInterrupt:
        print('runner_interrupted', file=sys.stderr)
        return 1
    except (Error, OSError, ValueError, KeyError, TypeError) as exc:
        print(getattr(exc, 'code', 'runner_operation_failed'), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
