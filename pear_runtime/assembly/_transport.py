# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""D36 bounded transport adapted to reap an owned command process group.

Retains stream limits, failure evidence and the outer worker guard. Each Apple
command owns a separate group so an exited leader cannot leave descendants
holding pipes; normal and exceptional exits terminate that group. SIGTERM/INT
reach the same cleanup path while the worker is alive.
"""
from pathlib import Path
import os, selectors, signal, subprocess, time
# The factory supplies original.Error/need and clean_env in the captured namespace.


def run_bounded(argv, *, cwd=None, timeout=60, limit=32*1024**2, env=None, log_directory=None):
    need = original.need
    need(isinstance(argv, list) and argv and all(type(a) is str and '\0' not in a for a in argv), 'command_arguments')
    need(os.getpgrp() == os.getpid(), 'signing_worker_group_required')
    started = time.monotonic_ns(); process = None; selector = selectors.DefaultSelector()
    chunks = {'stdout': bytearray(), 'stderr': bytearray()}
    timed_out = limited = False; failure = None; code = None; previous = {}; evidence_errors = []
    def secondary(error):
        nonlocal failure
        if failure is None: failure = error
        else:
            detail = dict(type=type(error).__name__, code=getattr(error, "code", str(error)))
            if isinstance(error, OSError): detail["errno"] = error.errno
            evidence_errors.append(detail)
    def interrupted(signum, frame):
        raise KeyboardInterrupt('owned signing worker interrupted')
    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, interrupted)
        process = subprocess.Popen(argv, cwd=cwd, env=clean_env() if env is None else env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        for stream, label in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
            os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map() or process.poll() is None:
            if time.monotonic_ns() - started > timeout * 1_000_000_000:
                timed_out = True; break
            for key, _ in selector.select(.05):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data: selector.unregister(key.fileobj)
                else:
                    chunks[key.data].extend(data)
                    if sum(map(len, chunks.values())) > limit:
                        limited = True; break
            if limited: break
    except BaseException as error:
        failure = error
    finally:
        selector.close()
        if process is not None:
            # Deliberately do not condition this on leader poll(): descendants
            # can outlive the leader while retaining inherited output pipes.
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            try: code = process.wait(timeout=5)
            except BaseException as error: secondary(error)
            finally: process.stdout.close(); process.stderr.close()
        for signum, handler in previous.items(): signal.signal(signum, handler)
    result = dict(argv=argv, exit_code=code, timed_out=timed_out, output_limit=limited,
        elapsed_ms=(time.monotonic_ns()-started)//1_000_000, stdout=bytes(chunks['stdout']), stderr=bytes(chunks['stderr']))
    if failure is None and (timed_out or limited):
        failure = original.Error('command_bound')
        failure.bound_outcome = {k: result[k] for k in ('timed_out', 'output_limit', 'elapsed_ms')}
    if log_directory is not None:
        try:
            directory = Path(log_directory); need(directory.is_dir() and not directory.is_symlink(), 'command_log_directory')
            for stream in ('stdout', 'stderr'):
                with (directory/stream).open('xb') as output: output.write(result[stream])
        except BaseException as error: secondary(error)
    if failure is not None:
        if evidence_errors: failure.evidence_errors = evidence_errors
        raise failure
    return result
