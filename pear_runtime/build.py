# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit-input development builds; no candidate execution or authorization.

Component drivers preserve their recorded compiler/linker recipes. This module
checks named roots, exact inputs, owned output, storage and a live operation lock.
Receipts contain local paths and must remain outside source/release artifacts.
"""
from __future__ import annotations

from contextlib import suppress
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time
import uuid

from .errors import Error, need

KINDS = {'git', 'input', 'toolchain', 'sdk', 'private', 'host'}
HEX = re.compile(r'[0-9a-f]{64}\Z')


def load(path, *, with_bytes=False):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'build_duplicate_json_key')
            result[key] = value
        return result
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode), 'build_json_not_regular')
        limit = 64 * 1024**2
        need(before.st_size <= limit, 'build_json_size')
        chunks, count = [], 0
        while chunk := os.read(fd, min(1024**2, limit + 1 - count)):
            chunks.append(chunk)
            count += len(chunk)
            need(count <= limit, 'build_json_size')
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(all(getattr(before, key) == getattr(after, key) == getattr(path.lstat(), key)
                 for key in fields), 'build_json_changed')
        raw = b''.join(chunks)
    finally:
        os.close(fd)
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(Error('build_json_number')))
    return (value, raw) if with_bytes else value


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def fact(path):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode), 'build_input_not_regular')
        sha = hashlib.sha256()
        while chunk := os.read(fd, 1024**2):
            sha.update(chunk)
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(all(getattr(before, k) == getattr(after, k) for k in fields), 'build_input_changed')
        current = path.lstat()
        need(all(getattr(after, k) == getattr(current, k) for k in fields), 'build_input_replaced')
        return dict(path=str(path), sha256=sha.hexdigest(), size_bytes=after.st_size)
    finally:
        os.close(fd)


def point():
    return dict(monotonic_seconds=time.monotonic(),
                wall_utc=datetime.now(timezone.utc).isoformat())


def span(name, started):
    ended = point()
    return dict(name=name, started=started, ended=ended,
                seconds=ended['monotonic_seconds'] - started['monotonic_seconds'])


def relative(value):
    need(type(value) is str and value and '\\' not in value and '\x00' not in value,
         'build_relative_path')
    path = Path(value)
    need(not path.is_absolute() and '..' not in path.parts and str(path) == value,
         'build_relative_path')
    return path


def parse_depfile(path):
    """Read the first Make dependency rule, including escaped spaces and dollars."""
    text = Path(path).read_text().replace('\\\r\n', '').replace('\\\n', '')
    line = text.splitlines()[0] if text else ''
    escaped = False
    split = None
    for i, char in enumerate(line):
        if char == ':' and not escaped:
            split = i
            break
        if char == '\\' and not escaped:
            escaped = True
        else:
            escaped = False
    need(split is not None, 'build_depfile_rule')
    values, token, escaped = [], '', False
    for char in line[split + 1:]:
        if escaped:
            token += char
            escaped = False
        elif char == '\\':
            escaped = True
        elif char.isspace():
            if token:
                values.append(token.replace('$$', '$'))
                token = ''
        else:
            token += char
    need(not escaped, 'build_depfile_escape')
    if token:
        values.append(token.replace('$$', '$'))
    need(values, 'build_depfile_empty')
    return values


class Context:
    """A fresh output and exclusive live lease for one reviewed component recipe."""
    def __init__(self, recipe, bindings, output, *, lock_path='/private/tmp/pear-native-compilation.lock'):
        if isinstance(recipe, (str, Path)):
            self.recipe, raw = load(recipe, with_bytes=True)
        else:
            self.recipe = recipe
            raw = json.dumps(recipe, sort_keys=True).encode()
        self.recipe_sha256 = hashlib.sha256(raw).hexdigest()
        bindings = load(bindings) if isinstance(bindings, (str, Path)) else bindings
        need(type(bindings) is dict and type(self.recipe) is dict, 'build_recipe_shape')
        self.bindings = bindings.get('roots', bindings)
        need(type(self.bindings) is dict, 'build_root_bindings')
        need(self.recipe.get('schema_version') == 1 and type(self.recipe.get('name')) is str,
             'build_recipe_shape')
        definitions = self.recipe.get('roots')
        need(type(definitions) is dict and definitions and set(definitions) == set(self.bindings),
             'build_root_bindings')
        self.roots = {}
        for name, definition in definitions.items():
            need(type(name) is str and re.fullmatch(r'[a-z][a-z0-9_]*', name)
                 and type(definition) is dict and definition.get('kind') in KINDS,
                 'build_root_definition')
            need('path' not in definition, 'build_root_reserved_field')
            bound = self.bindings[name]
            bound = bound['path'] if isinstance(bound, dict) else bound
            path = Path(bound)
            need(path.is_absolute() and path.is_dir() and path.resolve(strict=True) == path
                 and path != Path('/'), 'build_root_alias')
            self.roots[name] = path
        self.output = Path(output).absolute()
        need(not self.output.exists() and not self.output.is_symlink(), 'build_output_exists')
        need(self.output.parent.resolve(strict=True) == self.output.parent, 'build_output_parent_alias')
        need(all(not self.output.is_relative_to(root) and not root.is_relative_to(self.output)
                 for root in self.roots.values()), 'build_output_overlaps_input')
        self.lock_path = Path(lock_path)
        self.inputs = {}
        need(type(self.recipe.get('inputs', [])) is list, 'build_inputs_shape')
        for row in self.recipe.get('inputs', []):
            need(type(row) is dict, 'build_input_shape')
            need(row.get('root') in self.roots, 'build_input_root')
            rel = str(relative(row['path']))
            key = (row['root'], rel)
            need(key not in self.inputs, 'build_duplicate_input')
            if row.get('kind', 'file') == 'symlink':
                need(type(row.get('target')) is str, 'build_link_target')
            else:
                need(HEX.fullmatch(row.get('sha256', '')) and type(row.get('size_bytes')) is int
                     and row['size_bytes'] >= 0, 'build_input_identity')
            self.inputs[key] = row
        self.timings = []
        self.commands = []
        self.outputs = {}
        self.dependencies = []
        self._lock = None
        self._entered = False
        self._finished = False
        self._last_cwd = self.output
        self.operation_id = str(uuid.uuid4())

    def root(self, name):
        need(name in self.roots, 'build_unknown_root')
        return self.roots[name]

    def _source(self, name, path):
        root = self.root(name)
        definition = self.recipe['roots'][name]
        need(definition['kind'] == 'git', 'build_undeclared_input')
        rel = path.relative_to(root).as_posix()
        listing = subprocess.run(['git', '-C', str(root), 'ls-tree', definition['commit'], '--', rel],
                                 capture_output=True, check=True, text=True).stdout
        need(listing.startswith(('100644 blob ', '100755 blob ')), 'build_untracked_source_input')
        original = subprocess.run(['git', '-C', str(root), 'show', definition['commit'] + ':' + rel],
                                  capture_output=True, check=True).stdout
        current = fact(path)
        need(current['sha256'] == hashlib.sha256(original).hexdigest(), 'build_source_changed')
        return current

    def input(self, name, rel, expected_sha256=None):
        rel = str(relative(rel))
        path = self.root(name) / rel
        need(path.resolve(strict=True).is_relative_to(self.root(name)), 'build_input_escape')
        row = self.inputs.get((name, rel))
        if row is not None and row.get('kind') == 'symlink':
            need(path.is_symlink() and os.readlink(path) == row['target'], 'build_link_changed')
            target = path.resolve(strict=True)
            current = self._admit_path(target)
            need(expected_sha256 is None or current['sha256'] == expected_sha256, 'build_expected_input')
            return path
        need(not path.is_symlink(), 'build_input_alias')
        current = fact(path)
        if row is None:
            current = self._source(name, path)
        else:
            need(current['sha256'] == row['sha256'] and current['size_bytes'] == row['size_bytes'],
                 'build_input_mismatch')
            if 'mode' in row:
                need(stat.S_IMODE(path.stat().st_mode) == row['mode'], 'build_input_mode')
        need(expected_sha256 is None or expected_sha256 == current['sha256'], 'build_expected_input')
        return path

    def _admit_path(self, path):
        path = Path(path).absolute()
        resolved = path.resolve(strict=True)
        if path.is_relative_to(self.output):
            rel = path.relative_to(self.output).as_posix()
            need(resolved.is_relative_to(self.output) and rel in self.outputs, 'build_unrecorded_generated_input')
            need(fact(path) == self.outputs[rel], 'build_generated_input_changed')
            return fact(path)
        for name, root in sorted(self.roots.items(), key=lambda row: len(str(row[1])), reverse=True):
            if path.is_relative_to(root):
                self.input(name, path.relative_to(root).as_posix())
                return fact(resolved)
        raise Error('build_undeclared_dependency')

    def validate_inputs(self):
        for name, definition in self.recipe['roots'].items():
            if definition['kind'] != 'git':
                continue
            commit = definition.get('commit', '')
            need(re.fullmatch(r'[0-9a-f]{40}', commit), 'build_source_commit')
            root = self.root(name)
            head = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
            need(head == commit, 'build_source_commit_mismatch')
            result = subprocess.run(['git', '-C', str(root), 'diff', '--quiet', commit, '--'])
            need(result.returncode == 0, 'build_source_dirty')
        for name, rel in self.inputs:
            self.input(name, rel)

    def __enter__(self):
        started = point()
        budget = self.recipe.get('budget', {})
        required = budget.get('additional_bytes')
        floor = budget.get('floor_bytes')
        need(type(required) is int and required >= 0 and type(floor) is int and floor >= 0,
             'build_storage_budget')
        need(shutil.disk_usage(self.output.parent).free >= required + floor, 'build_storage_unavailable')
        self.timings.append(span('storage_preflight', started))
        started = point()
        self._lock = self.lock_path.open('a+')
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._lock.close()
            self._lock = None
            raise Error('build_operation_busy')
        self.timings.append(span('coordination_acquire', started))
        try:
            started = point()
            self.validate_inputs()
            need(shutil.disk_usage(self.output.parent).free >= required + floor, 'build_storage_unavailable')
            self.timings.append(span('input_admission', started))
            self.output.mkdir(mode=0o700)
            (self.output / 'logs').mkdir()
            (self.output / 'tmp').mkdir()
            self._entered = True
            write_json(self.output / 'operation.json', dict(operation_id=self.operation_id,
                       scope='task56_component_build', pid=os.getpid(), released=False))
            return self
        except BaseException:
            self._release()
            raise

    def path(self, rel):
        path = self.output / relative(rel)
        need(path.resolve().is_relative_to(self.output), 'build_output_escape')
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def copy_input(self, name, rel, output_relative):
        source = self.input(name, rel).resolve(strict=True)
        destination = self.path(output_relative)
        need(not destination.exists() and not destination.is_symlink(), 'build_copy_output_exists')
        with source.open('rb') as src, destination.open('xb') as dst:
            shutil.copyfileobj(src, dst, 1024**2)
        shutil.copystat(source, destination)
        need(fact(source)['sha256'] == fact(destination)['sha256'], 'build_copy_mismatch')
        self.record_output(output_relative)
        return destination

    def record_output(self, rel):
        path = self.output / relative(rel)
        need(path.resolve(strict=True).is_relative_to(self.output) and not path.is_symlink(),
             'build_output_alias')
        self.outputs[rel] = fact(path)
        return self.outputs[rel]

    def _check_argument_paths(self, argv):
        prefixes = ('-I', '-L', '-F', '-isystem', '--sysroot=', '--gcc-toolchain=')
        for item in argv:
            candidate = item
            for prefix in prefixes:
                if item.startswith(prefix) and item[len(prefix):].startswith('/'):
                    candidate = item[len(prefix):]
                    break
            if not candidate.startswith('/'):
                continue
            path = Path(candidate)
            need(path.is_relative_to(self.output) or any(path.is_relative_to(p) for p in self.roots.values()),
                 'build_undeclared_argument_path')
            if path.exists() and path.is_file():
                self._admit_path(path)

    def run(self, ident, argv, cwd=None, env=None, timeout=600, max_output_bytes=16 * 1024**2):
        need(self._entered and not self._finished, 'build_not_active')
        need(re.fullmatch(r'[A-Za-z0-9_-]+', ident) and not any(c['id'] == ident for c in self.commands),
             'build_command_id')
        need(type(argv) is list and argv and all(type(a) is str and '\x00' not in a for a in argv),
             'build_command_argv')
        need(type(timeout) in (int, float) and timeout > 0 and type(max_output_bytes) is int
             and max_output_bytes > 0, 'build_command_budget')
        cwd = Path(cwd or self.output).absolute()
        need(cwd.is_dir() and cwd.resolve(strict=True) == cwd and cwd.is_relative_to(self.output),
             'build_command_cwd')
        # Preserve the admitted executable spelling, including declared driver aliases.
        # Relative operands would resolve through a different cwd or PATH at spawn.
        need(Path(argv[0]).is_absolute(), 'build_executable_absolute')
        self._admit_path(Path(argv[0]))
        self._check_argument_paths(argv)
        environment = dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LANG='C', LC_ALL='C',
                           TMPDIR=str(self.output / 'tmp'))
        environment.update(env or {})
        need(all(type(k) is str and type(v) is str for k, v in environment.items()), 'build_environment')
        logs = {channel: self.output / 'logs' / (ident + '.' + channel) for channel in ('stdout', 'stderr')}
        row = dict(id=ident, argv=argv, cwd=str(cwd), env=environment, exit_code=None,
                   error=None, logs={}, timeout_seconds=timeout, max_output_bytes=max_output_bytes)
        self.commands.append(row)
        row['started'] = point()
        start = row['started']['monotonic_seconds']
        process = None
        streams = {}
        try:
            streams = {name: path.open('xb') for name, path in logs.items()}
            process = subprocess.Popen(argv, cwd=cwd, env=environment, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
            total = 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
                selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
                while selector.get_map():
                    need(time.monotonic() - start < timeout, 'build_command_timeout')
                    for key, _ in selector.select(0.1):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        allowed = max(0, max_output_bytes - total)
                        streams[key.data].write(chunk[:allowed])
                        total += len(chunk)
                        need(total <= max_output_bytes, 'build_command_output_limit')
                row['exit_code'] = process.wait(timeout=max(0.01, timeout - (time.monotonic() - start)))
            need(row['exit_code'] == 0, 'build_command_failed')
        except BaseException as exc:
            row['error'] = getattr(exc, 'code', type(exc).__name__)
            if process is not None:
                # The leader may have exited while descendants still own its pipes.
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            if process is not None:
                row['exit_code'] = process.returncode
            raise
        finally:
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            for stream in streams.values():
                stream.close()
            row['logs'] = {name: fact(path) for name, path in logs.items() if path.exists()}
            row['ended'] = point()
            row['elapsed_seconds'] = row['ended']['monotonic_seconds'] - start
            write_json(self.output / 'commands.json', self.commands)
        self._last_cwd = cwd
        return row

    def audit_depfile(self, path, cwd=None):
        cwd = Path(cwd or self._last_cwd)
        checked = []
        for value in parse_depfile(path):
            source = Path(value)
            if not source.is_absolute():
                source = cwd / source
            source = Path(os.path.abspath(source))
            checked.append(self._admit_path(source))
        self.dependencies.append(dict(depfile=fact(path), files=checked))
        return checked

    def finish(self, status, comparisons=None, extra=None):
        need(status in ('passed', 'failed') and self._entered and not self._finished, 'build_finish_state')
        started = point()
        if status == 'passed':
            need(all(c['exit_code'] == 0 and c['error'] is None for c in self.commands), 'build_failed_commands')
            self.validate_inputs()
            for rel, expected in self.outputs.items():
                need(fact(self.output / rel) == expected, 'build_output_changed')
            for command in self.commands:
                for expected in command['logs'].values():
                    need(fact(expected['path']) == expected, 'build_log_changed')
            for dependency in self.dependencies:
                expected = dependency['depfile']
                need(fact(expected['path']) == expected, 'build_depfile_changed')
        self.timings.append(span('final_validation', started))
        receipt = dict(schema_version=1, scope='development_component_build', status=status,
                       phase_times=self.timings,
                       operation_id=self.operation_id, recipe_sha256=self.recipe_sha256,
                       roots={k: dict(path=str(v), **self.recipe['roots'][k]) for k, v in self.roots.items()},
                       inputs=list(self.inputs.values()), commands=self.commands, outputs=self.outputs,
                       dependencies=self.dependencies, comparisons=comparisons or {},
                       runtime_eligible=False, game_qualified=False)
        need(not set(extra or {}) & set(receipt), 'build_receipt_override')
        receipt.update(extra or {})
        write_json(self.output / 'build.json', receipt)
        self._finished = True
        return receipt

    def _release(self):
        if self._lock is not None:
            fcntl.flock(self._lock, fcntl.LOCK_UN)
            self._lock.close()
            self._lock = None

    def __exit__(self, kind, value, traceback):
        try:
            if self._entered:
                try:
                    if not self._finished:
                        self.finish('failed')
                finally:
                    write_json(self.output / 'operation.json', dict(operation_id=self.operation_id,
                               scope='task56_component_build', pid=os.getpid(), released=True))
        finally:
            self._release()
