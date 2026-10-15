# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only planning and explicitly requested development candidate assembly."""
from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stdout, redirect_stderr
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import threading
import uuid

from pear_runtime import build
from pear_runtime.errors import Error, need
from . import core

GLOBAL_LOCK = Path('/private/tmp/pear-native-compilation.lock')
REQUEST_LIMIT = 8 * 1024**2
INPUT_FIELDS = {'parent_ref', 'builds', 'roles', 'profile_ref', 'helper_root',
                'output_root', 'name', 'disk_floor_bytes'}


def read_request(path):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink(),
         'assembly_request_path')
    need(stat.S_ISREG(path.stat().st_mode) and path.stat().st_size <= REQUEST_LIMIT, 'assembly_request_size')
    ref = build.fact(path)
    value = build.load(path)
    need(build.fact(path) == ref, 'assembly_request_changed')
    need(type(value) is dict and set(value) == {'schema_version', 'scope', 'inputs', 'expected_signing_recipe', 'limits'}
         and type(value['schema_version']) is int and value['schema_version'] == 1
         and value['scope'] == 'development_candidate_assembly', 'assembly_request_shape')
    row = value['inputs']
    need(type(row) is dict and set(row) == INPUT_FIELDS and type(row['builds']) is list
         and type(row['roles']) is list and type(row['helper_root']) is str and type(row['output_root']) is str,
         'assembly_request_inputs')
    builds, refs = [], [ref]
    for item in row['builds']:
        need(type(item) is dict and set(item) == {'ref','recipe_sha256','source_commits','recipe_review'},
             'assembly_recipe_review_shape')
        review = item['recipe_review']
        need(type(review) is dict and set(review) == {'mode','public_recipe_ref','bindings_ref','private_manifest_ref'}
             and review['mode'] in ('file_sha256','expanded_dict_sha256'), 'assembly_recipe_review_shape')
        refs.extend((review['public_recipe_ref'], review['bindings_ref']))
        if review['mode'] == 'expanded_dict_sha256':
            need(type(review['private_manifest_ref']) is dict, 'assembly_private_recipe_review')
            refs.append(review['private_manifest_ref'])
        else: need(review['private_manifest_ref'] is None, 'assembly_private_recipe_review')
        builds.append({k:item[k] for k in ('ref','recipe_sha256','source_commits')})
    inputs = core.AssemblyInputs(**{**row, 'builds': tuple(builds), 'roles': tuple(row['roles']),
                                   'helper_root': Path(row['helper_root']), 'output_root': Path(row['output_root']),
                                   'review_refs':tuple(refs)})
    recipe = value['expected_signing_recipe']
    need(type(recipe) is list and recipe and len(recipe) <= 4096 and all(
        type(c) is dict and set(c) == {'id', 'argv'} and type(c['id']) is str
        and type(c['argv']) is list and c['argv'] and all(type(a) is str and '\0' not in a for a in c['argv'])
        for c in recipe), 'assembly_request_signing_recipe')
    limits = value['limits']
    need(type(limits) is dict and set(limits) == {'whole_timeout_seconds', 'worker_log_bytes'}
         and type(limits['whole_timeout_seconds']) is int and 1 <= limits['whole_timeout_seconds'] <= 21600
         and type(limits['worker_log_bytes']) is int and 256 <= limits['worker_log_bytes'] <= 64 * 1024**2,
         'assembly_request_limits')
    return value, inputs, ref


def validate_recipe_reviews(value, plan):
    """Expected recipe identity is supplied independently, never read as its own proof."""
    for request, receipt in zip(value['inputs']['builds'], plan['builds']):
        review = request['recipe_review']
        public = core.read_ref(review['public_recipe_ref'])
        bindings = core.read_ref(review['bindings_ref'])
        bound = bindings.get('roots', bindings)
        need(type(public.get('roots')) is dict and type(bound) is dict
             and set(bound) == set(public['roots']) == set(receipt['roots']), 'assembly_recipe_root_set')
        commits = {name:r['commit'] for name,r in public['roots'].items() if r['kind'] == 'git'}
        need(commits == request['source_commits'], 'assembly_public_source_pins')
        for name, row in bound.items():
            path = row.get('path') if type(row) is dict else row
            need(type(path) is str and receipt['roots'][name]['path'] == path, 'assembly_build_binding')
        if review['mode'] == 'file_sha256':
            need(request['recipe_sha256'] == review['public_recipe_ref']['sha256'], 'assembly_file_recipe_hash')
        else:
            # FEX's private_recipe expands the public JSON with an exact local
            # private-input manifest. The reviewer supplies the expanded dict
            # digest; merely accepting the receipt's own digest would be circular.
            core.checked_ref(review['private_manifest_ref'], limit=core.JSON_LIMIT)
            need(receipt.get('public_recipe') == review['public_recipe_ref'] and
                 receipt.get('private_manifest') == review['private_manifest_ref'] and
                 receipt.get('bindings_manifest') == review['bindings_ref'],
                 'assembly_expanded_recipe_provenance')


def review(value, inputs, request_ref):
    """No lock, mkdir, process-group change, native command or signing call."""
    plan = core.inspect_inputs(inputs)
    validate_recipe_reviews(value, plan)
    recipe = value['expected_signing_recipe']
    signers = []
    for row in recipe:
        if '--sign' in row['argv']:
            at = row['argv'].index('--sign')
            need(at + 1 < len(row['argv']), 'assembly_request_signing_recipe')
            signers.append(row['argv'][at + 1])
    need(signers and len(set(signers)) == 1, 'assembly_request_signing_identity')
    expected = [{'id': ident, 'argv': ['/usr/bin/arch', '-arm64', *argv]}
                for ident, argv in plan['helpers'].signing_recipe(plan['output'], plan['old']['native_images'], signers[0])]
    need(recipe == expected, 'attach_sign_exact_recipe')
    operation = inputs.output_root / (inputs.name + '.assembly-operation')
    need(not operation.exists() and not operation.is_symlink(), 'assembly_operation_exists')
    # Candidate admission already keeps this same output parent separate from
    # input roots. This additional sibling must also stay outside every input.
    roots = [plan['parent'], plan['source_pack'].root, Path(inputs.profile_ref['path']).parent,
             *(Path(r['ref']['path']).parent for r in inputs.builds)]
    need(all(not operation.is_relative_to(p) and not p.is_relative_to(operation) for p in roots),
         'assembly_operation_overlaps_input')
    total_peak = plan['storage']['additional_peak_bytes'] + value['limits']['worker_log_bytes'] + 1024**2
    core.checked_ref(request_ref, limit=REQUEST_LIMIT)
    return plan, dict(schema_version=1, scope='development_candidate_assembly_plan',
        request_ref=request_ref, output=str(plan['output']), operation_output=str(operation),
        replacement_roles=list(inputs.roles), signing_command_count=len(recipe),
        static_signing_recipe_sha256=hashlib.sha256(json.dumps(recipe, sort_keys=True).encode()).hexdigest(),
        limits=value['limits'], storage={**plan['storage'], 'worker_additional_peak_bytes': total_peak},
        builder_sources=plan['builder_sources'], recipe_review_refs=list(inputs.review_refs), current_authority_assessed=False,
        signing_performed=False, runtime_execution_performed=False, permission_admitted=False)


@contextmanager
def lease():
    started = build.point()
    fd = os.open(GLOBAL_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    acquired = False
    try:
        need(stat.S_ISREG(os.fstat(fd).st_mode), 'assembly_lock_not_regular')
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise Error('assembly_operation_busy') from None
        acquired = True
        point = build.point()
        yield dict(path=str(GLOBAL_LOCK), acquisition_started=started, acquired=point,
                   acquisition_seconds=point['monotonic_seconds'] - started['monotonic_seconds'])
    finally:
        if acquired: fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


@contextmanager
def deadline(seconds):
    """One worker deadline; existing command cleanup runs while unwinding it."""
    need(threading.current_thread() is threading.main_thread(), 'assembly_worker_main_thread')
    need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'assembly_existing_deadline')
    previous = signal.getsignal(signal.SIGALRM)
    def expired(signum, frame): raise Error('assembly_worker_timeout')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try: yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class LogBudget:
    def __init__(self, limit): self.limit, self.written = limit, 0


class BoundedLog(io.TextIOBase):
    """Aggregate Python worker diagnostics bound; native commands have own bounds."""
    def __init__(self, stream, budget): self.stream, self.budget = stream, budget
    @property
    def encoding(self): return 'utf-8'
    def writable(self): return True
    def write(self, value):
        raw = value.encode('utf-8', errors='backslashreplace')
        remaining = max(0, self.budget.limit - self.budget.written)
        kept = raw[:remaining]
        self.stream.write(kept); self.stream.flush(); self.budget.written += len(kept)
        need(len(raw) <= remaining, 'assembly_worker_log_limit')
        return len(value)
    def flush(self):
        if not self.stream.closed: self.stream.flush()


def execute(value, inputs, request_ref):
    """Called only in this CLI's owned worker process group; no game execution."""
    need(os.getpgrp() == os.getpid(), 'signing_worker_group_required')
    started = build.point(); operation = None; record = None; error = None; runtime_ref = None
    # The one-shot deadline covers lock/admission/copy/sign/final verification.
    # Existing owned-command cleanup has a separate maximum 5-second reap wait.
    try:
        with deadline(value['limits']['whole_timeout_seconds']), lease() as held:
            admission_started = build.point()
            plan, reviewed = review(value, inputs, request_ref)
            need(core.shutil.disk_usage(inputs.output_root).free >= reviewed['storage']['worker_additional_peak_bytes']
                 + inputs.disk_floor_bytes, 'assembly_worker_storage')
            admission_phase = build.span('worker_input_admission', admission_started)
            operation = Path(reviewed['operation_output']); operation.mkdir(mode=0o700)
            record = dict(schema_version=1, scope='development_candidate_assembly_operation',
                operation_id=str(uuid.uuid4()), status='running', request_ref=request_ref, plan=reviewed,
                worker={'pid': os.getpid(), 'process_group': os.getpgrp()},
                lock={**held, 'released': False}, phases=[admission_phase],
                intervals=[], runtime_ref=None, runtime_execution_performed=False, game_qualified=False)
            build.write_json(operation / 'operation.json', record)
            @contextmanager
            def interval(kind, output):
                need(kind == 'assembly-sign' and Path(output) == plan['output'], 'assembly_live_interval_scope')
                core.checked_ref(request_ref, limit=REQUEST_LIMIT)
                need(core.builder_sources() == reviewed['builder_sources'], 'assembly_builder_changed')
                point = build.point()
                try: yield
                finally: record['intervals'].append(build.span(kind, point))
            budget = LogBudget(value['limits']['worker_log_bytes'])
            with (operation/'stdout.log').open('xb') as stdout, (operation/'stderr.log').open('xb') as stderr:
                with redirect_stdout(BoundedLog(stdout, budget)), redirect_stderr(BoundedLog(stderr, budget)):
                    runtime_ref = core.assemble(inputs, interval=interval,
                                                expected_signing_recipe=value['expected_signing_recipe'],
                                                operation_binding={'path':str(operation/'operation.json'),
                                                                   'operation_id':record['operation_id']})
            for ref in inputs.review_refs: core.checked_ref(ref, limit=core.JSON_LIMIT)
            need(core.builder_sources() == reviewed['builder_sources'], 'assembly_builder_changed')
            record.update(status='passed', runtime_ref=runtime_ref)
    except BaseException as failure:
        error = failure
        if record is not None: record.update(status='failed', error=core.failure_details(failure))
        raise
    finally:
        if record is not None:
            record['lock'].update(released=True, release_observed=build.point())
            record['timing'] = build.span('assembly_worker_before_final_receipt', started)
            record['logs'] = {}
            for name in ('stdout','stderr'):
                path = operation/(name+'.log')
                if not path.is_file(): continue
                try: record['logs'][name] = build.fact(path)
                except BaseException as evidence:
                    record.setdefault('evidence_errors',[]).append(core.failure_details(evidence))
                    if error is None: raise
            record['receipt_write_started'] = build.point()
            try: build.write_json(operation/'operation.json', record)
            except BaseException:
                if error is None: raise
    return dict(status='passed', runtime_ref=runtime_ref, operation_ref=build.fact(operation/'operation.json'),
                runtime_execution_performed=False, game_qualified=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('inspect', 'plan', 'execute'))
    parser.add_argument('--request', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        value, inputs, ref = read_request(args.request)
        if args.command in ('inspect', 'plan'):
            _, result = review(value, inputs, ref)
        else:
            # Only this newly launched assembly CLI changes its own group.
            if os.getpgrp() != os.getpid(): os.setpgid(0, 0)
            result = execute(value, inputs, ref)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({'status':'failed', 'error':core.failure_details(error),
                          'runtime_execution_performed':False}), file=sys.stderr)
        return 1
