# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Inspect or execute one fixed CPU19/ordering development case under one lease."""
from __future__ import annotations

import argparse
from contextlib import contextmanager,redirect_stdout,redirect_stderr
import json
import os
import signal
from pathlib import Path
import sys
import uuid

from pear_runtime import build
from pear_runtime.errors import need
from pear_runtime.assembly import core
from pear_runtime.assembly.driver import lease,deadline,BoundedLog,LogBudget
from . import cpu_execution
from .cpu_context import CPUContext,CASES,descriptor
from .cpu_evidence import OPTIONS
from pear_runtime.fixtures.types import Selection

REQUEST_FIELDS={'schema_version','scope','descriptor_ref','case_id','output_name','limits'}
LIMIT_FIELDS={'whole_timeout_seconds','worker_log_bytes'}


def request(path):
    path=Path(path);ref=build.fact(path);value=core.read_ref(ref)
    need(type(value) is dict and set(value)==REQUEST_FIELDS and
         type(value['schema_version']) is int and value['schema_version']==1 and
         value['scope']=='development_cpu_verification','cpu_request_shape')
    need(type(value['case_id']) is str and value['case_id'] in CASES,'cpu_request_case')
    name=value['output_name']
    need(type(name) is str and name and name not in ('.','..') and
         all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in name),'cpu_request_output')
    limits=value['limits']
    need(type(limits) is dict and set(limits)==LIMIT_FIELDS and
         type(limits['whole_timeout_seconds']) is int and 120<=limits['whole_timeout_seconds']<=1800 and
         type(limits['worker_log_bytes']) is int and 1024<=limits['worker_log_bytes']<=16*1024**2,
         'cpu_request_limits')
    value_descriptor,base=descriptor(value['descriptor_ref'])
    candidate=Selection('d25-game',Path(base['runtime_ref']['path']).parent)
    core.checked_ref(ref)
    return value,ref,value_descriptor,candidate


def review(path):
    value,ref,m,candidate=request(path)
    @contextmanager
    def no_execution(output):
        need(False,'cpu_inspection_cannot_execute')
        yield
    context=CPUContext(value['descriptor_ref'],candidate,no_execution)
    output=context.fresh_output(Path(m['output_root'])/value['output_name'])
    operation=output.with_name(output.name+'.cpu-operation')
    need(not operation.exists() and not operation.is_symlink(),'cpu_operation_exists')
    storage=context.storage_admission(output)
    plan=dict(schema_version=1,scope='development_cpu_plan',request_ref=ref,
        descriptor_ref=value['descriptor_ref'],runtime_ref=context.base['runtime_ref'],
        case_id=value['case_id'],output=str(output),operation_output=str(operation),
        options=OPTIONS,limits=value['limits'],storage=storage,
        current_authority_assessed=False,runtime_execution_performed=False,game_qualified=False)
    return value,ref,context,plan


@contextmanager
def interrupts():
    """Unwind the original owned session on an externally requested stop."""
    previous={}
    def stopped(signum,frame):
        raise KeyboardInterrupt('owned fixture worker interrupted')
    try:
        for signum in (signal.SIGINT,signal.SIGTERM):
            previous[signum]=signal.signal(signum,stopped)
        yield
    finally:
        for signum,handler in previous.items():signal.signal(signum,handler)


def execute(path):
    """Use original APISession for every runtime process under one live lease."""
    need(os.getpgrp()==os.getpid(),'cpu_worker_group_required')
    initial,initial_ref,_,_=request(path)
    started=build.point();record=None;operation=None;error=None;entered=False
    try:
        with interrupts(),deadline(initial['limits']['whole_timeout_seconds']),lease() as held:
            value,ref,context,plan=review(path)
            need(ref==initial_ref and value==initial,'cpu_request_changed')
            output=Path(plan['output']);operation=Path(plan['operation_output'])
            operation.mkdir(mode=0o700)
            record=dict(schema_version=1,scope='development_cpu_operation',
                operation_id=str(uuid.uuid4()),status='running',request_ref=ref,plan=plan,
                worker=dict(pid=os.getpid(),process_group=os.getpgrp(),
                    interpreter_ref=build.fact(Path(sys.executable).resolve(strict=True)),
                    interpreter_version=sys.version,argv=list(sys.argv)),
                lock={**held,'released':False},intervals=[],runtime_execution_attempted=False,
                runtime_execution_performed=False,game_qualified=False)
            build.write_json(operation/'operation.json',record)
            @contextmanager
            def interval(actual):
                nonlocal entered
                need(not entered and Path(actual)==output,'cpu_live_interval_scope')
                core.checked_ref(ref);core.checked_ref(value['descriptor_ref'])
                entered=True;point=build.point()
                try:yield
                finally:record['intervals'].append(build.span('current_authority_owned_execution_cleanup',point))
            context.execution_interval=interval
            budget=LogBudget(value['limits']['worker_log_bytes'])
            with (operation/'stdout.log').open('xb') as stdout,(operation/'stderr.log').open('xb') as stderr:
                with redirect_stdout(BoundedLog(stdout,budget)),redirect_stderr(BoundedLog(stderr,budget)):
                    record['runtime_execution_attempted']=True
                    result=cpu_execution.run(context,value['case_id'],output)
            need(entered and result['passed'] is True,'cpu_operation_incomplete')
            context.finalize_assessment(output)
            core.checked_ref(ref);core.checked_ref(value['descriptor_ref'])
            record.update(status='passed',result_ref=build.fact(output/'cpu-assessment.json'),
                          timings=context.timings)
    except BaseException as failure:
        error=failure
        if record is not None:record.update(status='failed',error=core.failure_details(failure))
        raise
    finally:
        if record is not None:
            evidence_failure=None
            def evidence_error(failure):
                nonlocal evidence_failure
                record.setdefault('evidence_errors',[]).append(core.failure_details(failure))
                if error is None and evidence_failure is None:
                    evidence_failure=failure
                    record.update(status='failed',error=core.failure_details(failure))
            record['lock'].update(released=True,release_observed=build.point())
            record['timing']=build.span('cpu_worker_before_final_receipt',started)
            case=Path(record['plan']['output'])/'case.json'
            if case.is_file():
                try:
                    value=build.load(case)
                    record['case_ref']=build.fact(case)
                    record['runtime_execution_performed']=bool(value.get('launches'))
                    record['cleanup']=value.get('cleanup')
                    record['sentinel_survived']=value.get('sentinel_survived')
                except BaseException as failure:
                    evidence_error(failure)
                    record['runtime_execution_performed']='unknown'
            elif entered:record['runtime_execution_performed']='unknown'
            record['logs']={}
            for name in ('stdout','stderr'):
                log=operation/(name+'.log')
                if log.is_file():
                    try:record['logs'][name]=build.fact(log)
                    except BaseException as evidence:
                        evidence_error(evidence)
            try:build.write_json(operation/'operation.json',record)
            except BaseException as write_error:
                if error is None and evidence_failure is None:raise
                (error if error is not None else evidence_failure).add_note(
                    'Final operation receipt write also failed: '+getattr(write_error,'code',type(write_error).__name__))
            if error is None and evidence_failure is not None:raise evidence_failure
    return dict(status='passed',operation_ref=build.fact(operation/'operation.json'),
                result_ref=record['result_ref'],runtime_execution_performed=record['runtime_execution_performed'],
                game_qualified=False)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('inspect','execute','compare'))
    parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args(argv)
    try:
        if args.command=='compare':
            from .cpu_evidence import compare_index
            need(args.output is not None,'cpu_comparison_output_required')
            output=args.output
            need(output.is_absolute() and output.parent.resolve(strict=True)==output.parent and
                 not output.exists() and not output.is_symlink(),'cpu_comparison_fresh_output')
            result=compare_index(build.fact(args.request))
            build.write_json(output,result)
        elif args.command=='inspect':
            need(args.output is None,'cpu_inspect_output_option')
            result=review(args.request)[3]
        else:
            need(args.output is None,'cpu_execute_output_option')
            if os.getpgrp()!=os.getpid():os.setpgid(0,0)
            result=execute(args.request)
        print(json.dumps(result,indent=2,sort_keys=True));return 0
    except (Exception,KeyboardInterrupt) as failure:
        print(json.dumps(dict(status='failed',error=core.failure_details(failure))),file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
