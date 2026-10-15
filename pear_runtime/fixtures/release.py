# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent read-only post-worker process, handle and coordination release check.

No runtime process is launched, signaled or reaped. The existing global flock is
only probed and immediately released, without creating or rewriting its file.
"""
from __future__ import annotations
import argparse
import ast
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from pear_runtime import build
from pear_runtime.assembly import core
from pear_runtime.assembly.driver import GLOBAL_LOCK
from pear_runtime.errors import Error,need

FIELDS={'schema_version','scope','operations'}
ROLES={'loader','server','sentinel'}


def identity(row):
    need(type(row) is dict and set(row)=={'pid','ppid','start_sec','start_usec'} and
         all(type(x) is int for x in row.values()) and row['pid']>1 and row['ppid']>1 and
         row['start_sec']>0 and 0<=row['start_usec']<1000000,'release_identity')
    return {k:row[k] for k in ('pid','start_sec','start_usec')}


def inputs(request_ref):
    value=core.read_ref(request_ref)
    need(type(value) is dict and set(value)==FIELDS and type(value['schema_version']) is int and
         value['schema_version']==1 and value['scope']=='development_fixture_release' and
         type(value['operations']) is list and 1<=len(value['operations'])<=16,'release_request')
    refs=[request_ref];roots=[];identities={};workers=set();groups={};statuses=[]
    for ref in value['operations']:
        operation=core.read_ref(ref);refs.append(ref)
        need(operation['scope']=='development_fixture_operation' and operation['status'] in ('passed','failed') and
             operation['lock']['released'] is True and operation['lock']['path']==str(GLOBAL_LOCK),
             'release_operation_incomplete')
        worker=operation['worker']
        need(type(worker['pid']) is int and worker['pid']>1 and worker['process_group']==worker['pid'],
             'release_worker_identity')
        workers.add(worker['pid']);groups.setdefault(worker['pid'],None)
        output=Path(operation['plan']['output']);oproot=Path(operation['plan']['operation_output'])
        need(output.is_absolute() and output.resolve(strict=True)==output and output.is_dir() and
             oproot.is_absolute() and oproot.resolve(strict=True)==oproot and oproot.is_dir() and
             ref['path']==str(oproot/'operation.json'),'release_output_binding')
        roots.extend((output,oproot))
        case_ref=operation.get('case_ref')
        need(type(case_ref) is dict and case_ref['path']==str(output/'case.json'),'release_case_unavailable')
        case=core.read_ref(case_ref);refs.append(case_ref)
        need(set(case['processes'])==ROLES and type(case['registrations']) is list and case['registrations'],
             'release_process_evidence_incomplete')
        need(case['runtime_ref']==operation['plan']['runtime_ref'] and
             case['diagnostic_fixture']['name']==operation['plan']['fixture'], 'release_case_binding')
        for role,row in case['processes'].items():
            current=identity(row['identity'])
            need(row['identity']['ppid']==worker['pid'],'release_worker_parent')
            prior=groups.setdefault(current['pid'],current)
            need(prior==current,'release_group_identity_conflict')
        for row in [*case['processes'].values(),*case['registrations']]:
            current=identity(row['identity']);key=(current['pid'],current['start_sec'],current['start_usec'])
            identities[key]=current
        statuses.append({'operation_ref':ref,'original_status':operation['status'],'case_ref':case_ref})
    need(len({r['path'] for r in value['operations']})==len(value['operations']),'release_duplicate_operation')
    return dict(refs=refs,roots=sorted(set(roots)),identities=list(identities.values()),
                workers=sorted(workers),groups=groups,operations=statuses)


class DarwinProbe:
    """Reuse original BSDInfo layout; query identities/groups without signaling."""
    def __init__(self):
        need(sys.platform=='darwin','release_host_unavailable')
        root=Path(__file__).resolve().parents[2]
        rel='pear_runtime/providers/pear_legacy/tools/wine/run_fixtures.py'
        source=root/rel;raw=source.read_bytes();self.source_ref=build.fact(source)
        manifest=core.read_ref(build.fact(root/'provenance/fixture-provider-import.json'))
        row=next(r for r in manifest['files'] if r['destination']==rel)
        need(row['sha256']==self.source_ref['sha256']==hashlib.sha256(raw).hexdigest() and row['size_bytes']==len(raw),'release_provider_changed')
        node=next(n for n in ast.parse(raw).body if isinstance(n,ast.ClassDef) and n.name=='BSDInfo')
        namespace={'ctypes':ctypes};exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),namespace)
        self.Info=namespace['BSDInfo'];self.lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
        self.lib.proc_pidinfo.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int]
        self.lib.proc_pidinfo.restype=ctypes.c_int
        self.lib.proc_listpids.argtypes=[ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_int]
        self.lib.proc_listpids.restype=ctypes.c_int
        core.checked_ref(self.source_ref)

    def pids(self,kind=1,group=0):
        for capacity in (4096,16384,65536):
            rows=(ctypes.c_int*capacity)();ctypes.set_errno(0)
            count=self.lib.proc_listpids(kind,group,rows,ctypes.sizeof(rows))
            need(count>=0 and ctypes.get_errno()==0 and count%ctypes.sizeof(ctypes.c_int)==0,'release_pid_query')
            if count<ctypes.sizeof(rows):return sorted(set(p for p in rows[:count//ctypes.sizeof(ctypes.c_int)] if p>0))
        raise Error('release_pid_query_truncated')

    def info(self,pid):
        row=self.Info();ctypes.set_errno(0)
        count=self.lib.proc_pidinfo(pid,3,0,ctypes.byref(row),ctypes.sizeof(row))
        if count==0 and ctypes.get_errno() in (0,errno.ESRCH) and pid not in self.pids():return None
        need(count==ctypes.sizeof(row) and row.pid==pid,'release_identity_query')
        return {'pid':row.pid,'start_sec':row.start_sec,'start_usec':row.start_usec,'pgid':row.pgid,'status':row.status}

    def observe(self,plan):
        pids=set(self.pids());need(pids,'release_empty_pid_census')
        present={pid:self.info(pid) for pid in sorted({r['pid'] for r in plan['identities']}|set(plan['workers'])) if pid in pids}
        groups={pid:[self.info(member) for member in self.pids(2,pid)] for pid in plan['groups']}
        core.checked_ref(self.source_ref)
        return dict(processes=present,groups={pid:[r for r in rows if r is not None] for pid,rows in groups.items()},provider_ref=self.source_ref)


def handles(roots):
    tool=Path('/usr/sbin/lsof');tool_ref=build.fact(tool)
    result=subprocess.run([str(tool),'-nP','-F0pfn'],capture_output=True,timeout=20,check=False)
    need(len(result.stdout)<=16*1024**2 and len(result.stderr)<=1024**2,'release_handle_output_limit')
    need(result.returncode==0 and not result.stderr,'release_handles_unavailable')
    found=[];pid=None;fd=None;seen=False
    for field in result.stdout.split(b'\0'):
        field=field.lstrip(b'\n')
        if not field:continue
        tag=field[:1];value=field[1:].decode('utf-8',errors='surrogateescape')
        if tag==b'p':need(value.isdecimal(),'release_handle_shape');pid=int(value);fd=None;seen=True
        elif tag==b'f':fd=value
        elif tag==b'n':
            need(pid is not None and fd is not None,'release_handle_shape')
            path=value.removesuffix(' (deleted)')
            if any(path==str(root) or path.startswith(str(root)+'/') for root in roots):
                found.append(dict(pid=pid,fd=fd,path=value))
    need(seen,'release_handles_empty_census')
    need(build.fact(tool)==tool_ref,'release_handle_tool_changed')
    return dict(handles=found,tool_ref=tool_ref)


def lock_probe():
    fd=os.open(GLOBAL_LOCK,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    acquired=False
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode),'release_lock_not_regular')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);acquired=True
        except BlockingIOError:return {'available':False,'immediately_released':False}
        current=GLOBAL_LOCK.lstat()
        need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
             (current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns),'release_lock_changed')
    finally:
        if acquired:fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)
    return {'available':True,'immediately_released':True}


def resource_verdict(plan,observed,handle_result):
    """Original resource oracle, independent of how coordination is owned."""
    survivors=[];reused=[];unknown=[];group_survivors=[]
    for expected in plan['identities']:
        actual=observed['processes'].get(expected['pid'])
        if actual is None:continue
        if all(actual[k]==expected[k] for k in ('pid','start_sec','start_usec')):survivors.append(expected)
        else:reused.append(dict(expected=expected,actual=actual))
    for pid in plan['workers']:
        if observed['processes'].get(pid) is not None:
            unknown.append(dict(reason='worker_pid_present_without_recorded_birthtime',pid=pid))
    for pid,rows in observed['groups'].items():
        if not rows:continue
        known={(r['pid'],r['start_sec'],r['start_usec']) for r in plan['identities']}
        owned=[r for r in rows if (r['pid'],r['start_sec'],r['start_usec']) in known]
        group_survivors.extend(owned)
        if len(owned)!=len(rows):unknown.append(dict(reason='group_members_without_original_identity',group=pid,members=rows))
    failed=bool(survivors or group_survivors or handle_result['handles'])
    status='failed' if failed else 'unknown' if unknown else 'passed'
    return dict(status=status,resource_release_passed=status=='passed',original_identities_present=survivors,
                original_group_members_present=group_survivors,reused_pids=reused,uncertain_observations=unknown,
                handles=handle_result['handles'])


def verdict(plan,observed,handle_result,lock):
    result=resource_verdict(plan,observed,handle_result)
    if not lock['available']:
        result.update(status='failed',resource_release_passed=False)
    return dict(result,lock=lock)


def inspect(request_ref):
    record=dict(schema_version=1,scope='development_fixture_independent_release',request_ref=request_ref,
                status='unknown',resource_release_passed=False,game_qualified=False,
                runtime_processes_signaled=False,runtime_execution_performed=False,checked_at=build.point())
    source_ref=build.fact(Path(__file__).resolve());record['checker_ref']=source_ref
    provenance=Path(__file__).resolve().parents[2]/'provenance/fixture-release-import.json'
    provenance_ref=build.fact(provenance);record['provenance_ref']=provenance_ref
    try:
        plan=inputs(request_ref);record.update(operations=plan['operations'],checked_identities=plan['identities'],
             worker_pids=plan['workers'],checked_group_ids=sorted(plan['groups']),handle_roots=[str(p) for p in plan['roots']])
        probe=DarwinProbe();observed=probe.observe(plan)
        handle_result=handles(plan['roots']);lock=lock_probe()
        # A second observation rejects a process/group that became visible while
        # checking handles. Neither observation sends a signal to the workload.
        final=probe.observe(plan)
        for observation in (observed,final):
            result=verdict(plan,observation,handle_result,lock)
            if result['status']!='passed':break
        for ref in [*plan['refs'],source_ref,provenance_ref]:core.checked_ref(ref)
        record.update(result,provider_ref=observed['provider_ref'],handle_tool_ref=handle_result['tool_ref'],
                      observation_count=2,root_holds_outer_lock=False)
    except (Exception,KeyboardInterrupt) as failure:
        record.update(status='unknown',resource_release_passed=False,error=core.failure_details(failure))
    return record


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        output=args.output
        need(output.is_absolute() and output.parent.resolve(strict=True)==output.parent and
             not output.exists() and not output.is_symlink(),'release_output_fresh')
        result=inspect(build.fact(args.request))
        with output.open('x') as stream:stream.write(json.dumps(result,indent=2,sort_keys=True)+'\n')
        print(json.dumps(dict(status=result['status'],resource_release_passed=result['resource_release_passed'],receipt=build.fact(output))))
        return 0 if result['resource_release_passed'] else 1
    except (Exception,KeyboardInterrupt) as failure:
        print(json.dumps(dict(status='unknown',resource_release_passed=False,error=core.failure_details(failure))),file=sys.stderr)
        return 1


if __name__=='__main__':raise SystemExit(main())
