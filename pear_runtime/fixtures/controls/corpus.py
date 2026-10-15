# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Original full CPU19 and finite ordering comparators with explicit data inputs.

These pure result checks do not authorize or prove host execution. The caller
must separately bind each actual run, source/PE, producer, log, current authority
and cleanup record. Canonical CPU sources belong to pear-fex; this module binds an explicit
provider and checks its pinned derived contract snapshots. Existing unavailable-feature and candidate-admission refusals remain.
"""
import importlib.util
import subprocess
from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path
from pear_runtime.assembly._common import read_relative

def require(condition, message):
    if not condition:
        raise ValueError(message)

def canonical(value):
    return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def decode(raw, limit=8*1024*1024):
    require(len(raw)<=limit, 'record_size')
    def pairs(rows):
        result={}
        for key,value in rows:
            require(key not in result, 'duplicate_key')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite')))

def read(path, limit=8*1024*1024):
    path=Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size<=limit,'record_file')
    return decode(path.read_bytes(),limit=limit)

def hex64(value):
    require(type(value) is str and re.fullmatch(r'0x[0-9a-f]{16}',value),'hex64')
    return int(value,16)

def fixture_ids(manifest):
    return [c['id'] for c in manifest['cases']]+[c['id'] for c in manifest['boundaries'] if c['stage']==2]

def admit_build(manifest, manifest_raw, build, root, *, provider):
    provider.recheck()
    require(build['scope']=='cpu_pe_build' and build['passed'] is True,'build_status')
    require(manifest==decode(manifest_raw) and build['manifest_sha256']==digest(canonical(manifest)), 'build_manifest')
    require(build.get('adaptations_sha256')==digest(canonical(rules())), 'build_adaptations')
    ids=fixture_ids(manifest)
    require([r['id'] for r in build['cases']]==ids,'build_case_set')
    for row in build['cases']:
        require(row['path']==row['id']+'.exe' and re.fullmatch('[a-z0-9-]+',row['id']),'binary_path')
        path=root/row['path']
        require(not path.is_symlink() and path.stat().st_size<=8*1024*1024,'binary_size')
        raw=path.read_bytes()
        require(digest(raw)==row['sha256'],'binary_changed')
        require(raw[:2]==b'MZ' and len(raw)>64,'pe_header')
        off=int.from_bytes(raw[60:64],'little')
        require(raw[off:off+6]==b'PE\0\0\x64\x86','pe_machine')
    return ids

def case_result(case, row, manifest_hash, *, provider):
    case=effective_case(case, provider=provider)
    require(row['id']==case['id'], 'case_identity')
    events=row['events']
    require(type(events) is list and events, 'missing_events')
    begin=events[0]
    require(begin.get('event')=='begin' and begin.get('id')==case['id'] and begin.get('manifest')==manifest_hash,'begin_identity')
    ecx,edx,xcr0=(hex64(begin[key]) for key in ('cpuid_ecx','cpuid_edx','xcr0'))
    avx=bool(ecx&(1<<28) and ecx&(1<<27) and xcr0&6==6)
    require(type(begin.get('avx')) is bool and begin['avx']==avx,'feature_record')
    require(edx&(1<<26), 'missing_sse2')
    if case['contract']['features'] and not avx:
        require(len(events)==2 and events[1]==dict(event='unavailable',reason='AVX_OSXSAVE_XCR0') and row['exit_code']==77,'feature_refusal')
        return dict(status='unavailable',values=None,reason='AVX_OSXSAVE_XCR0')
    require(row['exit_code']==42 and len(events)==2,'incomplete_case')
    result=events[1]
    require(result.get('event')=='result' and result.get('id')==case['id'] and result.get('matched') is True,'case_result')
    hex64(result['rflags'])
    values=result['values']; expected=case['contract']['expectations']
    require(type(values) is list and len(values)==len(expected),'value_count')
    normalized=[]
    for actual,want,mask in zip(values,expected,case['masks']):
        bits=int(mask['bits'],16)
        require(hex64(actual)&bits==int(want['value'],16)&bits,'golden_mismatch')
        normalized.append(hex64(actual)&bits)
    return dict(status='passed',values=normalized)

def boundary_result(case, row):
    require(row['exit_code']==42, 'boundary_failed')
    if case['id']=='abi-state':
        require(len(row['events'])==1 and row['events'][0].get('event')=='abi_state','abi_record')
        values=row['events'][0]['values']
        expected=[0x1020304050607080+i for i in range(8)]
        for i in range(10): expected.extend([0x1122334455667700+i,0x8877665544332200+i])
        require(type(values) is list and [hex64(v) for v in values]==expected*4,'abi_state_mismatch')
        return dict(status='passed',values=values)
    require(row['events']==[], 'unexpected_boundary_output')
    return dict(status='passed',values=[42])

def assess_records(manifest, build_raw, record, route, *, provider):
    build=decode(build_raw)
    require(record['scope']=='cpu_'+route+'_results' and record.get('complete') is True,'incomplete_run')
    require(record['build_sha256']==digest(build_raw),'mixed_build')
    ids=fixture_ids(manifest)
    require(build.get('scope')=='cpu_pe_build' and build.get('passed') is True and
            build.get('manifest_sha256')==digest(canonical(manifest)), 'build_contract')
    require(build.get('adaptations_sha256')==digest(canonical(rules())), 'build_adaptations')
    require([r['id'] for r in build['cases']]==ids, 'build_case_set')
    require([r['id'] for r in record['cases']]==ids and record['completed_count']==len(ids),'missing_case')
    if route=='native':
        host=record['host']
        require(host['native_machine']==0x8664 and host['process_machine']==0 and host['pointer_bits']==64,'reference_not_native_x64')
    else:
        # Pear execution admission is a separate, still-unimplemented adapter.
        # A caller-supplied success flag must never stand in for its evidence.
        raise ValueError('candidate_admission_not_implemented')
    outcomes={}; cases={c['id']:c for c in manifest['cases']}
    boundaries={c['id']:c for c in manifest['boundaries']}
    for row,binary in zip(record['cases'],build['cases']):
        require(row['binary_sha256']==binary['sha256'] and row.get('outcome')=='exited','case_binary_or_outcome')
        c=cases.get(row['id'])
        outcomes[row['id']]=case_result(c,row,build['manifest_sha256'],provider=provider) if c else boundary_result(boundaries[row['id']],row)
    return outcomes


def _contract(name):
    packet = read(Path(__file__).resolve().parents[3] / 'provenance/fixture-controls-import.json')
    row = packet['contracts'][name]
    require(digest(canonical(row['data'])) == row['canonical_sha256'], 'control_contract_changed')
    return row['data']


def manifest():
    """The exact imported 19-case corpus, without a historical repository root."""
    return _contract('cpu_manifest')


def rules():
    """Original adaptation data, rebound from tests/cpu/adaptations.json."""
    return _contract('cpu_adaptations')

def _provider_pin():
    return read(Path(__file__).resolve().parents[3] /
                'provenance/fixture-controls-import.json')['canonical_cpu_provider']


@dataclass(frozen=True)
class CPUProvider:
    root: Path
    source_commit: str
    files: tuple
    module: object

    def recheck(self):
        pin = _provider_pin()
        require(self.source_commit == pin['commit'] and list(self.files) == pin['files'],
                'cpu_provider_pin_changed')
        require(Path(self.module.__file__).resolve(strict=True) == self.root / pin['module_path'],
                'cpu_provider_loaded_root')
        for row in self.files:
            path = self.root / row['path']
            require(path.resolve(strict=True) == path, 'cpu_provider_file_alias')
            raw = read_relative(self.root, row['path'])
            require(digest(raw) == row['sha256'] and len(raw) == row['size_bytes'],
                    'cpu_provider_source_changed')
        for name, path in pin['contracts'].items():
            require(decode(read_relative(self.root, path)) == _contract(name),
                    'cpu_provider_snapshot_changed')
        return self


def bind_provider(fex_root, source_commit):
    """Admit an explicitly supplied canonical FEX root before loading its code.

    PYTHONPATH must expose that same checkout. This function never inserts a
    historical worktree or guesses a sibling path. A reviewed new source pin
    and regenerated derived snapshot are required for a changed corpus.
    """
    root = Path(fex_root)
    require(root.is_absolute() and root.is_dir() and root.resolve(strict=True) == root,
            'cpu_provider_root_alias')
    pin = _provider_pin()
    require(source_commit == pin['commit'], 'cpu_provider_commit')
    try:
        actual = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'],
                                         text=True, timeout=10).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError('cpu_provider_git_identity') from exc
    require(actual == source_commit, 'cpu_provider_checkout_commit')
    for row in pin['files']:
        path = root / row['path']
        require(path.resolve(strict=True) == path, 'cpu_provider_file_alias')
        raw = read_relative(root, row['path'])
        require(digest(raw) == row['sha256'] and len(raw) == row['size_bytes'],
                'cpu_provider_source_changed')
    for name in ('Pear/__init__.py', 'Pear/Tools/__init__.py', 'Pear/Tools/CPU/__init__.py'):
        require(not (root/name).exists(), 'cpu_provider_unreviewed_package')
    spec = importlib.util.find_spec('Pear.Tools.CPU.adapt')
    require(spec is not None and spec.origin == str(root / pin['module_path']),
            'cpu_provider_import_root')
    from Pear.Tools.CPU import adapt
    return CPUProvider(root, source_commit, tuple(pin['files']), adapt).recheck()


def effective_case(case, *, provider):
    require(type(provider) is CPUProvider, 'cpu_provider_required')
    provider.recheck()
    return provider.module.effective_case(case, rules())


def assess(events,iterations,rounds,exit_code):
    require(exit_code==42,'ordering_exit')
    require(type(events) is list and len(events)==rounds+1,'ordering_incomplete')
    require(events[-1]==dict(event='ordering_complete',rounds=rounds,iterations=iterations),'ordering_final')
    workers=[];coordinator=None
    for index,event in enumerate(events[:-1]):
        require(event.get('event')=='ordering_round' and event.get('round')==index and
                event.get('iterations')==iterations and event.get('joined')==2 and event.get('tls_ok') is True,'ordering_round')
        ids=event.get('workers');main=event.get('coordinator')
        require(type(main) is int and main>0 and type(ids) is list and len(ids)==2 and
                all(type(t) is int and t>0 and t!=main for t in ids) and ids[0]!=ids[1],'ordering_workers')
        require(coordinator in (None,main),'ordering_coordinator_changed');coordinator=main
        counts=event.get('counts')
        require(type(counts) is list and len(counts)==4,'ordering_modes')
        for buckets in counts:
            require(type(buckets) is list and len(buckets)==4 and
                    all(type(n) is int and n>=0 for n in buckets) and sum(buckets)==iterations,'ordering_counts')
        require(counts[0][2:]==[0,0],'locked_outcome')
        require(counts[1][2]==0,'message_passing_forbidden')
        # Plain store-buffer 00 is architecturally allowed; no occurrence quota.
        require(counts[3][0]==0,'fenced_store_buffer_forbidden')
        workers.extend(ids)
    return dict(passed=True,rounds=rounds,iterations_per_mode=iterations,
                measured_pairs=4*rounds*iterations,workers=workers,coordinator=coordinator,
                simultaneous_participants=3,universal_ordering_proof=False)

def policy_records(raw,assessment):
    require(len(raw)<=64*1024**2,'policy_log_bound')
    pattern=rb'Pear CPU (?:policy state=([0-9a-f]+) scalar=(true|false|1|0) vector=(true|false|1|0) memcpy=(true|false|1|0)|thread tid=([0-9]+) state=([0-9a-f]+))'
    pending={};observed=[]
    for match in re.finditer(pattern,raw):
        state,scalar,vector,memcpy,tid,mapped=match.groups()
        if state:
            require(state not in pending,'duplicate_live_policy_state')
            require(all(v in (b'true',b'1') for v in (scalar,vector,memcpy)),'software_policy_disabled')
            pending[state]=(True,True,True)
        else:
            require(mapped in pending,'thread_without_policy')
            pending.pop(mapped)
            observed.append(dict(tid=int(tid),scalar=True,vector=True,memcpy=True))
    require(not pending,'unpublished_policy_state')
    available=[o['tid'] for o in observed]
    for tid in [assessment['coordinator']]+assessment['workers']:
        require(tid in available,'worker_policy_missing');available.remove(tid)
    return observed

def retirements(raw,workers):
    completed=re.findall(rb'Pear FEX init ThreadTerm.complete: status=00000000 domain=0 code=0',raw)
    require(len(completed)==workers,'worker_source_retirement_incomplete')
    return len(completed)


def compare_result_rows(build_raw, reference, reference_logs, candidate_rows, *, provider):
    """Original comparison loop over explicitly supplied, separately admitted rows.

    reference_logs maps (fixture_id, stdout|stderr) to immutable bytes. This
    function checks their original record identities and mathematical outcomes;
    it cannot replace the original live/runtime execution evidence adapter.
    """
    contract=manifest();built=decode(build_raw)
    expected=assess_records(contract,build_raw,reference,'native',provider=provider)
    for row in reference['cases']:
        for stream in ('stdout','stderr'):
            require(digest(reference_logs[(row['id'],stream)])==row[stream+'_sha256'],'reference_log_changed')
        require([decode(line) for line in reference_logs[(row['id'],'stdout')].splitlines() if line.strip()]==row['events'],'reference_events_changed')
    require([r['id'] for r in candidate_rows]==[r['id'] for r in built['cases']],'candidate_case_set')
    cases={c['id']:c for c in contract['cases']};boundaries={c['id']:c for c in contract['boundaries']}
    results=[]
    for fixture,row in zip(built['cases'],candidate_rows):
        require(row['binary_sha256']==fixture['sha256'] and row['outcome']=='exited','case_binary_or_outcome')
        c=cases.get(row['id'])
        actual=case_result(c,row,built['manifest_sha256'],provider=provider) if c else boundary_result(boundaries[row['id']],row)
        reference_case=expected[row['id']]
        if actual['status']=='unavailable':
            status='unsupported_not_exposed'
        else:
            require(reference_case['status']=='passed','reference_unavailable_for_exposed_case')
            require(actual['values']==reference_case['values'],'native_mismatch')
            status='passed'
        results.append(dict(id=row['id'],status=status))
    return dict(passed=True,scope='pure_full_corpus_result_comparison',cases=results,
                execution_admission_performed=False,cpu_qualified=False,game_qualified=False)


def compare_ordering_records(build_raw, reference, reference_logs, candidate_events,
                             candidate_exit, candidate_stderr):
    """Original finite outcomes/policy/retirement checks on explicit exact inputs."""
    built=decode(build_raw);budget=_contract('ordering_budget')
    require(built['scope']=='cpu_ordering_build' and built['passed'] is True,'ordering_build_status')
    require(type(built['iterations']) is int and type(built['rounds']) is int and
            built['iterations']==budget['iterations'] and built['rounds']==budget['rounds'],'ordering_budget')
    host=reference['host']
    require(reference['scope']=='ordering_native_reference' and reference['passed'] is True and
            reference['build_sha256']==digest(build_raw),'ordering_reference_identity')
    require(host['native_machine']==0x8664 and host['process_machine']==0 and host['pointer_bits']==64 and
            host['system'] and host['processor'],'ordering_reference_architecture')
    for stream in ('stdout','stderr'):
        raw=reference_logs[stream]
        require(len(raw)<=1024*1024 and digest(raw)==reference[stream+'_sha256'],'ordering_reference_log')
    events=[decode(line) for line in reference_logs['stdout'].splitlines() if line.strip()]
    expected=assess(events,built['iterations'],built['rounds'],reference['exit_code'])
    require(expected==reference['assessment'],'ordering_reference_assessment')
    actual=assess(candidate_events,built['iterations'],built['rounds'],candidate_exit)
    actual['policy']=policy_records(candidate_stderr,actual)
    actual['checked_worker_retirements']=retirements(candidate_stderr,len(actual['workers']))
    return dict(passed=True,scope='pure_finite_ordering_result_comparison',reference=expected,candidate=actual,
                execution_admission_performed=False,cpu_qualified=False,game_qualified=False)
