# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Selected direct fixture policy and unchanged owned Wine session lifecycle.

Historical pure policy functions remain for their original portable tests.
Execution admits only the explicit new development fixture context.
"""
from pathlib import Path
from types import SimpleNamespace
import ctypes,json,os,re,shutil,subprocess,time,uuid
from pear_runtime.assembly._common import decode_json
from pear_runtime.assembly import core
from pear_runtime.assembly import helpers as signing
from .inputs import fact,read,save,digest,need
from .types import Selection
from . import supervision as supervisor
from .supervision import prefix_inventory
from .assessment import query,query_context as context_query,entry,link,assess_owned
from .context import FixtureContext,NAMES

preparation=SimpleNamespace(Selection=Selection,checked_ref=core.checked_ref,signing=signing,
    PE=signing.PAYLOAD+'/lib/wine/aarch64-windows/ntdll.dll',
    NATIVE=signing.PAYLOAD+'/lib/wine/aarch64-unix/ntdll.so')
METAL_ENV = {'MTL_DEBUG_LAYER': '1', 'MTL_DEBUG_LAYER_ERROR_MODE': 'assert',
             'MTL_DEBUG_LAYER_WARNING_MODE': 'nslog', 'MTL_SHADER_VALIDATION': '1',
             'MTL_SHADER_VALIDATION_FAIL_MODE': 'zerofill',
             'MTL_SHADER_VALIDATION_REPORT_TO_STDERR': '1'}


CANDIDATES = ('d5-optimized','d6-original','d6-optimized','d7-original','d7-optimized','d9-original','d9-optimized','d10-original','d10-optimized','d11-original','d11-optimized','d12-original','d12-optimized','d13-optimized','d14-optimized','d15-optimized','d16-optimized','d17-optimized','d18-optimized','d19-optimized','d20-optimized','d21-optimized','d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game','n1-optimized')


FIXTURES = {'phase-guest':42,'native-pool-native':42,'link-stress-guest':42,'platform-probe-native':42,'platform-restart-native':42,'platform-prepare-native':42,'query-callsite-native':42,'configured-memory':42,'tls-thread':42,'rendering-original':42,'presentation-original':42,
            'seh-unwind':42,'suspend-context':42,'guest-fault-guard':42,'code-invalidation':42,
            'image-admission-native':42,'image-admission-guest':42}


def query_policy(name):
    if name in link.CANDIDATES: return link
    if name in entry.CANDIDATES: return entry
    return context_query if name in context_query.CANDIDATES else query


OBSERVATIONS = ('PEAR_FEX_BATCH_OBSERVE', 'PEAR_FEX_WRITE_OBSERVE',
                'PEAR_FEX_OWNER_OBSERVE', 'PEAR_FEX_WAKE_OBSERVE')


SEED_FEX = '6c23fda169ab859aafc1f988bf2d7557c0317c07094abd964eec165b20bcfb05'


DEADLINE_SECONDS = 120


def execution_seconds(candidate, fixture, samples, budget):
    need(type(budget) is str and budget in ('standard120', 'd18-game300', 'd23-game300', 'd25-game300'), 'direct_execution_budget')
    if budget == 'standard120':
        return DEADLINE_SECONDS
    admitted = candidate.name in {'d18-game300':('d18-optimized',),'d23-game300':('d23-16384','d23-65536'),'d25-game300':('d25-game',)}[budget]
    need(admitted and fixture is None and samples == (), 'direct_extended_budget_scope')
    return 300


def options(candidate, observations, samples):
    need(type(candidate) is preparation.Selection and candidate.name in CANDIDATES, 'direct_candidate_unavailable')
    need(type(observations) is str and observations in ('on','off'), 'direct_observations')
    need(type(samples) is tuple and samples in ((),(0,),(15,60,90),(15,92,94),(15,35,50),(15,30,45),('source-wait',),('source-wait-short',)), 'direct_samples_unavailable')
    need(samples not in (('source-wait',),('source-wait-short',)) or (candidate.name in ('d22-optimized','d23-16384','d23-65536','d24-131072') and observations == 'on'), 'direct_event_sample_scope')
    need(samples != (0,) or candidate.name in ('d19-optimized','d20-optimized'), 'direct_early_sample_scope')
    need(samples != (15,30,45) or candidate.name == 'd21-optimized', 'direct_pending_sample_scope')
    need(candidate.name != 'd5-optimized' or samples == (), 'direct_original_run_samples')
    need(samples != (15,35,50) or candidate.name in ('d16-optimized','d17-optimized','d18-optimized'), 'direct_mutation_sample_scope')
    result = {key: '1' if observations == 'on' else '0' for key in OBSERVATIONS}
    if candidate.name.startswith(('d6-','d7-','d9-','d10-','d11-','d12-','d13-','d14-','d15-','d16-','d17-','d18-','d19-','d20-','d21-','d22-','d23-','d24-','d25-','n1-')):
        result['PEAR_FEX_THREAD_OBSERVE'] = '1' if observations == 'on' else '0'
    if candidate.name in ('d25-fixture','d25-game'):
        result['PEAR_PHASE_OBSERVE']='1' if observations=='on' else '0'
    return result


TRACE_PRESETS = ('historical', 'progress', 'platform', 'menu')


MENU_TRACE = '-all,err+all,+loaddll'


PLATFORM_TRACE = '-all,err+all,+service,+rpc,+nsi,+iphlpapi,+loaddll'


FULL_TRACE = '-all,+loaddll,+seh,+module,+file,+thread'


GRAPHICS_TRACE = '-all,+loaddll,+seh,+module'


PROGRESS_TRACE = '-all,+loaddll,+module,+thread'


def trace_environment(candidate, fixture, preset):
    need(type(preset) is str and preset in TRACE_PRESETS, 'direct_trace_unavailable')
    if preset == 'menu':
        need(candidate == 'd25-game' and fixture is None, 'direct_menu_trace_scope')
        return MENU_TRACE
    if preset == 'platform':
        need(candidate in ('d14-optimized','n1-optimized') and fixture in ('platform-probe-native','platform-prepare-native','platform-restart-native'), 'direct_platform_scope')
        return PLATFORM_TRACE
    if preset == 'progress':
        need(candidate in ('d7-original','d7-optimized','d9-original','d9-optimized','d10-original','d10-optimized','d11-original','d11-optimized','d12-original','d12-optimized','d13-optimized','d14-optimized','d15-optimized','d16-optimized','d17-optimized','d18-optimized','d19-optimized','d20-optimized','d21-optimized','d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game','n1-optimized') and fixture is None, 'direct_trace_scope')
        return PROGRESS_TRACE
    return GRAPHICS_TRACE if fixture in ('rendering-original','presentation-original','image-admission-native','image-admission-guest') else FULL_TRACE


def assess_trace(value):
    requested = value['requested']; applied = value['applied']
    loaders = [r for r in value['launches'] if r['role'] == 'loader']
    need(len(loaders) == 1, 'direct_trace_loader')
    actual = loaders[0]['environment'].get('WINEDEBUG')
    if 'trace' not in requested:
        # Historical receipts predate declarations. Validate their recorded
        # environment without inventing a request or rewriting their producer.
        allowed = {FULL_TRACE}
        if requested.get('fixture') in ('rendering-original','presentation-original'):
            allowed.add(GRAPHICS_TRACE)
        need('trace_environment' not in applied and actual in allowed, 'direct_legacy_trace_contradiction')
        return dict(declaration='historical_undeclared',requested=None,applied=actual)
    expected = trace_environment(requested['candidate'],requested.get('fixture'),requested['trace'])
    need(applied.get('trace_environment') == expected == actual, 'direct_trace_contradiction')
    need(value.get('observed',{}).get('loader_trace_environment') == actual, 'direct_observed_trace_contradiction')
    return dict(declaration='explicit',requested=requested['trace'],applied=actual)


LOG_BUDGETS = {'standard2': 2*1024**2, 'menu8': 8*1024**2, 'menu64': 64*1024**2}


def log_limit(candidate, fixture, trace, budget):
    need(type(budget) is str and budget in LOG_BUDGETS, 'direct_log_budget')
    need(budget == 'standard2' or (candidate == 'd25-game' and fixture is None and trace == 'menu'),
         'direct_log_budget_scope')
    return LOG_BUDGETS[budget]


def assess_log_budget(value):
    request = value['requested']
    budget = request.get('log_budget', 'standard2')
    limit = log_limit(request['candidate'], request.get('fixture'), request.get('trace', 'historical'), budget)
    if 'log_budget' in request:
        need(value['applied'].get('stream_limit_bytes') == limit == value['observed'].get('stream_limit_bytes'),
             'direct_log_budget_contradiction')
    else:
        need('stream_limit_bytes' not in value['applied'] and 'stream_limit_bytes' not in value['observed'],
             'direct_log_budget_legacy')
    for row in value['logs']:
        if row['channel'] in ('stdout', 'stderr'):
            need(0 <= row['bytes'] == row['observed_bytes'] <= limit, 'direct_log_budget_exceeded')
    return dict(name=budget,stream_limit_bytes=limit)


SIGNAL_OPTIONS = ('historical','on','off')


SIGNAL_KEY = 'PEAR_SIGNAL_RESUME_OBSERVE'


def signal_environment(candidate, setting):
    need(type(setting) is str and setting in SIGNAL_OPTIONS, 'direct_signal_setting')
    need(setting == 'historical' or candidate in ('d9-original','d9-optimized','d10-original','d10-optimized','d11-original','d11-optimized','d12-original','d12-optimized','d13-optimized','d14-optimized','d15-optimized','d16-optimized','d17-optimized','d18-optimized','d19-optimized','d20-optimized','d21-optimized','d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game','n1-optimized'), 'direct_signal_scope')
    return {} if setting == 'historical' else {SIGNAL_KEY:'1' if setting == 'on' else '0'}


def assess_signal(value, raw):
    request = value['requested'];applied = value['applied']
    setting = request.get('signal_resume','historical')
    expected = signal_environment(request['candidate'],setting)
    actual = next(r['environment'] for r in value['launches'] if r['role'] == 'loader')
    need({k:actual[k] for k in (SIGNAL_KEY,) if k in actual} == expected, 'direct_signal_launch')
    if 'signal_resume' in request:
        need(applied.get('signal_environment') == expected and
             value['observed'].get('loader_signal_environment') == expected, 'direct_signal_contradiction')
    else:
        need('signal_environment' not in applied, 'direct_signal_legacy')
    count = raw.count(b'Pear SIGUSR2 resume guest\n') + raw.count(b'Pear SIGUSR2 resume native\n')
    need(setting != 'off' or count == 0, 'direct_disabled_signal_emission')
    return dict(requested=setting if 'signal_resume' in request else None,applied=expected,
                observed_message_count=count,resume_count_claim=False)


def read_sources(path):
    # The preserved v1 source manifest is an array; retain the shared strict
    # decoder's duplicate-key/node/size checks by wrapping that array.
    raw = Path(path).read_bytes()
    value = decode_json(b'{\"files\":'+raw+b'}', 64*1024**2, max_nodes=1000000)['files']
    need(type(value) is list, 'direct_source_manifest_shape')
    return value


def complete_provenance(rows):
    for row in rows:
        need(fact(row['original']['path']) == row['original'] and
             fact(row['snapshot']['path']) == row['snapshot'], 'direct_producer_changed_during_run')


def finish_reason(data, loader_pid, image):
    match = re.search(rb'Pear FEX init (?:ECGate\.(?:enter|fill|exit)|GuestSyscall\.exit): status=(?!00000000)[0-9a-fA-F]{8} domain=\d+ code=-?\d+',data[-65536:])
    refusal = match.group().decode('ascii') if match else None
    # Synthetic fixtures have no owned-game image; generic guards still apply.
    if image is not None:
        target = (b'pid='+str(loader_pid).encode()+rb' fd=\d+ dev='+str(image['dev']).encode()+b' ino='+str(image['ino']).encode()+b' bytes='+str(image['bytes']).encode())
        image_failure = re.search(rb'PEAR_IMAGE_ADMISSION '+target+rb' phase=caller\.parsed status=(?!00000000)[0-9a-f]{8}',data)
        if image_failure:
            refusal = image_failure.group().decode('ascii')
    if not match:
        guard = re.search(rb'[^\n]*(?:Pear source guard refused|Pear FEX assertion:)[^\n]*',data[-65536:])
        if guard:
            refusal = guard.group().decode('utf-8',errors='replace')
    return refusal


def sample_interval(candidate, samples):
    sparse = (candidate.name in ('d22-optimized','d23-16384','d23-65536','d24-131072') and samples in (('source-wait',),('source-wait-short',))) or (candidate.name in ('d20-optimized','d23-16384','d23-65536','d24-131072') and samples == (15,60,90)) or (candidate.name == 'd21-optimized' and samples == (15,30,45))
    return 10 if sparse else 1


class SampleWindows:
    """Schedule finite samples through the existing owned Session, not an observer."""
    def __init__(self, session, output, deadline, environment, launch, offsets, interval_ms=1):
        need(type(interval_ms) is int and interval_ms in (1,10), 'direct_sample_interval')
        self.interval_ms = interval_ms
        self.duration_seconds = 1 if offsets==('source-wait-short',) else 2
        self.session, self.output, self.deadline = session, output, deadline
        self.environment, self.launch, self.offsets = environment, launch, offsets
        self.rows = []; self.active = None

    def start(self, target):
        session = self.session; session.observer.refresh()
        need(not target.exited and not target.reaped and
             session.observer.identity(target.pid) == target.identity and
             session.observer.executable(target.pid) in target.allowed_paths, 'direct_sample_target')
        index = len(self.rows); path = self.output/('sample-'+str(index)+'.txt')
        need(not path.exists() and not path.is_symlink(), 'direct_sample_path')
        row = dict(index=index,target_identity=dict(target.identity),start_ns=time.monotonic_ns(),
                   clock_monotonic_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC),
                   report_path=str(path),duration_seconds=self.duration_seconds,interval_ms=self.interval_ms,valid=False,
                   tool=fact(Path('/usr/bin/sample')),requested_offset_seconds=None if self.offsets in (('source-wait',),('source-wait-short',)) else self.offsets[index])
        self.rows.append(row)
        # Current-process architecture metadata uses the existing observer's
        # libproc binding; SDK PROC_PIDARCHINFO is two signed 32-bit fields.
        child = self.launch('sample-'+str(index),['/usr/bin/arch','-arm64','/usr/bin/sample',str(target.pid),str(self.duration_seconds),str(self.interval_ms),*([] if self.offsets==('source-wait-short',) else ['-mayDie']),'-file',str(path)],
                            self.environment,allowed_paths=['/usr/bin/arch','/usr/bin/sample'])
        row['sampler_identity'] = dict(child.identity); info = (ctypes.c_int32*2)()
        got = session.observer.lib.proc_pidinfo(child.pid,19,0,ctypes.byref(info),ctypes.sizeof(info))
        row['sampler_architecture'] = dict(available=got == ctypes.sizeof(info),cpu_type=int(info[0]) if got == ctypes.sizeof(info) else None)
        self.active = (child,target,row,min(self.deadline,time.monotonic()+10))

    def finish(self, reason):
        child,target,row,_ = self.active;session = self.session
        row['end_ns'] = time.monotonic_ns();row['end_reason'] = reason
        try:
            session.observer.refresh()
            row['target_after'] = session.observer.identity(target.pid)
            row['target_alive_after'] = not target.exited and not target.reaped
        except Exception as exc:
            row['target_query_error'] = getattr(exc,'code',type(exc).__name__)
        # No natural-exit grace or wait for symbolication after game refusal.
        cleanup = session.cleanup((child.role,),dict(grace_ms=0,terminate_ms=500,kill_ms=500,drain_ms=200))
        row['cleanup'] = cleanup;row['exit_code'] = child.exit_code
        path = Path(row['report_path'])
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= 4*1024**2:
            row['report'] = fact(path)
            raw = path.read_bytes()
            match = re.search(rb'^Process:.*\[(\d+)\]',raw,re.M)
            row['report_target_matches'] = bool(match and int(match[1]) == target.pid)
        else:
            row['report_unavailable_or_oversize'] = True
        row['valid'] = bool(reason == 'completed' and child.exit_code == 0 and cleanup['complete'] and
            row.get('target_alive_after') and row.get('target_after') == row['target_identity'] and
            row['sampler_architecture']['cpu_type'] == 16777228 and row.get('report_target_matches') and
            fact('/usr/bin/sample') == row['tool'])
        if cleanup['complete']:
            self.active = None
        need(cleanup['complete'], 'direct_sampler_cleanup')

    def tick(self, target, attach_time, raw=b'', owned=None):
        if self.active:
            child,_,row,end = self.active;path = Path(row['report_path'])
            if child.exited:
                self.finish('completed')
            elif path.exists() and path.stat().st_size > 4*1024**2:
                self.finish('report_limit')
            elif time.monotonic() >= end:
                self.finish('deadline')
        if not self.active and len(self.rows) < len(self.offsets) and attach_time is not None and not target.exited:
            if self.offsets in (('source-wait',),('source-wait-short',)):
                from .assessment.early_wait import trigger
                event=trigger(raw,target.pid,owned)
                if event is not None and self.deadline-time.monotonic() >= self.duration_seconds:
                    self.start(target)
                    self.rows[-1]['source_wait_trigger']=event
                    self.rows[-1]['trigger_received_ns']=time.monotonic_ns()
            elif time.monotonic()-attach_time >= self.offsets[len(self.rows)] and self.deadline-time.monotonic() >= self.duration_seconds:
                self.start(target)

    def cancel(self):
        if self.active:
            self.finish('game_ended_or_refused')


def pump_observations(adapter,handoff,sampler,loader,attach_time,data,owned,terminal):
    if adapter is not None:
        adapter.tick(data,terminal=terminal)
        terminal=terminal or adapter.ended
    if not terminal and not (adapter and (adapter.experiments_stopped or adapter.pending_key is not None)):
        sampler.tick(loader,attach_time,data,owned)
    if handoff is not None and adapter is None:handoff.tick(data)


def attached(data):
    call = re.search(rb'MODULE_InitDLL \(([0-9A-Fa-f]+) L"GameAssembly\.dll",PROCESS_ATTACH,[^\n]* - CALL',data)
    return bool(call and re.search(rb'MODULE_InitDLL \('+call[1]+rb',PROCESS_ATTACH,[^\n]* - RETURN 1',data))


def thread_identities(raw):
    rows = []; seen = set()
    for line in raw.splitlines():
        if not line.startswith(b'PEAR_OWNER_THREAD '):
            continue
        m = re.fullmatch(rb'PEAR_OWNER_THREAD seq=(\d+) index=(\d+) id=(\d+) valid=([01]) host=(\d+) register_lo=(\d+) register_hi=(\d+)',line)
        need(m is not None, 'direct_thread_identity_syntax')
        seq,index,ident,valid,host,lo,hi = map(int,m.groups())
        need(seq < 8 and index < 8 and (seq,index) not in seen and 0 < ident < 2**64 and
             ((valid and 0 < host < 2**64 and 0 < lo <= hi < 2**64) or (not valid and host == lo == hi == 0)), 'direct_thread_identity_values')
        seen.add((seq,index));rows.append(dict(sequence=seq,index=index,executor=ident,valid=bool(valid),host_thread=host,register_lo=lo,register_hi=hi,clock_scope='current-thread query interval before registration lock; not an admission upper bound'))
    return rows


def assess(root):
    root = Path(root); v = read(root/'case.json')
    selected = options(preparation.Selection(v['requested']['candidate'],Path(v['runtime_ref']['path']).parent),
                       'on' if v['requested']['observations'].get(OBSERVATIONS[0]) == '1' else 'off',tuple(v['requested']['samples']))
    need(v['requested']['observations'] == selected == v['applied']['observation_environment'], 'direct_observation_contradiction')
    env = next(row['environment'] for row in v['launches'] if row['role'] == 'loader')
    need(all(env.get(k) == val for k,val in selected.items()), 'direct_launch_contradiction')
    need(env.get('PEAR_FEX_ABORT_OBSERVE')==('1' if v['requested'].get('abort_observation','off')=='on' else None),'abort_launch_contradiction')
    need(v['producer_dependencies_unchanged'] is True, 'direct_provenance_incomplete')
    preparation.checked_ref(v['producers_ref'])
    for row in read_sources(root/'producers.json'):
        preparation.checked_ref(row['snapshot'])
        need(row['snapshot']['sha256'] == row['original']['sha256'], 'direct_snapshot_changed')
    budget=v['requested'].get('budget','standard120')
    seconds=execution_seconds(preparation.Selection(v['requested']['candidate'],Path(v['runtime_ref']['path']).parent),
                              v['requested'].get('fixture'),tuple(v['requested']['samples']),budget)
    need(v['applied'].get('deadline_seconds',120)==seconds and
         (budget=='standard120' or 'diagnostic_fixture' not in v),'direct_budget_contradiction')
    trace_record = assess_trace(v)
    log_policy = assess_log_budget(v)
    result = assess_owned(root)
    result['log_budget'] = log_policy
    result['samples'] = v['observed']['samples']
    result['execution_budget'] = dict(name=budget,seconds=seconds)
    raw = (root/'run/loader.stderr.log').read_bytes()
    trace_record['observed_channels'] = sorted({m.decode('ascii') for m in re.findall(rb'(?m)^[^\n]*?trace:([a-zA-Z0-9_]+):',raw)})
    trace_record['exception_detail_enabled'] = '+seh' in trace_record['applied'].split(',')
    trace_record['full_exception_observation_claim'] = False
    result['trace'] = trace_record
    result['signal_resume'] = assess_signal(v,raw)
    result['query_observation'] = query_policy(v['requested']['candidate']).assess(v,raw)
    result['entry_observation'] = link.assess_entry(v,raw)
    from .assessment.failure import assess as assess_failure
    result['failure_observation'] = assess_failure(v,raw)
    from .assessment.repair_epoch import assess as assess_repair
    result['repair_observation'] = assess_repair(v,raw)
    from .assessment.mutation_bound import assess as assess_mutation
    result['mutation_observation'] = assess_mutation(v,raw)
    if v['requested']['candidate'] in ('d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game'):
        from .assessment.early_wait import assess_owner as assess_source_owner
    elif v['requested']['candidate']=='d21-optimized':
        from .assessment.pending_transition import assess as assess_source_owner
    else:
        from .assessment.source_owner import assess as assess_source_owner
    result['source_owner_observation'] = assess_source_owner(v,raw)
    from .assessment.early_wait import assess as assess_early_wait
    result['early_wait_observation'] = assess_early_wait(v,raw)
    result['link_observation'] = link.assess_link(v,raw)
    result['thread_identities'] = thread_identities(raw)
    need(v['requested']['observations'].get('PEAR_FEX_THREAD_OBSERVE') == '1' or not result['thread_identities'], 'direct_disabled_identity_emission')
    for identity in result['thread_identities']:
        native = [r for t in result['native_timeouts'] if t['sequence'] == identity['sequence'] for r in t['rows'] if r['index'] == identity['index']]
        need(len(native) == 1 and native[0]['id'] == identity['executor'], 'direct_thread_native_join')
    if 'diagnostic_fixture' in v:
        need(v['diagnostic_fixture']['name'] in FIXTURES and v['diagnostic_fixture']['expected_exit'] == FIXTURES[v['diagnostic_fixture']['name']], 'direct_fixture_result_policy')
        result['fixture_name'] = v['diagnostic_fixture']['name']
        result['fixture_passed'] = bool(v['outcome'] == 'exited' and result['loader_exit'] == v['diagnostic_fixture']['expected_exit'] and not v['error'] and result['cleanup_passed'] and result['authority_passed'] and result['host_bootstrap_arm64_no_rosetta'] and result['runtime_unchanged'])
    need(not v.get('sampler_cleanup_error'), 'direct_sampler_cleanup_incomplete')
    need(not v.get('play_cleanup_error'),'direct_play_cleanup_incomplete')
    result.update(assessor_ref=fact(Path(__file__)),execution_producer_ref=v['producer_ref'],producer_dependencies_unchanged=True,candidate=v['applied']['candidate'],diagnostic_only=True)
    return result


def stage_modules(prefix,runtime,candidate,*,fixture_context):
    need(type(fixture_context) is FixtureContext and candidate.name=='d25-game','direct_stage_candidate')
    before=prefix_inventory(prefix);records={}
    for name,row in fixture_context.value['modules'].items():
        target=prefix/'drive_c/windows/system32'/name
        source=runtime/preparation.PE.replace('ntdll.dll',name)
        need(not target.is_symlink() and target.resolve().is_relative_to(prefix.resolve()),'direct_prefix_alias')
        need(fact(target)['sha256']==row['seed_sha256'] and fact(source)==row['selected_ref'],'direct_module_preimage')
        prior=fact(target);shutil.copyfile(source,target)
        need(target.read_bytes()==source.read_bytes(),'direct_module_copy')
        records[name]=dict(before=prior,after=fact(target),source=fact(source))
    allowed={'drive_c/windows/system32/'+name for name in records}
    after=prefix_inventory(prefix)
    need([r for r in before if r['path'] not in allowed]==[r for r in after if r['path'] not in allowed],
         'direct_prefix_other_change')
    save(prefix.parents[1]/'prefix-ntdll.json',dict(**records['ntdll.dll'],
        fex=records['xtajit64.dll']['after'],fex_source=records['xtajit64.dll']['source'],
        only_permitted_changes=sorted(allowed)))
    return records


def run(inputs, candidate, output, observations='off', samples=(), fixture=None, trace='historical', signal_resume='historical', query_observation='historical', entry_observation='historical', link_observation='historical', budget='standard120', abort_observation='off', log_budget='standard2', play_adapter_factory=None, fixture_context=None):
    need(type(candidate) is Selection and candidate.name=='d25-game' and
         type(fixture_context) is FixtureContext and fixture in NAMES and
         inputs is None and play_adapter_factory is None,'direct_fixture_context_scope')
    admission=fixture_context.current_authority
    if candidate.name == 'n1-optimized':
        need(fixture in ('native-pool-native','platform-probe-native','platform-prepare-native','platform-restart-native') and not samples, 'pool_native_control_scope')
    need(fixture != 'platform-restart-native' or candidate.name == 'n1-optimized', 'nsi_restart_scope')
    need(fixture != 'native-pool-native' or candidate.name == 'n1-optimized', 'pool_fixture_scope')
    external_fixture_name = 'platform-probe-native' if fixture == 'platform-restart-native' else fixture
    selected_env = options(candidate,observations,samples)
    need((fixture is None or fixture in FIXTURES) and (fixture is None or not samples), 'direct_fixture_scope')
    need(abort_observation in ('off','on'),'abort_observation_option')
    abort_env={}
    if abort_observation=='on':
        need(candidate.name=='d25-game' and fixture_context.selected.get('abort_observer') is True,'abort_selected_runtime')
        abort_env={'PEAR_FEX_ABORT_OBSERVE':'1'}
    seconds = execution_seconds(candidate,fixture,samples,budget)
    selected_trace = trace_environment(candidate.name,fixture,trace)
    selected_limit = log_limit(candidate.name,fixture,trace,log_budget)
    selected_signal = signal_environment(candidate.name,signal_resume)
    selected_query = query_policy(candidate.name).environment(candidate.name,query_observation)
    selected_entry = link.entry_settings(candidate.name,entry_observation)
    selected_link = link.settings(candidate.name,link_observation)
    need(samples not in (('source-wait',),('source-wait-short',)) or entry_observation == 'on', 'direct_event_sample_entry')
    if fixture in ('link-stress-guest','platform-probe-native','platform-prepare-native','platform-restart-native'):
        need(candidate.name in ('d14-optimized','d15-optimized','d16-optimized','d17-optimized','d18-optimized','d19-optimized','d20-optimized','d21-optimized','d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game','n1-optimized'), 'direct_extra_fixture_scope')
    if fixture == 'phase-guest':
        need(candidate.name=='d25-fixture','phase_fixture_scope')
    if candidate.name=='d25-fixture':need(fixture=='phase-guest','phase_synthetic_only')
    if fixture == 'query-callsite-native':
        need(candidate.name in context_query.CANDIDATES + entry.CANDIDATES + link.CANDIDATES,'context_fixture_scope')
    if fixture == 'configured-memory':
        need(candidate.name in query.CANDIDATES + context_query.CANDIDATES + entry.CANDIDATES + link.CANDIDATES, 'query_memory_fixture_scope')
    if fixture in ('seh-unwind','suspend-context','guest-fault-guard','code-invalidation','image-admission-native','image-admission-guest'):
        need(candidate.name in ('d9-original','d9-optimized','d10-original','d10-optimized','d11-original','d11-optimized','d12-original','d12-optimized','d13-optimized','d14-optimized','d15-optimized','d16-optimized','d17-optimized','d18-optimized','d19-optimized','d20-optimized','d21-optimized','d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game','n1-optimized'), 'direct_diagnostic_fixture_scope')
    output=fixture_context.fresh_output(output)
    runtime,value=fixture_context.begin(fixture,output)
    fixture_context.mark('runtime_admission')
    seed=fixture_context.seed;game=snapshot=None;prepared_seed=None
    reuse=fixture_context.provider_root
    storage=fixture_context.storage_admission(output)
    output.mkdir(mode=0o700);producers=fixture_context.preserve_sources(output)
    save(output/'storage-admission.json',storage)
    fixture_context.baseline(output/'baseline.log');sources=[]
    work=output/'run';work.mkdir();prefix=work/'prefix'
    template=seed/'run/prefix';inventory=prefix_inventory(template)
    inf=runtime/signing.PAYLOAD/'share/wine/wine.inf'
    need((template/'.update-timestamp').read_text().strip()==str(int(inf.stat().st_mtime)),'game_prefix_update')
    subprocess.run(['/bin/cp','-cRp',str(template),str(prefix)],check=True,timeout=30)
    need(prefix_inventory(prefix)==inventory,'game_prefix_clone')
    modules=stage_modules(prefix,runtime,candidate,fixture_context=fixture_context)
    for p in (work/'work',work/'work/tmp',work/'home'):p.mkdir(mode=0o700)
    target=None
    result = dict(schema_version=1,scope='development_direct_fixture_v1',kind='game_startup_observation',
        producer_ref=fact(Path(__file__)),producers_ref=fact(output/'producers.json'),
        inputs_ref=fixture_context.ref if fixture_context is not None else fact(inputs/'inputs.json'),runtime_ref=fact(runtime/'runtime.json'),target_identity=target,
        diagnostic_only=True,game_qualified=False,guest_execution_qualified=False,
        runtime_sha256=fact(runtime/'runtime.json')['sha256'],source_files=sources,snapshot_ref=None if fixture_context is not None else fact(snapshot),
        prefix_origin=dict(seed_ref=fact(seed/'case.json'),inventory=inventory,prepared_nsi_ref=None),
        steam_account_flow='unperformed; normal game Steam checks retained',
        requested=dict(candidate=candidate.name,observations=selected_env,samples=list(samples),fixture=fixture,trace=trace,signal_resume=signal_resume,query_observation=query_observation,entry_observation=entry_observation,link_observation=link_observation,budget=budget,abort_observation=abort_observation,log_budget=log_budget),
        applied=dict(candidate=candidate.name,deadline_seconds=seconds,stream_limit_bytes=selected_limit,modules=modules,native_owner=fact(runtime/preparation.NATIVE),
                     observation_environment=selected_env,trace_environment=selected_trace,signal_environment=selected_signal,query_environment=selected_query,entry_environment=selected_entry,link_environment=selected_link),observed={})
    if fixture_context is not None:
        result.update(kind='runtime_fixture_observation',fixture_context_ref=fixture_context.ref,
                      game_inputs_required=False,steam_account_flow='not applicable to redistributable fixtures')
    mismatch_selected = False
    target_selected = False
    writer_selected = False
    attach_selected = False
    idempotent_selected = False
    target_value2_selected = False
    if candidate.name in ('d25-fixture','d25-game'):
        selected = fixture_context.selected
        mismatch_selected = selected.get('mismatch_observer') is True
        target_selected = selected.get('target_observer') is True
        target_value2_selected = selected.get('target_value2_observer') is True
        writer_selected = selected.get('writer_observer') is True
        attach_selected = selected.get('attach_observer') is True
        idempotent_selected = selected.get('idempotent_repair') is True
    need(play_adapter_factory is None or (attach_selected and fixture is None),'direct_play_adapter_scope')
    need(not attach_selected or fixture is not None or play_adapter_factory is not None,'direct_play_adapter_required')
    execution_interval=fixture_context.execution_interval(output)
    if fixture_context is not None:fixture_context.mark('prefix_and_case_preparation')
    with execution_interval:
        if candidate.name in ('d23-16384','d23-65536','d24-131072','d25-fixture','d25-game'):
            print('current authorization',flush=True); admission(runtime,value,output/'before',reuse)
        if fixture_context is not None:fixture_context.mark('live_gate_and_authority_before')
        with supervisor.supervision(reuse) as (life,helpers):
            # Only this private helper namespace changes; shared supervisor defaults stay intact.
            helpers.base.STREAM_LIMIT = selected_limit
            nonce = uuid.uuid4().hex; packet = supervisor.assessment_packet(value)
            session = helpers.api.APISession(work,runtime,packet,nonce,suite='api-abi',case_id='first-dispatch')
            env = supervisor.environment(work/'work',prefix,nonce,str(work/'home'))
            env.update(WINEDEBUG=selected_trace,PEAR_METAL_PIPELINE_OBSERVE='1',PEAR_IMAGE_ADMISSION_DIAGNOSTIC='1')
            env.update(METAL_ENV); env.update(selected_env); env.update(selected_signal); env.update(selected_query); env.update(selected_entry); env.update(selected_link); env.update(abort_env)
            if fixture in ('rendering-original','presentation-original'):
                # Reuse the graphics fixture's bounded trace policy; +file traces
                # every byte of its readback output and exhausts the log budget.
                env.update(MTL_SHADER_VALIDATION_DEFAULT_STATE='all',MTL_SHADER_VALIDATION_ENABLE_ERROR_REPORTING='1',MTL_SHADER_VALIDATION_DUMP_PIPELINES='1',MTL_SHADER_VALIDATION_GLOBAL_MEMORY='1',MTL_SHADER_VALIDATION_TEXTURE_USAGE='1')
            if fixture == 'presentation-original':
                env['PEAR_PRESENT_OBSERVE'] = '1'
            paths = {k:runtime/v for k,v in value['entrypoints'].items()}
            read_fd = control = None; error = None; outcome = 'not_started'; refusal = None
            interrupted = None
            started = time.monotonic(); deadline = started + seconds
            remaining = lambda cap:max(0,min(cap,deadline-time.monotonic()))
            launches = []
            def launch(role,args,environment,**kwargs):
                child = session.launch(role,args,environment,**kwargs)
                launches.append(dict(role=role,argv=args,environment=environment,pid=child.pid)); return child
            sampler = SampleWindows(session,output,deadline,env,launch,samples,sample_interval(candidate,samples))
            attach_time = None
            play_adapter = None
            print(f'starting owned direct diagnostic ({seconds} second bound)',flush=True)
            try:
                if play_adapter_factory is not None:
                    play_adapter=play_adapter_factory(session=session,output=output,candidate=candidate,selection=selected,sampler=sampler,deadline=deadline,launch=launch,environment=env)
                graphical = helpers.api.graphical_session()
                need(graphical == {'status':0,'available':True}, 'translated_graphical_session')
                result['graphical_session'] = graphical
                read_fd,control = os.pipe()
                sentinel = launch('sentinel',[str(paths['sentinel']),str(read_fd)],env,pass_fds=(read_fd,))
                os.close(read_fd); read_fd = None
                need(session.wait_for(lambda:b'\n' in session.streams[('sentinel','stdout')]['data'],remaining(5)), 'integration_sentinel_start')
                helpers.base.validate_helper(helpers.base.parse_lines(session,'sentinel')[0],'pear_sentinel_ready',sentinel)
                server = launch('server',[str(paths['server']),'-f','-p'],env,event_pipe=True)
                need(session.wait_for(lambda:any(r.get('event') == 'server_ready' for r in session.events['server']) or server.exited,remaining(30)) and not server.exited, 'integration_server_start')
                loader_env = {**env,'PEAR_STAGE3_CONTROL':session.endpoint,'PEAR_WINE_ABI_FIXTURE':'1',
                    'PEAR_BOOTSTRAP_SERVER_PID':str(server.pid),'WINEDLLOVERRIDES':'d3d11,dxgi,d3d10core,winemetal=b;mscoree='}
                arguments=[]
                declared=value['fixtures'][fixture];executable=runtime/declared['path']
                need(fact(executable)['sha256']==declared['sha256'],'direct_fixture_bytes')
                result['diagnostic_fixture']=dict(name=fixture,artifact=fact(executable),expected_exit=FIXTURES[fixture])
                session.output = work/'work'
                try:
                    loader = launch('loader',[str(paths['bootstrap_helper']),'--exec-4k',str(paths['loader']),str(executable),*arguments],loader_env,allowed_paths=[paths['bootstrap_helper'],paths['loader']])
                finally:
                    session.output = work
                handoff=None
                def finished():
                    nonlocal refusal, attach_time
                    data = bytes(session.streams.get(('loader','stderr'),{}).get('data',b''))
                    refusal = finish_reason(data,loader.pid,target)
                    if refusal is not None and 'refusal_received_ns' not in result:
                        result['refusal_received_ns'] = time.monotonic_ns()
                    if attach_time is None and attached(data):
                        attach_time = time.monotonic();result['gameassembly_attach_received_ns'] = time.monotonic_ns()
                    terminal=loader.exited or refusal is not None or session.failure is not None
                    pump_observations(play_adapter,handoff,sampler,loader,attach_time,data,
                        {loader.pid}|{row['identity']['pid'] for row in session.observer.registrations.values()},terminal)
                    # Adapter probes may consume EXIT after the earlier pump snapshot.
                    data=bytes(session.streams.get(('loader','stderr'),{}).get('data',b''))
                    refusal=refusal or finish_reason(data,loader.pid,target)
                    terminal=terminal or loader.exited or refusal is not None or session.failure is not None
                    if refusal is not None and 'refusal_received_ns' not in result:
                        result['refusal_received_ns']=time.monotonic_ns()
                    return terminal or bool(handoff and handoff.done)
                completed = session.wait_for(finished,remaining(seconds))
                while not completed and ((play_adapter is not None and play_adapter.continue_supervision) or (play_adapter is None and handoff is not None and handoff.held)):
                    completed=session.wait_for(finished,5)
                if play_adapter is not None:
                    result['play_handoff']=play_adapter.snapshot()
                elif handoff is not None and handoff.held:
                    result['menu_handoff']=dict(confirmation=handoff.confirmation,user_test_finished=handoff.done,supervisor_retained=True)
                    result['applied']['post_menu_supervised_wait']=True
                outcome = ('image_refused' if refusal.startswith('PEAR_IMAGE_ADMISSION') else 'owner_refused') if refusal else 'exited' if completed else 'timeout'
            except BaseException as exc:
                error = dict(type=type(exc).__name__,code=getattr(exc,'code',str(exc)),at_ns=time.monotonic_ns(),phase='owned-run'); outcome = 'error'
                if isinstance(exc,(KeyboardInterrupt,SystemExit)) or getattr(exc,'code',None)=='assembly_worker_timeout':
                    interrupted=exc
            finally:
                if play_adapter is not None:
                    try:
                        play_adapter.close()
                        result['play_handoff']=play_adapter.snapshot()
                        result['play_companions']=fact(output/'play/companion-result.json')
                    except BaseException as exc:result['play_cleanup_error']=getattr(exc,'code',type(exc).__name__)
                try:
                    sampler.cancel()
                except BaseException as exc:
                    result['sampler_cleanup_error'] = getattr(exc,'code',type(exc).__name__)
                before,cleanup,sentinel_cleanup,logs,survived,cleanup_errors = life.cleanup_session(session,control,read_fd,work)
            if play_adapter is not None and 'loader' in locals():
                result['post_cleanup_terminal_evidence']=dict(at_ns=time.monotonic_ns(),
                    scope='Final drain only; does not establish pre-error observation order',
                    refusal=finish_reason(bytes(session.streams.get(('loader','stderr'),{}).get('data',b'')),loader.pid,target),
                    loader_exit=loader.exit_code,registered_exit=session.observer.registrations.get(loader.pid))
            result.update(outcome=outcome,error=error,stream_error=session.failure,events=session.events,logs=logs,
                cleanup=cleanup,sentinel_cleanup=sentinel_cleanup,sentinel_survived=survived,cleanup_errors=cleanup_errors,
                pre_cleanup=before,elapsed_ms=round((time.monotonic()-started)*1000),launches=launches,
                registrations=list(session.observer.registrations.values()),signal_observations=session.observer.signal_observations,
                processes={role:dict(identity=child.identity,exit_code=child.exit_code,reaped=child.reaped,allowed_paths=sorted(child.allowed_paths)) for role,child in session.children.items()},
                observed_owner_refusal=refusal)
            result['applied']['launches'] = launches
            result['observed'] = dict(stream_limit_bytes=helpers.base.STREAM_LIMIT,outcome=outcome,owner_refusal=refusal,samples=sampler.rows,menu='unconfirmed',steamworks='unperformed',
                loader_trace_environment=next((r['environment']['WINEDEBUG'] for r in launches if r['role'] == 'loader'),None),
                loader_signal_environment=next(({k:r['environment'][k] for k in (SIGNAL_KEY,) if k in r['environment']} for r in launches if r['role'] == 'loader'),None))
            result['observed']['loader_link_environment'] = next(({k:r['environment'][k] for k in (link.KEY,) if k in r['environment']} for r in launches if r['role']=='loader'),None)
            result['observed']['loader_entry_environment'] = next(({k:r['environment'][k] for k in (entry.KEY,) if k in r['environment']} for r in launches if r['role']=='loader'),None)
            result['observed']['loader_query_environment'] = next(({k:r['environment'][k] for k in (query.KEY,) if k in r['environment']} for r in launches if r['role']=='loader'),None)
            save(output/'case.json',result)
            if interrupted is not None:raise interrupted
        if fixture_context is not None:fixture_context.mark('owned_execution_and_cleanup')
        print('execution ended; verifying unchanged authorization',flush=True)
        admission(runtime,value,output/'after',reuse); result['authorization_before_after_passed'] = True
        if fixture_context is not None:fixture_context.mark('authority_after')
    result['original_files_unchanged'] = None if fixture_context is not None else all(fact(r['path']) == r for r in sources)
    result['runtime_unchanged'] = fact(runtime/'runtime.json')['sha256'] == result['runtime_sha256']
    if fixture_context is not None:
        fixture_context.finish();fixture_context.mark('runtime_final')
    complete_provenance(producers); result['producer_dependencies_unchanged'] = True
    save(output/'case.json',result)
    assessment = assess(output); save(output/'assessment.json',assessment)
    if fixture_context is not None:fixture_context.mark('provenance_and_assessment')
    print(json.dumps(assessment,sort_keys=True))
    return assessment
