# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later AND MIT
"""Explicit D36 candidate, fixed CPU19/ordering inputs and one owned interval.

Adapted from the MIT Pear fixture context; the original supervisor, current
artifact authority, source capture and synthetic-prefix inventory remain shared.
No game input or historical source-root fallback is admitted.
"""
from pathlib import Path
import shutil
import time

from pear_runtime import build
from pear_runtime.assembly import core
from pear_runtime.assembly._common import encoded
from pear_runtime.assembly.helpers import SourcePack, signing_helpers, PAYLOAD
from pear_runtime.errors import need
from pear_runtime.fixtures import producers
from pear_runtime.fixtures.admission import current, prefix_inventory
from pear_runtime.fixtures.context import FIELDS as BASE_FIELDS, capability_binding, inventory_shape
from pear_runtime.fixtures.inputs import fact, read, save
from pear_runtime.fixtures.types import Selection
from . import corpus, cpu_evidence

CPU_IDS=('zero-extension','carry-widths','xor-flags','zero-shift-flags','cmpxchg-eax','xadd-widths',
    'packed-float-add','scalar-double-add','float-to-integer','configured-memory',
    'absolute-displacement','avx-lane-preservation','api-callback','tls-thread','guest-fault-guard',
    'code-invalidation','suspend-context','abi-state','seh-unwind')
CASES=CPU_IDS+('ordering',)
FIELDS={'schema_version','scope','candidate_context_ref','producer_manifest_ref',
        'source_provider','input_pack_ref','tool_refs','output_root'}
ENTRY_MODULES=('pear_runtime.fixtures.controls.cpu_driver', 'pear_runtime.fixtures.controls.cpu_context',
               'pear_runtime.fixtures.controls.cpu_execution', 'pear_runtime.fixtures.controls.cpu_evidence')
DYNAMIC_PATHS=(*producers.DYNAMIC_PATHS,'provenance/fixture-controls-import.json',
               'provenance/fixture-cpu-import.json','provenance/cpu-source-import.json')
PRODUCER_SCOPE='fixture_cpu_producer_sources'


def descriptor(ref):
    value=core.read_ref(ref)
    need(set(value)==FIELDS and type(value['schema_version']) is int and value['schema_version']==1 and
         value['scope']=='development_cpu_controls','cpu_context_shape')
    base=core.read_ref(value['candidate_context_ref'])
    need(set(base)==BASE_FIELDS and base['scope']=='redistributable_runtime_fixtures' and
         base['candidate']=='d25-game','cpu_candidate_input_shape')
    for name in ('runtime_ref','operation_ref','profile_ref','capabilities_ref','producer_manifest_ref','seed_ref'):
        core.checked_ref(base[name])
    for name in ('producer_manifest_ref','input_pack_ref'):core.checked_ref(value[name])
    provider=value['source_provider']
    need(type(provider) is dict and set(provider)=={'root','commit'},'cpu_source_provider_shape')
    cpu_evidence.canonical_directory(provider['root'])
    for name in ('seed_root','provider_root'):cpu_evidence.canonical_directory(base[name])
    output=cpu_evidence.canonical_directory(value['output_root'])
    need(type(value['tool_refs']) is dict and set(value['tool_refs'])=={'copy'} and
         value['tool_refs']['copy']['path']=='/bin/cp','cpu_copy_tool')
    core.checked_ref(value['tool_refs']['copy'])
    inventory_shape(base['seed_inventory'])
    need(type(base['modules']) is dict and set(base['modules'])=={'ntdll.dll','xtajit64.dll'},'cpu_modules')
    for row in base['modules'].values():
        need(type(row) is dict and set(row)=={'seed_sha256','selected_ref'},'cpu_module_shape')
        core.checked_ref(row['selected_ref'])
    roots=(Path(base['seed_root']),Path(base['provider_root']),Path(base['runtime_ref']['path']).parent,
           Path(base['profile_ref']['path']).parent,Path(value['input_pack_ref']['path']).parent,
           Path(provider['root']))
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in roots),
         'cpu_output_overlap')
    return value,base


class CPUContext:
    def __init__(self,ref,candidate,execution_interval=None):
        self.ref=dict(ref);self.value,self.base=descriptor(ref)
        need(type(candidate) is Selection and candidate.name=='d25-game' and
             Path(candidate.runtime)==Path(self.base['runtime_ref']['path']).parent and
             (execution_interval is None or callable(execution_interval)),'cpu_context_binding')
        self.candidate=candidate;self.execution_interval=execution_interval
        supplied=self.value['source_provider']
        self.provider=corpus.bind_provider(supplied['root'],supplied['commit'])
        need(tuple(corpus.fixture_ids(corpus.manifest()))==CPU_IDS,'cpu_fixed_case_table')
        self._producers=producers.capture(self.value['producer_manifest_ref'],self.base['provider_root'],
            entry_modules=ENTRY_MODULES,dynamic_paths=DYNAMIC_PATHS,scope=PRODUCER_SCOPE)
        need(self._producers.roots.get('fex')==self.provider.root,'cpu_producer_fex_binding')
        output=Path(self.value['output_root'])
        need(all(not output.is_relative_to(root) and not root.is_relative_to(output)
                 for root in self._producers.roots.values()),'cpu_output_source_overlap')
        self._active=self._completed=self._validated_end=False
        self._case=self._output=self._runtime=self._runtime_value=self._source_rows=None
        self.timings=[];self._clock=time.monotonic();self._admit()

    @property
    def seed(self):return Path(self.base['seed_root'])

    @property
    def provider_root(self):return Path(self.base['provider_root'])

    def mark(self,name):
        now=time.monotonic();self.timings.append(dict(name=name,seconds=now-self._clock,**build.point()));self._clock=now

    def _admit(self):
        value,base=descriptor(self.ref)
        need(value==self.value and base==self.base,'cpu_inputs_changed')
        self._producers.recheck();self.provider.recheck()
        runtime=Path(base['runtime_ref']['path']).parent;packet=core.read_ref(base['runtime_ref'])
        core.completed_operation(base['runtime_ref'],packet,base['operation_ref'])
        need(packet['passed'] is True and packet['diagnostic_only'] is True and
             all(packet[k] is False for k in ('runtime_qualified','runtime_eligible','game_qualified',
                 'execution_authorized_by_this_record')) and
             packet['development_assembly']['profile_ref']==base['profile_ref'],'cpu_runtime_scope')
        selected=capability_binding(base['capabilities_ref'],packet)
        need(selected['abort_observer'] is True,'cpu_d36_abort_capability')
        _,reader=signing_helpers(SourcePack(self.provider_root));core.verify_closure(runtime,packet,reader)
        for name,row in base['modules'].items():
            need(build.fact(runtime/PAYLOAD/'lib/wine/aarch64-windows'/name)==row['selected_ref'],
                 'cpu_selected_module')
        self.pack=cpu_evidence.admit_pack(value['input_pack_ref'],self.provider,base['runtime_ref'])
        need(base['seed_ref']['path']==str(self.seed/'case.json'),'cpu_seed_path')
        origin=core.read_ref(base['seed_ref'])
        need(origin['scope']=='translated_graphics' and origin['fixture_id']=='device' and
             origin['outcome']=='exited' and origin['error'] is None and origin['cleanup']['complete'] is True and
             origin['sentinel_survived'] is True and origin['cleanup_errors']==[],'cpu_synthetic_seed_origin')
        template=self.seed/'run/prefix'
        need(template.is_dir() and template.resolve(strict=True)==template and
             prefix_inventory(template)==base['seed_inventory'],'cpu_seed_changed')
        for name,row in base['modules'].items():
            need(build.fact(template/'drive_c/windows/system32'/name)['sha256']==row['seed_sha256'],
                 'cpu_seed_module')
        inf=runtime/PAYLOAD/'share/wine/wine.inf'
        need((template/'.update-timestamp').read_text().strip()==str(int(inf.stat().st_mtime)),
             'cpu_prefix_update')
        return runtime,packet

    def fresh_output(self,output):
        path=Path(output)
        need(path.is_absolute() and path.parent==Path(self.value['output_root']) and
             path.parent.resolve(strict=True)==path.parent and not path.exists() and not path.is_symlink(),
             'cpu_fresh_output')
        return path

    def storage_admission(self,output):
        output=self.fresh_output(output);self._producers.recheck()
        files={r['path']:r for r in self.base['seed_inventory'] if r['kind']=='file'}
        seed=sum(r['size'] for r in files.values());growth=0
        for name,row in self.base['modules'].items():
            before=files.get('drive_c/windows/system32/'+name)
            need(before is not None and before['sha256']==row['seed_sha256'],'cpu_seed_module')
            growth+=max(0,row['selected_ref']['size_bytes']-before['size'])
        sources=self._producers.logical_bytes+sum(r['size_bytes'] for r in self._extra_refs().values())
        additional=max(seed,842557436)+growth+sources+1024**3;reserve=6*1024**3
        free=shutil.disk_usage(output.parent).free
        need(free>=additional+reserve,'cpu_storage_capacity')
        return dict(scope='single_owned_cpu_run',output=str(output),seed_inventory_logical_bytes=seed,
                    positive_module_growth_bytes=growth,producer_snapshot_bytes=sources,
                    additional_peak_bytes=additional,reserve_bytes=reserve,observed_free_bytes=free,
                    apfs_clone_savings_assumed=False,execution_authorized_by_this_record=False)

    def begin(self,case_id,output):
        need(case_id in CASES and not self._active and not self._completed and callable(self.execution_interval),
             'cpu_single_execution')
        self._case,self._output=case_id,self.fresh_output(output)
        try:self._runtime,self._runtime_value=self._admit()
        except BaseException:self._completed=True;raise
        self._active=True
        return self._runtime,self._runtime_value

    def _extra_refs(self):
        refs={'context.json':self.ref,'candidate-inputs.json':self.value['candidate_context_ref'],
              'input-pack.json':self.value['input_pack_ref']}
        for row in self.provider.files:
            if row['path'].endswith('.json'):
                refs[Path(row['path']).name]=dict(row,path=str(self.provider.root/row['path']))
        return refs

    def preserve_sources(self,output):
        need(self._active and Path(output)==self._output,'cpu_source_output')
        rows=self._producers.preserve(output);extra=Path(output)/'cpu-input-sources';extra.mkdir(mode=0o700)
        for name,ref in self._extra_refs().items():
            source=core.checked_ref(ref);target=extra/name
            with target.open('xb') as stream:stream.write(source.read_bytes())
            target.chmod(0o600);snapshot=fact(target)
            need(snapshot['sha256']==ref['sha256'] and snapshot['size_bytes']==ref['size_bytes'],'cpu_snapshot_changed')
            rows.append(dict(original=ref,snapshot=snapshot))
        save(Path(output)/'cpu-producers.json',{'files':rows});self._source_rows=encoded(rows)
        return rows

    def current_authority(self,output):
        need(self._active,'cpu_not_active')
        return current(self.base['runtime_ref'],self.base['operation_ref'],self.base['profile_ref'],self.provider_root,output)

    def finish(self):
        need(self._active and not self._completed,'cpu_not_active')
        try:
            runtime,value=self._admit()
            need(runtime==self._runtime and value==self._runtime_value,'cpu_runtime_changed')
            self._validated_end=True
        finally:self._active=False;self._completed=True

    def admit_record(self,output,case_id,operation_ref):
        """Replay only a released, exact completed CPU operation; no live grant."""
        need(self.execution_interval is None and not self._active and not self._completed,
             'cpu_replay_scope')
        path=cpu_evidence.canonical_directory(output)
        need(path.parent==Path(self.value['output_root']) and case_id in CASES,'cpu_replay_output')
        cpu_evidence.completed_cpu_operation(path,case_id,operation_ref,self.ref,self.base['runtime_ref'])
        self._case,self._output=case_id,path
        self._runtime,self._runtime_value=self._admit()
        self._source_rows=encoded(read(path/'cpu-producers.json')['files'])
        self._completed=self._validated_end=True

    def finalize_assessment(self,output):
        need(self._completed and self._validated_end and not self._active and Path(output)==self._output,
             'cpu_final_assessment_scope')
        self._admit()
        rows=read(Path(output)/'cpu-producers.json')['files']
        need(encoded(rows)==self._source_rows,'cpu_snapshot_rows_changed')
        expected={ref['path']:ref for ref in self._producers.refs.values()}
        expected[self._producers.manifest_ref['path']]=self._producers.manifest_ref
        for ref in self._extra_refs().values():need(ref['path'] not in expected,'cpu_duplicate_source');expected[ref['path']]=ref
        need(len(rows)==len(expected) and {r['original']['path']:r['original'] for r in rows}==expected,'cpu_snapshot_coverage')
        for row in rows:
            core.checked_ref(row['original']);target=core.checked_ref(row['snapshot'])
            need(target.is_relative_to(Path(output)) and row['snapshot']['sha256']==row['original']['sha256'] and
                 row['snapshot']['size_bytes']==row['original']['size_bytes'],'cpu_snapshot_changed')
        return fact(Path(output)/'cpu-producers.json')
