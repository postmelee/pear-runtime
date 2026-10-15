# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit current candidate and exact sources for seven original native cases."""
from pathlib import Path
from types import SimpleNamespace
import shutil

from pear_runtime.assembly import core
from pear_runtime.assembly._common import encoded
from pear_runtime.assembly.helpers import SourcePack, signing_helpers
from pear_runtime.errors import need
from pear_runtime.fixtures import producers
from pear_runtime.fixtures.admission import current
from pear_runtime.fixtures.controls.context import _arena, canonical_directory
from pear_runtime.fixtures.inputs import fact, save
from pear_runtime.fixtures.types import Selection
from . import binding, api_variant
from pear_runtime.fixtures.controls.context import descriptor as seed_descriptor
from pear_runtime.fixtures.supervision import prefix_inventory
from pear_runtime.assembly.helpers import PAYLOAD
from .provider import native_helpers, WINDOW_PATH, NATIVE_SEED_POLICY

API_CASES=('api','abi','threads','window')
BOOTSTRAP_CASES=('bootstrap','bootstrap-timeout','wrong-prefix-server')
CASES=API_CASES+BOOTSTRAP_CASES
FIELDS={'schema_version','scope','runtime_ref','operation_ref','profile_ref','provider_root',
        'producer_manifest_ref','binding_ref','api_cases_ref','bootstrap_cases_ref',
        'arena_header_ref','arena_source_ref','output_root','native_prerequisites',
        'seed_context_ref','api_variant_ref'}
ENTRY_MODULES=(*producers.ENTRY_MODULES,'pear_runtime.fixtures.native.__main__',
               'pear_runtime.fixtures.native.driver','pear_runtime.fixtures.native.execution',
               'pear_runtime.fixtures.native.context')
DYNAMIC_PATHS=(*producers.DYNAMIC_PATHS,'provenance/fixture-controls-import.json',
               'provenance/fixture-controls-execution-import.json','provenance/fixture-native-import.json',WINDOW_PATH)
PRODUCER_SCOPE='fixture_native_producer_sources'


def capture(ref, provider):
    return producers.capture(ref,provider,entry_modules=ENTRY_MODULES,dynamic_paths=DYNAMIC_PATHS,
                             scope=PRODUCER_SCOPE)


def descriptor(ref):
    value=core.read_ref(ref)
    need(set(value)==FIELDS and type(value['schema_version']) is int and value['schema_version']==2 and
         value['scope']=='development_native_wine_controls','native_context_shape')
    for name in FIELDS:
        if name.endswith('_ref'): core.checked_ref(value[name])
    provider=canonical_directory(value['provider_root']); output=canonical_directory(value['output_root'])
    runtime=Path(value['runtime_ref']['path']).parent
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in
             (provider,runtime,Path(value['profile_ref']['path']).parent,
              Path(value['arena_source_ref']['path']).parent.parent)), 'native_output_overlap')
    prereqs=value['native_prerequisites']
    need(type(prereqs) is dict and (set(prereqs)==set() or set(prereqs)==set(API_CASES)), 'native_prerequisite_set')
    for row in prereqs.values():
        need(type(row) is dict and set(row)=={'assessment_ref','operation_ref'}, 'native_prerequisite_shape')
        core.checked_ref(row['assessment_ref']);core.checked_ref(row['operation_ref'])
    return value


def completed_fixture(operation_ref, assessment_ref, case_id, runtime_ref, assembly_ref):
    """Independent final worker record is required; an inner pass is insufficient."""
    operation=core.read_ref(operation_ref); assessment=core.read_ref(assessment_ref)
    need(operation.get('scope')=='development_native_fixture_execution' and operation.get('status')=='passed' and
         operation.get('released') is True and operation.get('lock',{}).get('released') is True and
         operation.get('assessment_ref')==assessment_ref and
         operation.get('case_id')==case_id and operation.get('runtime_ref')==runtime_ref and
         operation.get('assembly_operation_ref')==assembly_ref and
         type(operation.get('operation_id')) is str and operation['operation_id'], 'native_completed_operation')
    need(assessment.get('passed') is True and assessment.get('scope')=='development_native_fixture_assessment' and
         assessment.get('case_id')==case_id and assessment.get('runtime_ref')==runtime_ref and
         assessment.get('assembly_operation_ref')==assembly_ref and
         assessment.get('execution_operation')=={'path':operation_ref['path'], 'operation_id':operation['operation_id']},
         'native_completed_assessment')
    need(assessment_ref['path']==str(Path(operation['plan']['output'])/'native-assessment.json') and
         Path(operation_ref['path']).name=='operation.json','native_completed_output')
    core.checked_ref(assessment['case_ref'])
    core.checked_ref(assessment['producer_snapshot_ref'])
    for side in ('before_ref','after_ref'):
        authority=core.read_ref(assessment[side])
        need(authority.get('passed') is True and authority.get('runtime_sha256')==runtime_ref['sha256'] and
             authority.get('operation_ref')==assembly_ref,'native_completed_authority')
    return assessment


class NativeContext:
    def __init__(self, context_ref, candidate, execution_interval=None):
        self.ref=dict(context_ref); self.value=descriptor(self.ref)
        need(type(candidate) is Selection and candidate.name=='d25-game' and
             Path(candidate.runtime)==Path(self.value['runtime_ref']['path']).parent and
             (execution_interval is None or callable(execution_interval)), 'native_context_binding')
        self.candidate=candidate;self.execution_interval=execution_interval
        self.execution_operation=None
        self._producers=capture(self.value['producer_manifest_ref'],self.provider_root)
        output=Path(self.value['output_root'])
        need(all(not output.is_relative_to(root) and not root.is_relative_to(output)
                 for root in self._producers.roots.values()), 'native_source_output_overlap')
        self._active=self._completed=self._validated_end=False
        self._case=self._output=self._source_rows=None
        self._admit()

    @property
    def seed(self): return Path(self.base['seed_root'])

    @property
    def provider_root(self): return Path(self.value['provider_root'])

    def _admit(self):
        need(descriptor(self.ref)==self.value,'native_context_changed');self._producers.recheck()
        runtime=Path(self.value['runtime_ref']['path']).parent
        packet=core.read_ref(self.value['runtime_ref'])
        core.completed_operation(self.value['runtime_ref'],packet,self.value['operation_ref'])
        need(packet.get('passed') is True and packet.get('diagnostic_only') is True and
             all(packet.get(key) is False for key in ('runtime_qualified','runtime_eligible','game_qualified',
                  'execution_authorized_by_this_record')) and
             packet['development_assembly']['profile_ref']==self.value['profile_ref'],'native_candidate_scope')
        _,reader=signing_helpers(SourcePack(self.provider_root));core.verify_closure(runtime,packet,reader)
        _arena(self.value,packet)
        inputs,self.input_evidence=binding.verify(self.value['binding_ref'],runtime,packet,self.provider_root)
        need(inputs['wine_source_ref']==self.value['arena_source_ref'],'native_source_manifest_join')
        self.inputs=inputs
        self.variant=api_variant.verify(self.value['api_variant_ref'],inputs,runtime,packet,self.provider_root)
        self._admit_seed(runtime)
        protected=(self.seed,Path(self.variant['fixture_ref']['path']).parent,Path(inputs['build_ref']['path']).parent,
                   Path(packet['development_assembly']['input_runtime']['path']).parent)
        output=Path(self.value['output_root'])
        need(all(not output.is_relative_to(root) and not root.is_relative_to(output)
                 for root in protected),'native_retained_input_output_overlap')
        need(not any(Path(self.value[key]['path']).is_relative_to(output)
                     for key in FIELDS if key.endswith('_ref')),'native_descriptor_output_overlap')
        with native_helpers(self.provider_root) as (_,helpers):
            self.api_cases=helpers.api.validate_cases(core.read_ref(self.value['api_cases_ref']),'mac-driver')
            self.bootstrap_cases=helpers.base.validate_cases(core.read_ref(self.value['bootstrap_cases_ref']))
        fixture=core.read_ref(inputs['fixture_manifest_ref'])
        owner=Path(inputs['fixture_manifest_ref']['path']).parent.parent
        for name,path in [('api_cases_ref','pear/tests/cases-stage5.json'),('bootstrap_cases_ref','pear/tests/cases.json')]:
            selected=[row for row in fixture['files'] if row['path']==path]
            need(len(selected)==1 and self.value[name]['path']==str(owner/path) and
                 self.value[name]['sha256']==selected[0]['sha256'] and
                 self.value[name]['size_bytes']==selected[0]['size_bytes'],'native_cases_source_join')
        return runtime,packet

    def _admit_seed(self, runtime):
        seed_value,base=seed_descriptor(self.value['seed_context_ref'])
        need(all(base[key]==self.value[key] for key in ('runtime_ref','operation_ref','profile_ref','provider_root')),
             'native_seed_candidate_join')
        template=Path(base['seed_root'])/'run/prefix'
        need(template.is_dir() and template.resolve(strict=True)==template and
             prefix_inventory(template)==base['seed_inventory'],'native_seed_changed')
        need(base['seed_ref']['path']==str(Path(base['seed_root'])/'case.json'),'native_seed_origin_path')
        origin=core.read_ref(base['seed_ref'])
        need(origin['scope']=='translated_graphics' and origin['fixture_id']=='device' and
             origin['outcome']=='exited' and origin['error'] is None and origin['cleanup']['complete'] is True and
             origin['sentinel_survived'] is True and origin['cleanup_errors']==[],'native_seed_origin')
        for name,row in base['modules'].items():
            need(fact(runtime/PAYLOAD/'lib/wine/aarch64-windows'/name)==row['selected_ref'] and
                 fact(template/'drive_c/windows/system32'/name)['sha256']==row['seed_sha256'],
                 'native_seed_module')
        inf=runtime/PAYLOAD/'share/wine/wine.inf'
        need((template/'.update-timestamp').read_text().strip()==str(int(inf.stat().st_mtime)),
             'native_seed_update_timestamp')
        self.base,self.seed_value=base,seed_value
        self.seed_adapter=SimpleNamespace(seed=Path(base['seed_root']),base=base,value=seed_value)

    def fresh_output(self, output):
        path=Path(output)
        need(path.is_absolute() and path.parent==Path(self.value['output_root']) and
             path.parent.resolve(strict=True)==path.parent and not path.exists() and not path.is_symlink(),
             'native_fresh_output')
        return path

    def storage_admission(self, output):
        path=self.fresh_output(output);self._producers.recheck()
        metadata_bytes=sum(row['size_bytes'] for row in self._source_inputs())
        allowance=842557436+1024**3+self._producers.logical_bytes+metadata_bytes;reserve=6*1024**3
        free=shutil.disk_usage(path.parent).free
        need(free>=allowance+reserve,'native_storage_capacity')
        return dict(scope='single_fresh_native_wine_prefix',output=str(path),additional_peak_bytes=allowance,
                    reserve_bytes=reserve,observed_free_bytes=free,apfs_clone_savings_assumed=False,
                    producer_and_input_snapshot_bytes=self._producers.logical_bytes+metadata_bytes,
                    prefix_policy={'native_pe':NATIVE_SEED_POLICY,'bootstrap':'fresh-empty-bootstrap-no-pe'},
                    cold_prefix_initialization=False,execution_authorized_by_this_record=False)

    def begin(self, case_id, output):
        need(case_id in CASES and not self._active and not self._completed and callable(self.execution_interval),
             'native_single_execution')
        need(type(self.execution_operation) is dict and set(self.execution_operation)=={'path','operation_id'},
             'native_execution_operation_binding')
        self._output=self.fresh_output(output); self._case=case_id
        if case_id in BOOTSTRAP_CASES:
            need(set(self.value['native_prerequisites'])==set(API_CASES),'native_current_api_required')
            for name,row in self.value['native_prerequisites'].items():
                assessment=completed_fixture(row['operation_ref'],row['assessment_ref'],name,self.value['runtime_ref'],
                                  self.value['operation_ref'])
                prior=descriptor(assessment['context_ref'])
                keys=FIELDS-{'native_prerequisites','output_root'}
                need(all(prior[key]==self.value[key] for key in keys),'native_prerequisite_input_set')
        try:self._runtime,self._packet=self._admit()
        except BaseException:self._completed=True;raise
        self._active=True
        return self._runtime,self._packet

    def _source_inputs(self):
        refs=[self.ref]+[self.value[name] for name in ('binding_ref','api_cases_ref','bootstrap_cases_ref',
              'arena_header_ref','arena_source_ref')]
        refs += [self.inputs[name] for name in ('build_ref','installed_manifest_ref','fixture_manifest_ref')]
        refs += list(self.inputs['source_refs'].values())
        refs += self.variant['snapshots']+[self.value['seed_context_ref'],self.seed_value['candidate_context_ref'],self.base['seed_ref']]
        return refs

    def preserve_sources(self, output):
        need(self._active and Path(output)==self._output,'native_source_output')
        rows=self._producers.preserve(output)
        refs=self._source_inputs()
        extra=Path(output)/'native-input-sources';extra.mkdir(mode=0o700)
        for i,ref in enumerate(refs):
            path=core.checked_ref(ref);target=extra/(str(i)+'-'+path.name)
            with target.open('xb') as stream:stream.write(path.read_bytes())
            target.chmod(0o600);snapshot=fact(target)
            need(snapshot['sha256']==ref['sha256'] and snapshot['size_bytes']==ref['size_bytes'],'native_source_snapshot')
            rows.append({'original':ref,'snapshot':snapshot})
        save(Path(output)/'native-producers.json',{'files':rows});self._source_rows=encoded(rows)
        return rows

    def current_authority(self, output):
        need(self._active,'native_inactive')
        return current(self.value['runtime_ref'],self.value['operation_ref'],self.value['profile_ref'],
                       self.provider_root,output)

    def finish(self):
        need(self._active and not self._completed,'native_inactive')
        try:
            runtime,packet=self._admit()
            need(runtime==self._runtime and packet==self._packet,'native_candidate_changed')
            self._validated_end=True
        finally:self._active=False;self._completed=True

    def finalize_assessment(self, output):
        need(self._completed and self._validated_end and not self._active and Path(output)==self._output,
             'native_assessment_interval')
        self._admit()
        rows=core.read_ref(fact(Path(output)/'native-producers.json'))['files']
        need(self._source_rows is not None and encoded(rows)==self._source_rows,'native_snapshot_coverage')
        for row in rows:
            core.checked_ref(row['original']);target=core.checked_ref(row['snapshot'])
            need(target.is_relative_to(Path(output)) and row['snapshot']['sha256']==row['original']['sha256'] and
                 row['snapshot']['size_bytes']==row['original']['size_bytes'],'native_snapshot_changed')
        return fact(Path(output)/'native-producers.json')
