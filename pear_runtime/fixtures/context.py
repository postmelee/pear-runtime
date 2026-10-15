# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
# Adapted from Pear tools/steam/fixture_context.py; exact origin is in fixture-parent-import.json.
"""Exact new candidate and synthetic state; no owned-game inputs or saved grants."""
from pathlib import Path
import time
import shutil
from pear_runtime import build
from pear_runtime.errors import need
from pear_runtime.assembly import core
from pear_runtime.assembly._common import encoded
from pear_runtime.assembly.helpers import SourcePack, signing_helpers, PAYLOAD
from .inputs import fact, read, save
from .types import Selection
from .supervision import prefix_inventory, source_refs
from . import producers

NAMES=('tls-thread','seh-unwind','suspend-context','code-invalidation',
       'guest-fault-guard','configured-memory','rendering-original')
FIELDS={'schema_version','scope','candidate','runtime_ref','operation_ref','profile_ref',
        'capabilities_ref','provider_root','producer_manifest_ref','fixture_refs',
        'seed_root','seed_ref','seed_inventory','modules','output_root'}
CAPABILITIES=('abort_observer','mismatch_observer','target_observer',
              'target_value2_observer','writer_observer','attach_observer',
              'idempotent_repair','binding_census','slot_lifetime_observer')


def capability_binding(ref, runtime):
    value=core.read_ref(ref)
    need(set(value)=={'schema_version','scope','catalog_ref','fex_build_ref'} and
         type(value['schema_version']) is int and value['schema_version']==1 and value['scope']=='compiled_runtime_capabilities',
         'fixture_capability_shape')
    catalog_path=Path(__file__).with_name('capabilities')/'d36.json'
    need(value['catalog_ref']==build.fact(catalog_path),'fixture_capability_catalog')
    catalog=core.read_ref(value['catalog_ref'])
    need(value['fex_build_ref'] in runtime['development_assembly']['builds'],
         'fixture_capability_build_binding')
    built=core.read_ref(value['fex_build_ref'])
    need(built.get('scope')=='development_component_build' and built['status']=='passed' and
         built.get('runtime_eligible') is False and built.get('game_qualified') is False and
         built['roots']['fex']['kind']=='git' and built['roots']['fex']['commit']==catalog['source_commit'] and
         built['public_recipe']['sha256']==catalog['public_recipe_sha256'] and
         built['artifacts']['fex_pe']==runtime['development_assembly']['artifacts']['fex_pe'],
         'fixture_capability_compiled_source')
    compiled_capabilities(built,catalog)
    capabilities=catalog['capabilities']
    need(set(capabilities)==set(CAPABILITIES) and all(type(v) is bool for v in capabilities.values()),
         'fixture_capability_values')
    for row in (ref,value['catalog_ref'],value['fex_build_ref']):core.checked_ref(row)
    return dict(capabilities)



def compiled_capabilities(built,catalog):
    """Join every capability unit to its actual successful compiler arguments.

    Git source units are recorded by depfile evidence, not the retained operand
    inputs list. The complete ordered define subsequence must match the catalog;
    undefines, response files and split/forwarded overrides are not admitted.
    """
    units=catalog['compile_units']
    need(type(units) is list and len(units)==3 and len({u['path'] for u in units})==3,
         'fixture_capability_units')
    source_root=Path(built['roots']['fex']['path'])
    need(source_root.is_absolute() and source_root.resolve(strict=True)==source_root,
         'fixture_capability_source_root')
    commands=built['commands']
    need(type(commands) is list,'fixture_capability_commands')
    compiles=[]
    for row in commands:
        argv=row.get('argv')
        need(type(argv) is list and argv and all(type(a) is str for a in argv),
             'fixture_capability_argv')
        if '-c' in argv:compiles.append(row)
    need(len(compiles)==3,'fixture_capability_compile_set')
    for unit in units:
        parts=unit['path'].split('/')
        need(not unit['path'].startswith('/') and all(p not in ('','.','..') for p in parts),
             'fixture_capability_source_path')
        source=str(source_root.joinpath(*parts))
        matches=[row for row in compiles if row['argv'].count('-c')==1 and
                 row['argv'].index('-c')+1<len(row['argv']) and row['argv'][row['argv'].index('-c')+1]==source]
        need(len(matches)==1,'fixture_capability_compile_unit')
        row=matches[0];argv=row['argv']
        need(type(row.get('exit_code')) is int and row['exit_code']==0 and row.get('error') is None,
             'fixture_capability_compile_failed')
        defines=[a for a in argv if a.startswith('-D')]
        need(type(unit['required_defines']) is list and defines==unit['required_defines'] and
             all(a!='-D' and not a.startswith(('-U','@','-Wp,')) and a not in ('-Xclang','-Xpreprocessor') for a in argv) and
             len({a[2:].split('=',1)[0] for a in defines})==len(defines),
             'fixture_capability_compile_defines')
        groups=[g for g in built['dependencies'] if any(f.get('path')==source for f in g.get('files',[]))]
        need(len(groups)==1,'fixture_capability_dependency_group')
        facts=[f for f in groups[0]['files'] if f.get('path')==source]
        need(len(facts)==1 and facts[0]==dict(path=source,sha256=unit['sha256'],size_bytes=unit['size_bytes']),
             'fixture_capability_unit')
        need(argv.count('-MF')==1 and argv.index('-MF')+1<len(argv) and
             argv[argv.index('-MF')+1]==groups[0]['depfile']['path'],'fixture_capability_depfile')
        core.checked_ref(groups[0]['depfile'])
        for log in row['logs'].values():core.checked_ref(log)


def inventory_shape(rows):
    need(type(rows) is list and rows,'fixture_context_seed_inventory')
    seen=set()
    for row in rows:
        need(type(row) is dict and type(row.get('path')) is str,'fixture_context_seed_inventory')
        path=row['path'];parts=path.split('/')
        need(path not in seen and not path.startswith('/') and '\\' not in path and
             all(p not in ('','.','..') for p in parts),'fixture_context_seed_path_unsafe')
        seen.add(path);kind=row.get('kind')
        if kind=='link':
            need(set(row)=={'path','kind','target'} and (path,row['target']) in
                 {('dosdevices/c:','../drive_c'),('dosdevices/z:','/')},'fixture_context_seed_link')
        else:
            need(kind in ('file','directory') and type(row.get('mode')) is int and 0<=row['mode']<=0o7777,
                 'fixture_context_seed_inventory')
            if kind=='file':
                need(set(row)=={'path','kind','mode','size','sha256'} and type(row['size']) is int and
                     0<=row['size']<=8*1024**3 and type(row['sha256']) is str and len(row['sha256'])==64 and
                     all(c in '0123456789abcdef' for c in row['sha256']),'fixture_context_seed_file')
            else:need(set(row)=={'path','kind','mode'},'fixture_context_seed_directory')


def descriptor(ref):
    value=core.read_ref(ref)
    need(set(value)==FIELDS and type(value['schema_version']) is int and value['schema_version']==1 and
         value['scope']=='redistributable_runtime_fixtures' and value['candidate']=='d25-game',
         'fixture_context_shape')
    for key in ('runtime_ref','operation_ref','profile_ref','capabilities_ref','producer_manifest_ref','seed_ref'):
        core.checked_ref(value[key])
    runtime=core.read_ref(value['runtime_ref'])
    core.completed_operation(value['runtime_ref'],runtime,value['operation_ref'])
    need(runtime.get('passed') is True and runtime.get('diagnostic_only') is True and
         runtime.get('runtime_qualified') is False and runtime.get('runtime_eligible') is False and
         runtime.get('game_qualified') is False and runtime.get('execution_authorized_by_this_record') is False,
         'fixture_context_runtime_scope')
    need(runtime['development_assembly']['profile_ref']==value['profile_ref'], 'fixture_context_profile')
    seed=Path(value['seed_root']);provider=Path(value['provider_root']);output=Path(value['output_root'])
    for root in (seed,provider,output):
        need(root.is_absolute() and root.is_dir() and root.resolve(strict=True)==root, 'fixture_context_root_alias')
    need(value['seed_ref']['path']==str(seed/'case.json'),'fixture_context_seed_path')
    origin=core.read_ref(value['seed_ref'])
    need(origin['scope']=='translated_graphics' and origin['fixture_id']=='device' and
         origin['outcome']=='exited' and origin['error'] is None and
         origin['cleanup']['complete'] is True and origin['sentinel_survived'] is True and
         origin['cleanup_errors']==[], 'fixture_context_synthetic_seed')
    inventory_shape(value['seed_inventory'])
    need(type(value['modules']) is dict and set(value['modules'])=={'ntdll.dll','xtajit64.dll'}, 'fixture_context_modules')
    for name,row in value['modules'].items():
        need(type(row) is dict and set(row)=={'seed_sha256','selected_ref'} and
             type(row['seed_sha256']) is str and len(row['seed_sha256'])==64 and
             all(c in '0123456789abcdef' for c in row['seed_sha256']), 'fixture_context_module_shape')
        core.checked_ref(row['selected_ref'])
    need(type(value['fixture_refs']) is dict and set(value['fixture_refs'])==set(NAMES),'fixture_context_fixture_set')
    for row in value['fixture_refs'].values():core.checked_ref(row)
    runtime_root=Path(value['runtime_ref']['path']).parent
    input_roots=(seed,provider,runtime_root,Path(value['profile_ref']['path']).parent)
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in input_roots),
         'fixture_context_output_overlap')
    captured=producers.capture(value['producer_manifest_ref'],provider)
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in captured.roots.values()),
         'fixture_context_output_source_overlap')
    capability_binding(value['capabilities_ref'],runtime)
    core.checked_ref(ref)
    return value


class FixtureContext:
    def __init__(self,manifest_ref,candidate,execution_interval):
        self._clock=time.monotonic();self.timings=[]
        self.ref=dict(manifest_ref);self.value=descriptor(self.ref)
        need(type(candidate) is Selection and callable(execution_interval),'fixture_context_bindings')
        need(candidate.name==self.value['candidate'] and Path(candidate.runtime)==Path(self.value['runtime_ref']['path']).parent,
             'fixture_context_candidate')
        self.candidate=candidate
        self._producers=producers.capture(self.value['producer_manifest_ref'],self.value['provider_root'])
        self.selected=capability_binding(self.value['capabilities_ref'],core.read_ref(self.value['runtime_ref']))
        self.execution_interval=execution_interval
        self._active=False;self._completed=False;self._validated_end=False
        self._producer_rows=None;self._assessment_finalized=False
        self._output=None;self._fixture=None;self._runtime=None;self._runtime_value=None
        self.mark('descriptor')

    def mark(self,name):
        now=time.monotonic();self.timings.append(dict(name=name,seconds=now-self._clock,
            wall_utc=build.point()['wall_utc'],monotonic_seconds=now));self._clock=now

    def fresh_output(self,path):
        path=Path(path)
        need(path.is_absolute() and path.parent==Path(self.value['output_root']) and
             path.parent.resolve(strict=True)==path.parent and not path.exists() and not path.is_symlink(),
             'direct_fresh_output')
        return path

    def begin(self,fixture,output):
        need(fixture in NAMES and not self._active and not self._completed,'fixture_context_single_run')
        need(self.candidate.name==self.value['candidate'] and
             Path(self.candidate.runtime)==Path(self.value['runtime_ref']['path']).parent,
             'fixture_context_candidate')
        self._output=self.fresh_output(output);self._fixture=fixture
        try:self._runtime,self._runtime_value=self._admit()
        except BaseException:
            self._completed=True
            raise
        self._active=True
        return self._runtime,self._runtime_value

    def _admit(self):
        need(core.read_ref(self.ref)==self.value,'fixture_context_changed')
        m=self.value;runtime=Path(m['runtime_ref']['path']).parent;value=core.read_ref(m['runtime_ref'])
        core.completed_operation(m['runtime_ref'],value,m['operation_ref'])
        self._producers.recheck()
        need(value['passed'] is True and value['diagnostic_only'] is True and value['game_qualified'] is False and
             value['runtime_qualified'] is False and value['runtime_eligible'] is False and
             value['execution_authorized_by_this_record'] is False and
             capability_binding(m['capabilities_ref'],value)==self.selected,'fixture_context_runtime_scope')
        helpers,reader=signing_helpers(SourcePack(Path(m['provider_root'])))
        core.verify_closure(runtime,value,reader)
        for name,row in m['modules'].items():
            need(build.fact(runtime/PAYLOAD/'lib/wine/aarch64-windows'/name)==row['selected_ref'],
                 'fixture_context_selected_module')
        for name in NAMES:
            row=value['fixtures'][name];path=runtime/row['path']
            need(path.resolve(strict=True).is_relative_to(runtime) and build.fact(path)==m['fixture_refs'][name] and
                 m['fixture_refs'][name]['sha256']==row['sha256'],'fixture_context_fixture')
        core.checked_ref(m['seed_ref'])
        template=Path(m['seed_root'])/'run/prefix'
        need(template.is_dir() and template.resolve(strict=True)==template,'fixture_context_seed_alias')
        need(prefix_inventory(template)==m['seed_inventory'],'fixture_context_seed_changed')
        for name,row in m['modules'].items():
            need(build.fact(template/'drive_c/windows/system32'/name)['sha256']==row['seed_sha256'],
                 'fixture_context_seed_module')
        inf=runtime/PAYLOAD/'share/wine/wine.inf'
        need((template/'.update-timestamp').read_text().strip()==str(int(inf.stat().st_mtime)), 'game_prefix_update')
        return runtime,value


    def preserve_sources(self,output):
        need(self._active and Path(output)==self._output,'fixture_context_source_output')
        rows=self._producers.preserve(output)
        self._producer_rows=encoded(rows)
        return rows

    def finalize_assessment(self,output):
        """Recheck inputs and preserved source bytes after every verdict oracle."""
        need(self._completed and self._validated_end and not self._active and
             not self._assessment_finalized and Path(output)==self._output and
             self._producer_rows is not None,'fixture_context_final_assessment_scope')
        runtime,value=self._admit()
        need(runtime==self._runtime and value==self._runtime_value,'fixture_context_runtime_changed')
        # Reuse the original strict array decoder and complete source oracle.
        # This late import introduces no second implementation or launcher.
        from .direct import read_sources,complete_provenance
        rows=read_sources(Path(output)/'producers.json')
        need(encoded(rows)==self._producer_rows,'fixture_context_producer_rows_changed')
        complete_provenance(rows)
        self._assessment_finalized=True
        self.mark('post_assessment_input_validation')
        return dict(runtime_ref=self.value['runtime_ref'],producer_manifest_ref=self.value['producer_manifest_ref'],
                    producers_ref=fact(Path(output)/'producers.json'))

    def storage_admission(self,output):
        """Read-only per-run peak budget before any prefix clone or source copy."""
        output=self.fresh_output(output)
        self._producers.recheck()
        files={row['path']:row for row in self.value['seed_inventory'] if row['kind']=='file'}
        seed_bytes=sum(row['size'] for row in files.values())
        budgeted_seed=max(seed_bytes,842557436)
        growth=0
        for name,row in self.value['modules'].items():
            prior=files.get('drive_c/windows/system32/'+name)
            need(prior is not None and prior['sha256']==row['seed_sha256'],'fixture_context_seed_module')
            growth+=max(0,row['selected_ref']['size_bytes']-prior['size'])
        allowance=1024**3;reserve=6*1024**3
        additional=budgeted_seed+growth+allowance+self._producers.logical_bytes
        free=shutil.disk_usage(output.parent).free
        need(free>=additional+reserve,'fixture_storage_capacity')
        return dict(schema_version=1,scope='single_owned_fixture_run',output=str(output),
            observed_at=build.point(),seed_inventory_logical_bytes=seed_bytes,budgeted_seed_bytes=budgeted_seed,
            positive_module_growth_bytes=growth,logs_authority_metadata_allowance_bytes=allowance,
            producer_snapshot_bytes=self._producers.logical_bytes,additional_peak_bytes=additional,
            reserve_bytes=reserve,required_free_bytes=additional+reserve,observed_free_bytes=free,
            apfs_clone_savings_assumed=False,execution_authorized_by_this_record=False)

    @property
    def seed(self):return Path(self.value['seed_root'])

    @property
    def provider_root(self):return Path(self.value['provider_root'])

    def current_authority(self,runtime,value,output,reuse):
        from .admission import current
        need(self._active and runtime==self._runtime and value==self._runtime_value and
             Path(reuse)==self.provider_root,'fixture_authority_context')
        return current(self.value['runtime_ref'],self.value['operation_ref'],self.value['profile_ref'],
                       self.provider_root,output)

    def baseline(self,path):
        need(self._active,'fixture_context_not_active')
        save(path,dict(scope='runtime and synthetic prefix only',manifest_ref=self.ref,
             game_inputs_required=False,game_qualified=False,ownership_checked=False))

    def finish(self):
        need(self._active and not self._completed,'fixture_context_not_active')
        try:
            runtime,value=self._admit()
            need(runtime==self._runtime and value==self._runtime_value,'fixture_context_runtime_changed')
            self._validated_end=True
        finally:
            self._active=False;self._completed=True
        return runtime,value

    def assessed_runtime(self,run,record):
        need(self._completed and self._validated_end and not self._active and self._runtime is not None,
             'fixture_context_assessment_before_finish')
        need(Path(run)==self._output and record['diagnostic_fixture']['name']==self._fixture and
             fact(self.ref['path'])==self.ref and record.get('fixture_context_ref')==self.ref and
             record['runtime_ref']==self.value['runtime_ref'] and
             record['requested']['candidate']==self.candidate.name,'fixture_context_assessment_binding')
        return self._runtime,self._runtime_value
