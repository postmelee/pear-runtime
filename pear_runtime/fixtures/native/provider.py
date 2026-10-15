# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Eighteenth captured reader and original native supervisor namespace bindings."""
from contextlib import contextmanager
from pathlib import Path
from types import FunctionType, ModuleType, SimpleNamespace
import ast
import sys

from pear_runtime.assembly import core
from pear_runtime.assembly._common import read_relative
from pear_runtime.errors import need
from pear_runtime.fixtures import supervision as supervisor
from pear_runtime.fixtures.controls.execution import current_helpers
from pear_runtime.fixtures.inputs import digest, fact

WINDOW_PATH = 'pear_runtime/fixtures/native/window_evidence.py'
PROVENANCE_PATH = 'provenance/fixture-native-import.json'


def window_capture():
    root = Path(__file__).resolve().parents[3]
    proof = core.read_ref(fact(root/PROVENANCE_PATH))
    row = proof['window_provider']
    need(row['editable_destination'] == WINDOW_PATH, 'native_window_provider_path')
    raw = read_relative(root, WINDOW_PATH, 2*1024**2)
    need(digest(raw) == row['sha256'] and len(raw) == row['size_bytes'], 'native_window_provider_changed')
    return raw, {'path': str(root/WINDOW_PATH), 'sha256': digest(raw), 'size_bytes': len(raw)}


def _rebind(namespace):
    """Keep function code objects and defaults; resolve only through this capture."""
    result = dict(namespace)
    for name, value in namespace.items():
        if isinstance(value, FunctionType) and value.__module__ == namespace.get('__name__'):
            copied = FunctionType(value.__code__, result, value.__name__, value.__defaults__, value.__closure__)
            copied.__kwdefaults__ = value.__kwdefaults__
            copied.__annotations__ = value.__annotations__
            result[name] = copied
    return result


def validate_suite_authorization(suite, packet):
    """Current exact artifact authority replaces the historical saved-grant field."""
    policy = packet.get('native_fixture_policy')
    need(type(policy) is dict and set(policy) == {'scope', 'runtime_ref', 'operation_ref', 'authority_ref',
         'requirements'} and policy['scope'] == 'development_native_wine_controls' and
         suite in ('api-abi', 'threads-memory-exceptions', 'mac-driver') and
         packet.get('code_publication_policy') == 'page-wx', 'native_current_authority_required')
    observed = core.read_ref(policy['authority_ref'])
    need(observed.get('passed') is True and observed.get('runtime_sha256') == policy['runtime_ref']['sha256'] and
         observed.get('operation_ref') == policy['operation_ref'], 'native_current_authority_required')
    core.checked_ref(policy['runtime_ref']); core.checked_ref(policy['operation_ref'])
    if suite in ('threads-memory-exceptions', 'mac-driver'):
        need(isinstance(packet.get('entrypoints'), dict) and 'stage4_pe' in packet['entrypoints'],
             'stage4_signed_entrypoint_missing')
    if suite == 'mac-driver':
        need(all(name in packet['entrypoints'] for name in ('window_pe', 'window_driver_pe')),
             'stage5_signed_entrypoint_missing')


def _target_controls(raw, api, label):
    tree = ast.parse(raw, filename=label)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'target_controls']
    need(len(nodes) == 1, 'native_target_reader')
    node = nodes[0]
    expected = ["requirements_path = runtime / 'requirements.json'",
                "need(sha256(requirements_path) == signed.get('requirements_sha256'), 'changed_signing_requirements')",
                'requirements = load_json(requirements_path)']
    need([ast.unparse(row) for row in node.body[:3]] == expected, 'native_target_input_seam')
    node.body[:3] = ast.parse("validate_suite_authorization('mac-driver', signed)\n"
                             "requirements = signed['native_fixture_policy']['requirements']").body
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), label, 'exec'), api)


def _relocation_requirements(raw, api, label):
    tree=ast.parse(raw,filename=label)
    nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='assess_relocation_events']
    need(len(nodes)==1,'native_relocation_reader')
    node=nodes[0]
    expected=["raw_requirements = read_relative(runtime, 'requirements.json')",
              "need(hashlib.sha256(raw_requirements).hexdigest() == signed.get('requirements_sha256'), 'changed_signing_requirements')",
              'requirements = decode_json(raw_requirements)']
    need([ast.unparse(row) for row in node.body[3:6]]==expected,'native_relocation_input_seam')
    node.body[3:6]=ast.parse("validate_suite_authorization('api-abi', signed)\n"
                             "requirements = signed['native_fixture_policy']['requirements']").body
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),label,'exec'),api)


def _window_authorization(raw, namespace, label):
    """Bind only the original saved-grant statement to current artifact policy."""
    tree = ast.parse(raw, filename=label)
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'assess']
    need(len(nodes) == 1, 'native_window_authorization_seam')
    node = nodes[0]
    signature = ast.parse('def assess(rows, result, runtime, signed, dynamic): pass').body[0]
    expected = ast.parse("need(result['case']['id'] == 'window' and signed.get('authorization_scope') == "
                         "'development_windows_mac_driver_fixtures', 'window_authorization_scope')").body[0]
    need(not node.decorator_list and node.returns is None and node.type_comment is None and
         ast.dump(node.args, include_attributes=False) == ast.dump(signature.args, include_attributes=False) and
         len(node.body) >= 3 and ast.dump(node.body[2], include_attributes=False) ==
         ast.dump(expected, include_attributes=False), 'native_window_authorization_seam')
    node.body[2:3] = ast.parse("need(result['case']['id'] == 'window', 'window_authorization_scope')\n"
                             "_pear_current_suite_authorization('mac-driver', signed)").body
    namespace['_pear_current_suite_authorization'] = validate_suite_authorization
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), label, 'exec'), namespace)


def _variant_functions(raw, api, label, variant):
    need(type(variant) is dict and variant.get('variant')=='arm64ec-class181-arm64-i386-v1',
         'native_api_variant_required')
    expected={'version':1,'record_kind':'pear_architecture_result','status':0,'returned_bytes':12,
              'machines':[43620,332],'flags':[7,18],'terminator':0}
    need(variant['expected_architecture']==expected,'native_api_variant_expected')
    original=api['expected_api_rows']
    def expected_rows():
        rows=original()
        need(rows[0]=={'version':1,'record_kind':'pear_architecture_result','status':0,'returned_bytes':8,
                      'machines':[43620],'flags':[7],'terminator':0},'native_api_original_oracle_changed')
        return [dict(expected),*rows[1:]]
    def paths(runtime,signed):
        need(signed.get('native_api_variant')==variant,'native_api_variant_packet')
        values={key:runtime.joinpath(*api['relative'](value)) for key,value in signed['entrypoints'].items()
                if key!='api_pe'}
        external=core.checked_ref(variant['fixture_ref'])
        need(signed['entrypoints']['api_pe']==str(external),'native_api_variant_entrypoint')
        values['api_pe']=external
        return values
    api['expected_api_rows']=expected_rows;api['native_api_paths']=paths
    tree=ast.parse(raw,filename=label)
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='run_case')
    matches=[(i,n) for i,n in enumerate(node.body) if isinstance(n,ast.Assign) and
             any(isinstance(t,ast.Name) and t.id=='paths' for t in n.targets)]
    need(len(matches)==1 and ast.unparse(matches[0][1])==
         "paths = {key: runtime.joinpath(*relative(value)) for key, value in signed['entrypoints'].items()}",
         'native_api_path_seam')
    node.body[matches[0][0]]=ast.parse('paths = native_api_paths(runtime, signed)').body[0]
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),label,'exec'),api)


NATIVE_SEED_POLICY='verified-synthetic-seed-with-current-modules-and-no-desktop-menu'


def menu_configuration(raw):
    from pear_runtime.fixtures.controls.execution import without_desktop_menu
    after=without_desktop_menu(raw)
    return after,{'scope':'synthetic_native_four_prefix_only',
        'operation':'disable_optional_XDG_desktop_menu_autorun','registry_path':'system.reg',
        'removed_entries':1,'before_sha256':digest(raw),'after_sha256':digest(after),
        'original_seed_unchanged':True}


def configure_menu(seed, prefix):
    """Reuse the exact existing one-entry transformation on this clone only."""
    need(isinstance(prefix,Path),'native_menu_clone_scope')
    need(prefix.is_absolute() and prefix.resolve(strict=True)==prefix and prefix.is_dir() and
         not prefix.is_relative_to(seed.seed) and not seed.seed.is_relative_to(prefix),
         'native_menu_clone_scope')
    registry=prefix/'system.reg';original=seed.seed/'run/prefix/system.reg'
    before=registry.read_bytes()
    need(not registry.is_symlink() and before==original.read_bytes(),'native_menu_registry_preimage')
    inventory=supervisor.prefix_inventory(prefix)
    after,configuration=menu_configuration(before)
    registry.write_bytes(after)
    need(registry.read_bytes()==after,'native_menu_registry_write')
    current=supervisor.prefix_inventory(prefix)
    need([row for row in current if row['path']!='system.reg']==
         [row for row in inventory if row['path']!='system.reg'],'native_menu_copy_scope')
    need(supervisor.prefix_inventory(seed.seed/'run/prefix')==seed.base['seed_inventory'],
         'native_menu_seed_changed')
    return configuration


def _seed_environment(base, seed, observation):
    from pear_runtime.fixtures.controls.execution import clone_prefix
    original=base.environment;seen=None
    def environment(home,prefix,nonce):
        nonlocal seen
        if seen is None:
            origin=clone_prefix(seed,prefix)
            need(origin['cold_prefix_initialization'] is False,'native_seed_policy')
            configuration=configure_menu(seed,prefix)
            observation.update(origin,policy=NATIVE_SEED_POLICY,configuration=configuration)
            seen=prefix
        else:need(prefix==seen,'native_seed_multiple_prefixes')
        return original(home,prefix,nonce)
    base.environment=environment


@contextmanager
def native_helpers(provider, *, variant=None, seed=None):
    # Capture the additional module before executing any provider; recheck on
    # every exit. APISession/APIObserver/Session class objects remain original.
    raw, ref = window_capture()
    previous = ('window_evidence' in sys.modules, sys.modules.get('window_evidence'))
    primary=None
    try:
        with supervisor.supervision(provider) as (life, helpers):
            helpers.base.STREAM_LIMIT = 262144
            adapted = current_helpers(helpers, life, Path(provider))
            dynamic = _rebind(vars(adapted.dynamic))
            api = _rebind(vars(adapted.api))
            api['assess_dynamic_events'] = dynamic['assess_events']
            api['validate_budget'] = dynamic['validate_budget']
            api['validate_suite_authorization'] = validate_suite_authorization
            # The original constant is preserved in the captured provider. Only
            # this adapter namespace labels its actual seeded test setup.
            api['ENVIRONMENT_POLICY']={**api['ENVIRONMENT_POLICY'],
                'prefix_initialization':NATIVE_SEED_POLICY}
            original_cases=helpers.api.validate_cases
            def validate_cases(value,suite='api-abi'):
                original=original_cases(value,suite)
                return {**original,'environment_policy':dict(api['ENVIRONMENT_POLICY'])}
            api['validate_cases']=validate_cases
            label = str(Path(provider)/'tools/wine/api_runner.py')
            original_api=life.read_relative(provider, 'tools/wine/api_runner.py')
            _target_controls(original_api, api, label)
            _relocation_requirements(original_api,api,label)
            if variant is not None:_variant_functions(original_api,api,label,variant)
            seed_observation={}
            if seed is not None:_seed_environment(helpers.base,seed,seed_observation)
            window = ModuleType('window_evidence'); window.__file__ = ref['path']
            sys.modules['window_evidence'] = window
            exec(compile(raw, ref['path'], 'exec'), window.__dict__)
            _window_authorization(raw, window.__dict__, ref['path'])
            yield life, SimpleNamespace(**{**vars(helpers), 'api': SimpleNamespace(**api),
                                         'dynamic': SimpleNamespace(**dynamic), 'window': window, 'seed_observation': seed_observation})
    except BaseException as exc:
        primary=exc
        raise
    finally:
        if previous[0]: sys.modules['window_evidence'] = previous[1]
        else: sys.modules.pop('window_evidence', None)
        try:
            current_raw, current_ref = window_capture()
            need(current_raw == raw and current_ref == ref, 'native_window_provider_changed')
        except BaseException as secondary:
            if primary is None:raise
            primary.add_note('Window provider recheck also failed: '+getattr(secondary,'code',type(secondary).__name__))


def bootstrap_assessment(life, helpers, provider):
    """Original per-case outer checks; historical run/signed lookup is excluded."""
    raw=life.read_relative(provider,'tools/wine/run_fixtures.py')
    tree=ast.parse(raw)
    source=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='_validate_runs')
    loop=next(node for node in source.body if isinstance(node,ast.For) and ast.unparse(node.target)=='row')
    need(len(loop.body)==31 and ast.unparse(loop.body[12])==
         "need(result.get('case') == expected, 'case_configuration_mismatch')" and
         ast.unparse(loop.body[28])==
         "validate_native_images(result['events'], runtime, signed, expected['expected'])",
         'native_bootstrap_outer_seam')
    function=ast.parse('def assess(root, case_id, result, expected, runtime, signed):\n    nonces=set()\n    prefixes_seen=set()').body[0]
    function.body += loop.body[12:29]
    namespace=dict(vars(helpers.base))
    exec(compile(ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[])),
                 str(Path(provider)/'tools/wine/run_fixtures.py'),'exec'),namespace)
    return namespace['assess']
