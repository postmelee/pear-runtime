# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Selected FEX header ownership and actual dependency use, without execution.

Expected identities come from independently admitted source/configuration
documents. Recorded dependency rows and header basenames never supply them.
The caller owns metadata admission and output binding; this module is shared by
the component builder and retained fixture checker, with no fixture imports.
"""
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat

from . import build
from .errors import need

HEADER_LIMIT = 1024**2
DEPFILE_LIMIT = 8 * 1024**2


def canonical(value):
    need(type(value) is str and value and '\\' not in value and '\0' not in value,
         'header_path')
    lexical = PurePosixPath(value)
    need(lexical.is_absolute() and str(lexical) == value and '..' not in lexical.parts,
         'header_path')
    path = Path(value)
    need(path.resolve(strict=True) == path and not path.is_symlink(), 'header_alias')
    return path


def valid_identity(ref):
    need(type(ref) is dict and set(ref) == {'path', 'sha256', 'size_bytes'}, 'header_ref_shape')
    need(type(ref['path']) is str and type(ref['sha256']) is str and
         build.HEX.fullmatch(ref['sha256']) is not None and
         type(ref['size_bytes']) is int and ref['size_bytes'] >= 0, 'header_ref_identity')


def _fact(path, limit):
    path = canonical(str(path))
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'header_file_size')
    result = build.fact(path)
    need(canonical(str(path)) == path, 'header_alias')
    return result


def bound_roots(public_recipe, bindings):
    need(type(public_recipe) is dict and type(bindings) is dict, 'header_contract_shape')
    bound = bindings.get('roots', bindings)
    definitions = public_recipe.get('roots')
    need(type(bound) is dict and type(definitions) is dict and set(bound) == set(definitions),
         'header_roots')
    roots = {}
    for name, value in bound.items():
        definition = definitions[name]
        need(type(definition) is dict and 'path' not in definition and
             definition.get('kind') in build.KINDS, 'header_root_definition')
        path = value['path'] if type(value) is dict else value
        roots[name] = canonical(path)
        need(roots[name].is_dir() and roots[name] != Path('/'), 'header_root_directory')
    need({'fex', 'wine', 'runtime', 'private'} <= set(roots), 'header_roots')
    return roots


def _private_input(public_recipe, roots, private_manifest):
    need(type(private_manifest) is dict, 'header_private_binding')
    policy = public_recipe.get('required_private_input')
    need(type(policy) is dict and policy.get('name') == 'PearPhaseSelection.h' and
         policy.get('required_for_original_diagnostic_configuration') is True,
         'header_private_policy')
    root = roots['private']
    need(public_recipe['roots']['private']['kind'] == 'private' and
         type(private_manifest.get('schema_version')) is int and private_manifest['schema_version'] == 1 and
         private_manifest.get('root') == str(root), 'header_private_binding')
    need(not any((parent / '.git').exists() or (parent / '.git').is_symlink()
                 for parent in (root, *root.parents)), 'header_private_inside_repository')
    inputs = public_recipe.get('inputs')
    need(type(inputs) is list and all(type(row) is dict for row in inputs), 'header_inputs')
    need(not any(row.get('root') == 'private' for row in inputs), 'header_public_private_identity')
    rows = private_manifest.get('files')
    need(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict and
         set(rows[0]) == {'path', 'sha256', 'size_bytes'} and rows[0]['path'] == policy['name'],
         'header_private_set')
    row = rows[0]
    ref = dict(path=str(root / row['path']), sha256=row['sha256'], size_bytes=row['size_bytes'])
    valid_identity(ref)
    need(0 < ref['size_bytes'] <= HEADER_LIMIT, 'header_private_identity')
    return ref


def expanded_recipe_sha256(public_recipe, bindings, private_manifest):
    """Reproduce the existing local metadata expansion, never a build or restore."""
    roots = bound_roots(public_recipe, bindings)
    ref = _private_input(public_recipe, roots, private_manifest)
    expanded = copy.deepcopy(public_recipe)
    expanded['inputs'].append(dict(root='private', path='PearPhaseSelection.h',
                                   sha256=ref['sha256'], size_bytes=ref['size_bytes']))
    return hashlib.sha256(json.dumps(expanded, sort_keys=True).encode()).hexdigest()


def derive_fex_headers(public_recipe, bindings, private_manifest, *, output_root):
    """Derive the fixed selected-v1 policy from independently admitted operands.

    A new unit/header topology requires a reviewed policy change. All three
    selected units use wire and Abort; the private phase input is Module-only.
    """
    roots = bound_roots(public_recipe, bindings)
    output = canonical(str(output_root))
    need(output.is_dir(), 'header_output_directory')
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output)
             for root in roots.values()), 'header_output_overlap')
    units = public_recipe.get('compile_units')
    need(type(units) is list and len(units) == 3 and all(type(row) is dict for row in units) and
         {row.get('id') for row in units} == {'core', 'module', 'memory'} and
         len({row.get('path') for row in units}) == 3, 'header_unit_set')
    sources = {}
    for unit in units:
        path = roots['fex'] / build.relative(unit['path'])
        ref = dict(path=str(path), sha256=unit['sha256'], size_bytes=unit['size_bytes'])
        valid_identity(ref)
        sources[unit['id']] = ref
    shared = public_recipe.get('shared_headers')
    need(type(shared) is list and len(shared) == 2, 'header_owner_set')
    owner_paths = {'pear-wine': ('wine', 'include/wine/pear_fex_memory.h'),
                   'pear-runtime': ('runtime', 'include/PearAbortObservation.h')}
    owners = {}
    for row in shared:
        need(type(row) is dict and row.get('owner') in owner_paths and
             row['owner'] not in owners, 'header_owner_set')
        root, path = owner_paths[row['owner']]
        need(row.get('path') == path, 'header_owner_path')
        ref = _fact(roots[root] / path, HEADER_LIMIT)
        need(ref['sha256'] == row.get('sha256'), 'header_owner_identity')
        owners[row['owner']] = ref
    wire, abort = owners['pear-wine'], owners['pear-runtime']
    phase = _private_input(public_recipe, roots, private_manifest)
    abort_rows = [r for r in public_recipe['inputs'] if r.get('root') == 'runtime' and
                  r.get('path') == 'include/PearAbortObservation.h']
    need(len(abort_rows) == 1 and abort_rows[0].get('sha256') == abort['sha256'] and
         type(abort_rows[0].get('size_bytes')) is int and abort_rows[0]['size_bytes'] == abort['size_bytes'],
         'header_abort_input_identity')
    exports = public_recipe.get('source_exports')
    need(type(exports) is list and len(exports) == 1, 'header_export_set')
    export = exports[0]
    need(export == dict(root='wine', path='include/wine/pear_fex_memory.h',
                        output='exports/wire/wine/pear_fex_memory.h', sha256=wire['sha256']),
         'header_export_owner_binding')
    exported = dict(wire, path=str(output / export['output']))
    need(_fact(exported['path'], HEADER_LIMIT) == exported, 'header_export_identity')
    need(_fact(phase['path'], HEADER_LIMIT) == phase, 'header_private_identity')
    return dict(schema_version=1, policy='selected_fex_header_use_v1', sources=sources,
                owners=dict(wire=wire, abort=abort), roles=dict(wire=exported, abort=abort, phase=phase),
                required={key: ('wire', 'abort', 'phase') if key == 'module' else ('wire', 'abort')
                          for key in sources})


def recheck_fex_headers(contract):
    for ref in (*contract['owners'].values(), *contract['roles'].values()):
        need(_fact(ref['path'], HEADER_LIMIT) == ref, 'header_changed')


def depfile_paths(ref):
    """Parse only the exact regular depfile whose before/after identity is bound."""
    valid_identity(ref)
    need(ref['size_bytes'] <= DEPFILE_LIMIT, 'header_depfile_size')
    need(_fact(ref['path'], DEPFILE_LIMIT) == ref, 'header_depfile_changed')
    values = build.parse_depfile(Path(ref['path']))
    need(_fact(ref['path'], DEPFILE_LIMIT) == ref, 'header_depfile_changed')
    return values


def require_fex_header_use(contract, unit_id, dependencies, *, depfile_paths, cwd):
    """Require independently derived refs and actual tokens, rejecting shadows."""
    need(unit_id in contract['required'] and type(dependencies) is list and
         type(depfile_paths) is list and all(type(p) is str for p in depfile_paths), 'header_use_shape')
    for ref in dependencies:
        valid_identity(ref)
    cwd = canonical(str(cwd))
    need(cwd.is_dir(), 'header_dependency_cwd')
    paths = [str(Path(value) if Path(value).is_absolute() else cwd / value) for value in depfile_paths]
    source = contract['sources'][unit_id]
    observed_source = [ref for ref in dependencies if ref['path'] == source['path']]
    need(observed_source == [source], 'header_source_use')
    need(paths.count(source['path']) == 1, 'header_source_token')
    required, matched = contract['required'][unit_id], []
    for role, expected in contract['roles'].items():
        name = PurePosixPath(expected['path']).name
        refs = [ref for ref in dependencies if PurePosixPath(ref['path']).name == name]
        tokens = [p for p in paths if PurePosixPath(p).name == name]
        if role not in required:
            need(not refs and not tokens, 'header_unexpected_private_use')
        else:
            need(refs == [expected], 'header_required_use:' + role)
            need(tokens == [expected['path']], 'header_required_token:' + role)
            matched.append(role)
    return dict(unit=unit_id, required_roles=list(required), matched_roles=matched)
