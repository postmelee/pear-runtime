# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Rebuild the five selected Wine/DXMT surface units with exact lower layers.

Recorded pipeline, presentation and managed-surface source overlays are already
in the forks. This driver does not replay patches or execute GPU/guest work.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re

from pear_runtime.build import Context, fact
from pear_runtime.errors import Error, need
from .wine import audit_link_map, command, compare_macho, expand, number, snapshot_attempt, take


ARTIFACTS = {'metal-link': ('winemetal.so', 'winemetal'),
             'win32u-link': ('win32u.so', 'win32u'),
             'driver-link': ('winemac.so', 'winemac')}
ORDER = ('metal-compile', 'metal-link', 'bridge-compile', 'window-compile',
         'pairing-compile', 'win32u-compile', 'win32u-link', 'driver-link')


def validate_plan(recipe):
    need(recipe.get('driver') == 'graphics' and recipe.get('recipe_version') == 1, 'graphics_recipe_version')
    need(tuple(c['id'] for c in recipe['commands']) == ORDER, 'graphics_recipe_order')
    for row in recipe['commands']:
        invocation = recipe['tool_invocations'][row['id']]
        need(row['argv'][invocation['argv_index']] == invocation['lexical_argument'],
             'graphics_tool_invocation')
        if row['id'].startswith('metal-'):
            need('-mmacosx-version-min=' + recipe['targets']['metal'] in row['argv']
                 and 'MACOSX_DEPLOYMENT_TARGET' not in row['env'], 'graphics_metal_target')
        else:
            need(row['env']['MACOSX_DEPLOYMENT_TARGET'] == recipe['targets']['wine'], 'graphics_wine_target')
    need('-Wl,-objc_stubs_small' in recipe['commands'][1]['argv'], 'graphics_objc_stub_policy')


def control_recipe(recipe, row):
    name, _ = ARTIFACTS[row['id']]
    replacements = dict(recipe['control_inputs'])
    replacements['{output}/surface/' + name] = '{output}/surface/control-' + name
    if row['id'] == 'driver-link':
        replacements['{output}/surface/win32u.so'] = '{output}/surface/control-win32u.so'
    oldmap = '-Wl,-map,{output}/surface/' + row['id'] + '.map'
    replacements[oldmap] = '-Wl,-map,{output}/surface/control-' + row['id'] + '.map'
    return dict(row, id='control-' + row['id'],
                argv=[replacements.get(value, value) for value in row['argv']])


def linked_libraries(data):
    """Read Mach-O dependency load commands without loading executable code."""
    need(take(data, 0, 4) == b'\xcf\xfa\xed\xfe' and number(data, 'I', 4) == 0x0100000c,
         'graphics_macho_architecture')
    count, end = number(data, 'I', 16), 32 + number(data, 'I', 20)
    need(0 < count <= 4096 and end <= len(data), 'graphics_macho_commands')
    at, result = 32, []
    for _ in range(count):
        kind, size = number(data, 'I', at), number(data, 'I', at + 4)
        need(size >= 8 and at + size <= end, 'graphics_macho_command')
        if kind in (0xc, 0x80000018, 0x8000001f, 0x20, 0x80000023):
            offset = number(data, 'I', at + 8)
            need(24 <= offset < size, 'graphics_macho_library_name')
            raw = take(data, at + offset, size - offset)
            need(b'\0' in raw, 'graphics_macho_library_name')
            result.append({'name': raw.split(b'\0', 1)[0].decode('utf-8'), 'kind': kind,
                           'current_version': number(data, 'I', at + 16),
                           'compatibility_version': number(data, 'I', at + 20)})
        at += size
    need(at == end, 'graphics_macho_commands')
    return result


def audit_graphics_link_map(context, path):
    """Preserve a binary map while decoding only its exact input-file table."""
    raw = path.read_bytes()
    markers = list(re.finditer(rb'(?m)^# Object files:\r?$', raw))
    need(len(markers) == 1, 'graphics_link_map_object_table')
    start = markers[0].start()
    following = re.search(rb'(?m)^# [^\r\n]+', raw[markers[0].end():])
    need(following is not None, 'graphics_link_map_table_boundary')
    end = markers[0].end() + following.start()
    table = raw[start:end]
    try:
        table.decode('utf-8', errors='strict')
    except UnicodeDecodeError as error:
        raise Error('graphics_link_map_object_encoding') from error
    relative = str(path.relative_to(context.output)) + '.objects.txt'
    derived = context.path(relative)
    with derived.open('xb') as stream:
        stream.write(table)
    context.record_output(relative)
    result = audit_link_map(context, derived)
    result.update(source_map=fact(path), source_offset=start, source_length=end - start,
                  adaptation='Exact Object files bytes; binary Symbols section remains in the retained full map.')
    return result


def sources():
    root = Path(__file__).resolve().parents[1]
    return [fact(root / 'build.py'), fact(root / 'errors.py'),
            fact(Path(__file__).with_name('wine.py')), fact(Path(__file__))]


def build(context):
    recipe = context.recipe
    validate_plan(recipe)
    before = sources()
    for invocation in recipe['tool_invocations'].values():
        context.input(invocation['root'], invocation['path'])
    comparisons, implicit, artifacts = {}, [], {}
    links = {row['id']: row for row in recipe['commands'] if row['id'] in ARTIFACTS}

    def linked(row, *, control=False):
        original_id = row['id'].removeprefix('control-')
        name, role = ARTIFACTS[original_id]
        filename = 'control-' + name if control else name
        context.record_output('surface/' + filename)
        path = context.output / 'surface' / filename
        reference = Path(expand(recipe['references'][name], context))
        comparison = compare_macho(reference, path)
        old_libraries, new_libraries = linked_libraries(reference.read_bytes()), linked_libraries(path.read_bytes())
        comparison['linked_libraries'] = {'reference': old_libraries, 'candidate': new_libraries,
                                          'equal': old_libraries == new_libraries}
        need(old_libraries == new_libraries, 'graphics_linked_libraries_changed')
        names = {library['name'] for library in new_libraries}
        need(set(recipe.get('required_shared_libraries', {}).get(role, [])) <= names,
             'graphics_required_library_missing')
        comparisons[row['id']] = comparison
        need(comparison['text_equal'], 'graphics_text_changed')
        mapname = row['id'] + '.map'
        context.record_output('surface/' + mapname)
        implicit.append(audit_graphics_link_map(context, context.output / 'surface' / mapname))
        if not control:
            artifacts[role] = context.outputs['surface/' + name]

    for ident in ('metal-link', 'win32u-link', 'driver-link'):
        row = control_recipe(recipe, links[ident])
        command(context, row)
        linked(row, control=True)
    for row in recipe['commands']:
        command(context, row)
        if row['id'] in ARTIFACTS:
            linked(row)
        else:
            argv = [expand(value, context) for value in row['argv']]
            obj = Path(argv[argv.index('-o') + 1])
            dep = Path(argv[argv.index('-MF') + 1])
            context.record_output(str(obj.relative_to(context.output)))
            context.record_output(str(dep.relative_to(context.output)))
            context.audit_depfile(dep)
    after = sources()
    need(before == after, 'graphics_builder_changed')
    return context.finish('passed', comparisons=comparisons,
                          extra={'artifacts': artifacts, 'implicit_link_inputs': implicit,
                                 'builder_sources': {'before': before, 'after': after},
                                 'historical_semantics_gate': 'Selected source/object reconstruction comparison; no typed-lease, GPU or original-game execution.'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--bindings', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with Context(args.recipe, args.bindings, args.output) as context:
        try:
            snapshot_attempt(context, args.recipe, args.bindings, sources())
            build(context)
        except Exception as error:
            context.finish('failed', extra={'failure_code': getattr(error, 'code', type(error).__name__)})
            raise


if __name__ == '__main__':
    main()
