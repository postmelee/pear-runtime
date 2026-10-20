# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reproduce the retained WGI module without installing or executing its PE.

The sealed recipe preserves Wine's original relative source spelling and exact
lower layers. Raw compiler/link outputs survive every comparison and failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

from pear_runtime.build import Context, fact, load, point, span, write_json
from pear_runtime.errors import Error, need
from . import wine

RECIPE_SHA256 = '16b35a33816e5846f3dbd46620e066a0b9a557d3f77aacb839042a975dd9141f'
HISTORICAL_PLAN_SHA256 = '64a3fe23165dfae82badcec179771aec743f16bf20806170bd8d8d8c85563fd1'
PREFIX = 'dlls/windows.gaming.input/'
MIB = 1024**2


def validate_plan(recipe):
    """Validate the finite action contract, independently of its digest seal."""
    need(type(recipe) is dict and recipe.get('driver') == 'wgi'
         and type(recipe.get('recipe_version')) is int and recipe['recipe_version'] == 1,
         'wgi_recipe_version')
    actions = recipe.get('actions')
    need(type(actions) is list and len(actions) == 65, 'wgi_action_count')
    counts = {kind: 0 for kind in ('generate', 'compile', 'link')}
    targets, ids, units = set(), set(), {}
    for row in actions:
        need(type(row) is dict and row.get('kind') in counts, 'wgi_action_kind')
        kind, target = row['kind'], row['target']
        need(type(target) is str and target not in targets and row['id'] not in ids,
             'wgi_duplicate_action')
        targets.add(target)
        ids.add(row['id'])
        counts[kind] += 1
        original = row['historical_argv']
        need(type(original) is list and original and all(type(x) is str and '\x00' not in x for x in original),
             'wgi_command_argv')
        need(original.count('-o') == 1 and original[original.index('-o') + 1] == target,
             'wgi_command_target')
        expected = list(original)
        expected[0] = (expected[0] if expected[0].startswith('{llvm_mingw}')
                       else '{output}/objects/' + expected[0])
        expected = ['{host_tools}/arch', '-arm64', *expected]
        if kind == 'compile':
            need('-c' in original and original.count('-target') == 1
                 and original[0] == '{llvm_mingw}/bin/clang'
                 and not any(x.startswith('-O') for x in original), 'wgi_compile_flags')
            arch = original[original.index('-target') + 1]
            need(arch in ('aarch64-windows', 'arm64ec-windows')
                 and target.startswith(PREFIX + arch + '/') and target.endswith('.o'), 'wgi_compile_arch')
            source = '../source/' + row['source']
            need(original.count(source) == 1 and row['source'].startswith(PREFIX)
                 and row['source'].endswith('.c'), 'wgi_compile_source')
            units.setdefault(arch, set()).add(row['source'])
            need(row['depfile'] == 'depfiles/' + target + '.d', 'wgi_depfile_path')
            expected += ['-MD', '-MF', '{output}/' + row['depfile']]
        elif kind == 'generate':
            need(original[0] == 'tools/widl/widl' and '--nostdinc' in original
                 and target.endswith(('.h', '.res')), 'wgi_generator')
        else:
            need(row is actions[-1] and original[0] == 'tools/winegcc/winegcc'
                 and '-marm64x' in original and '-Wl,--build-id' in original,
                 'wgi_link_contract')
            operands = [x for x in original if Path(x).suffix in ('.o', '.obj', '.a')]
            need(len(operands) == 39 and len(set(operands)) == 39
                 and row['operands'] == operands, 'wgi_link_operands')
            expected = ['--cc-cmd=clang' if x.startswith('--cc-cmd=') else x for x in expected]
            expected += ['-v', '-v', '-save-temps', '-Wl,-verbose']
        need(row['argv'] == expected and row['cwd'] == '{output}/objects', 'wgi_argv_adaptation')
    need(counts == {'generate': 36, 'compile': 28, 'link': 1}
         and len(units.get('aarch64-windows', ())) == 14
         and units.get('aarch64-windows') == units.get('arm64ec-windows'), 'wgi_action_closure')
    return actions


def seal(context):
    raw = (json.dumps(context.recipe, indent=2, sort_keys=True) + '\n').encode()
    need(hashlib.sha256(raw).hexdigest() == RECIPE_SHA256
         and context.recipe_sha256 == RECIPE_SHA256, 'wgi_recipe_not_reviewed')
    validate_plan(context.recipe)
    ref = context.recipe['private_plan']
    need(ref['sha256'] == HISTORICAL_PLAN_SHA256, 'wgi_private_plan_identity')
    path = context.input(ref['root'], ref['path'], HISTORICAL_PLAN_SHA256)
    need(path.resolve(strict=True) == path, 'wgi_private_plan_alias')
    plan = load(path)
    rows = plan['commands']
    need(len(rows) == len(context.recipe['actions']), 'wgi_private_plan_actions')
    for old, new in zip(rows, context.recipe['actions']):
        expected = [value.replace('${LLVM_MINGW}', '{llvm_mingw}') for value in old['argv']]
        need(old['classification'] == new['kind'] and new['historical_argv'] == expected,
             'wgi_private_plan_correspondence')
    return fact(path)


def reference(context, row):
    path = context.input(row['root'], row['path'], row['sha256'])
    need(path.resolve(strict=True) == path and path.stat().st_size == row['size_bytes'],
         'wgi_reference_identity')
    return path


def sources():
    package = Path(__file__).resolve().parents[1]
    return [fact(path) for path in (package / 'build.py', package / 'errors.py',
                                    Path(wine.__file__).resolve(), Path(__file__).resolve())]


def tree_usage(root):
    total = allocated = logs = 0
    for path in root.rglob('*'):
        need(not path.is_symlink(), 'wgi_output_alias')
        if path.is_file():
            st = path.stat()
            total += st.st_size
            allocated += st.st_blocks * 512
            if 'logs' in path.relative_to(root).parts:
                logs += st.st_size
    return {'logical_bytes': total, 'allocated_stat_bytes': allocated, 'log_bytes': logs}


def storage_bindings(context, bindings_path):
    """Count the complete private campaign, including preserved failed attempts."""
    value = load(bindings_path)
    roots = value.get('storage_roots')
    need(type(roots) is dict and set(roots) == {'pack', 'attempts', 'evidence'},
         'wgi_storage_bindings')
    paths = {name: Path(path) for name, path in roots.items()}
    need(all(p.is_absolute() and p.is_dir() and p.resolve(strict=True) == p
             for p in paths.values()), 'wgi_storage_alias')
    need(paths['pack'] == context.root('inputs')
         and paths['attempts'] == context.output.parent
         and bindings_path.is_relative_to(paths['evidence']), 'wgi_storage_coverage')
    need(all(not a.is_relative_to(b) for name, a in paths.items()
             for other, b in paths.items() if name != other), 'wgi_storage_overlap')
    context.wgi_storage_roots = paths
    return paths


def usage(context):
    value = tree_usage(context.output)
    campaign = {name: dict(path=str(path), **tree_usage(path))
                for name, path in context.wgi_storage_roots.items()}
    value['campaign'] = campaign
    value['campaign_logical_bytes'] = sum(row['logical_bytes'] for row in campaign.values())
    value['campaign_allocated_stat_bytes'] = sum(row['allocated_stat_bytes'] for row in campaign.values())
    return value


def check_budget(context):
    value = usage(context)
    budget = context.recipe['budget']
    need(value['campaign_logical_bytes'] <= budget['additional_bytes'], 'wgi_campaign_budget')
    need(value['campaign']['pack']['logical_bytes'] <= budget['pack_bytes'], 'wgi_pack_budget')
    need(value['log_bytes'] <= budget['log_bytes'], 'wgi_log_budget')
    need(value['logical_bytes'] - value['log_bytes'] <= budget['output_bytes'] + budget['small_evidence_bytes'],
         'wgi_output_budget')
    need(shutil.disk_usage(context.output).free >= budget['floor_bytes'], 'wgi_reserve')
    return value


def run(context, action, *, ident=None):
    argv = [wine.expand(x, context) for x in action['argv']]
    env = {k: wine.expand(v, context) for k, v in context.recipe['environment'].items()}
    cwd = Path(wine.expand(action['cwd'], context))
    # Child tool selection is checked separately from the direct arch wrapper.
    selected = context.input('llvm_mingw', 'bin/clang').resolve(strict=True)
    found = shutil.which('clang', path=env['PATH'])
    need(found is not None and Path(found).resolve(strict=True) == selected, 'wgi_path_compiler')
    if action['kind'] == 'compile':
        context.path(action['depfile'])
    storage = check_budget(context)
    remaining = min(context.recipe['budget']['log_bytes'] - storage['log_bytes'],
                    context.recipe['budget']['additional_bytes'] - storage['campaign_logical_bytes'])
    need(remaining > 0, 'wgi_log_budget')
    started = point()
    try:
        result = context.run(ident or action['id'], argv, cwd=cwd, env=env,
                             timeout=600, max_output_bytes=min(8 * MIB, remaining))
    finally:
        context.timings.append(span('wgi_' + action['kind'] + ':' + (ident or action['id']), started))
    check_budget(context)
    return result


def audit_compile(context, action):
    path = context.output / action['depfile']
    text = path.read_text().replace('\\\r\n', '').replace('\\\n', '')
    need(text.split(':', 1)[0].strip() == action['target'], 'wgi_depfile_target')
    context.record_output(action['depfile'])
    cwd = context.output / 'objects'
    # The expected source is independently bound by the sealed action, not by
    # a basename or an assertion supplied in the compiler's dependency file.
    expected = context.output / 'source' / action['source']
    need(expected.resolve(strict=True) == expected, 'wgi_source_alias')
    rows = context.audit_depfile(path, cwd=cwd)
    actual = {Path(row['path']): row for row in rows}
    need(expected in actual and actual[expected] == context.outputs['source/' + action['source']],
         'wgi_depfile_missing_source')
    return rows


def explicit_link_operands(context, action):
    cwd = context.output / 'objects'
    operands = []
    for relative in action['operands']:
        path = cwd / relative
        need(path.is_file() and path.resolve(strict=True) == path, 'wgi_link_operand')
        context._admit_path(path)
        operands.append(str(path))
    need(len(operands) == len(set(operands)) == 39, 'wgi_link_operand_count')
    return operands


def audit_link_trace(context, record, operands):
    """Resolve only Wine's known relative helper field in derived diagnostics."""
    token = './tools/winebuild/winebuild'
    helper = Path(record['cwd']) / token[2:]
    need(helper.resolve(strict=True) == helper, 'wgi_trace_helper_alias')
    admitted = context._admit_path(helper)
    derived, adaptations = {}, []
    for channel in ('stdout', 'stderr'):
        original = record['logs'][channel]
        path = Path(original['path'])
        need(fact(path) == original, 'wgi_trace_log_changed')
        lines = path.read_text().splitlines(keepends=True)
        for number, line in enumerate(lines):
            text = line.lstrip()
            if text.startswith(('./', '../', 'tools/')):
                need(text.startswith(token + ' -'), 'wgi_trace_relative_tool')
                leading = line[:len(line) - len(text)]
                lines[number] = leading + '"' + str(helper) + '"' + text[len(token):]
                adaptations.append(dict(channel=channel, line=number + 1,
                                        original_executable=token, admitted_executable=admitted))
        relative = 'traces/' + record['id'] + '/' + channel + '.log'
        destination = context.path(relative)
        with destination.open('x') as stream:
            stream.write(''.join(lines))
        derived[channel] = context.record_output(relative)
        need(fact(path) == original, 'wgi_trace_log_changed')
    result = wine.audit_pe_trace(context, dict(record, logs=derived), operands)
    result.update(original_logs=record['logs'], derived_logs=derived,
                  executable_field_adaptations=adaptations)
    return result


def compare_pe(original, candidate):
    """Return a strict timestamp-only comparison; never rewrite either input."""
    old, new = wine.PE(original), wine.PE(candidate)
    old_hybrid, new_hybrid = old.hybrid(), new.hybrid()
    need(old.sections == new.sections and old.dirs == new.dirs and old_hybrid == new_hybrid,
         'wgi_pe_structure_changed')
    derived, changes = wine.normalize_pe(candidate, original)
    # Whole-byte equality includes RSDS, imports, unwind and ARM64X data. It is
    # deliberately stronger than a code-only or broad .rdata normalization.
    equal = derived == original
    return {'raw_equal': candidate == original, 'timestamp_only_equal': equal,
            'original_sha256': wine.sha(original), 'raw_sha256': wine.sha(candidate),
            'derived_sha256': wine.sha(derived), 'timestamp_fields': changes,
            'hybrid': new_hybrid, 'differing_bytes_after_timestamps':
            sum(a != b for a, b in zip(derived, original)) + abs(len(derived) - len(original))}


def link(context, action, name):
    operands = explicit_link_operands(context, action)
    row = run(context, action, ident=name)
    relative = 'objects/' + action['target']
    target = context.output / relative
    context.record_output(relative)
    raw = wine.copy_result(context, target, 'raw/' + name + '.dll')
    row['raw_outputs'] = [raw]
    # audit_pe_trace's expected operand check is cwd-sensitive. Supply the
    # independently admitted absolute operands; executed argv stays relative.
    started = point()
    trace = audit_link_trace(context, row, operands)
    need(trace['required_operand_count'] == 39, 'wgi_link_trace_operand_count')
    original = reference(context, action['reference']).read_bytes()
    comparison = compare_pe(original, target.read_bytes())
    comparison.update(raw_output=raw, implicit_link_inputs=trace)
    write_json(context.path('comparisons/' + name + '.json'), comparison)
    context.record_output('comparisons/' + name + '.json')
    write_json(context.output / 'commands.json', context.commands)
    context.timings.append(span('wgi_comparison:' + name, started))
    need(comparison['timestamp_only_equal'], 'wgi_pe_payload_changed')
    check_budget(context)
    return comparison


def reconstruct(context, before):
    need(sources() == before, 'wgi_builder_snapshot_changed')
    bound_plan = seal(context)
    comparisons = {'generated': [], 'compiled': []}
    started = point()
    for row in context.recipe['materialize']:
        source = context.input(row['root'], row['path'])
        need(source.resolve(strict=True) == source, 'wgi_materialize_alias')
        context.copy_input(row['root'], row['path'], row['output'])
    context.timings.append(span('wgi_preparation', started))
    check_budget(context)
    action = context.recipe['actions'][-1]
    comparisons['control_link'] = link(context, action, 'wgi-control-link')
    for kind in ('generate', 'compile'):
        for action in context.recipe['actions']:
            if action['kind'] != kind:
                continue
            row = run(context, action)
            relative = 'objects/' + action['target']
            output = context.output / relative
            current = context.record_output(relative)
            started = point()
            old = reference(context, action['reference'])
            if kind == 'generate':
                need(current['sha256'] == action['reference']['sha256']
                     and current['size_bytes'] == action['reference']['size_bytes'], 'wgi_generated_changed')
                comparisons['generated'].append({'id': action['id'], 'output': current, 'exact_equal': True})
            else:
                raw = wine.copy_result(context, output, 'raw/' + action['target'])
                row['raw_outputs'] = [raw]
                audit_compile(context, action)
                derived, timestamp = wine.normalize_coff(output.read_bytes(), old.read_bytes())
                # Only this fresh working operand changes. The separately
                # recorded raw compiler output and immutable reference survive.
                output.write_bytes(derived)
                normalized = context.record_output(relative)
                comparisons['compiled'].append({'id': action['id'], 'raw_output': raw,
                    'derived_link_operand': normalized, 'timestamp': timestamp, 'outside_timestamp_equal': True})
            context.timings.append(span('wgi_comparison:' + action['id'], started))
            write_json(context.output / 'commands.json', context.commands)
            check_budget(context)
    comparisons['selected_link'] = link(context, context.recipe['actions'][-1], 'wgi-selected-link')
    after = sources()
    need(before == after, 'wgi_builder_changed')
    return finish(context, 'passed', comparisons=comparisons, extra={
        'task_scope': 'task75_wgi_reconstruction_only',
        'historical_plan': bound_plan,
        'artifacts': {'wgi_pe': comparisons['selected_link']['raw_output']},
        'builder_sources': {'before': before, 'after': after},
        'output_storage': check_budget(context),
        'execution': {'native_fixture': False, 'PE': False, 'game': False,
                      'user_operable_window_metric': 'Not applicable: build-only investigation'},
        'claim': 'Whole module equality after only recorded COFF/PE timestamp derivation; preserved raw outputs are separately identified.',
        'executor_envelope': 'The unchanged common executor uses its legacy task56_component_build operation scope; this receipt is Task75 reconstruction only.'})


def settle_storage(context, receipt):
    """Include the receipt itself; no saved pass survives a capacity failure."""
    path = context.output / 'build.json'
    for _ in range(6):
        current = usage(context)
        if receipt.get('output_storage') == current:
            return current
        receipt['output_storage'] = current
        write_json(path, receipt)
    raise Error('wgi_storage_accounting_unstable')


def finish(context, status, *, comparisons=None, extra=None):
    extra = dict(extra or {}, wgi_finalization_complete=False)
    receipt = context.finish(status, comparisons=comparisons, extra=extra)
    try:
        settle_storage(context, receipt)
        check_budget(context)
        receipt['wgi_finalization_complete'] = True
        write_json(context.output / 'build.json', receipt)
        settle_storage(context, receipt)
        check_budget(context)
    except BaseException as error:
        receipt['status'] = 'failed'
        receipt['wgi_finalization_complete'] = False
        receipt['final_accounting_error'] = getattr(error, 'code', type(error).__name__)
        write_json(context.output / 'build.json', receipt)
        settle_storage(context, receipt)
        raise
    return receipt


def absolute_file(path):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path and path.is_file(), 'wgi_argument_alias')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--bindings', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    recipe_path, bindings_path = absolute_file(args.recipe), absolute_file(args.bindings)
    context = Context(recipe_path, bindings_path, args.output)
    storage_bindings(context, bindings_path)
    with context:
        before = sources()
        try:
            seal(context)
            wine.snapshot_attempt(context, recipe_path, bindings_path, before)
            reconstruct(context, before)
        except BaseException as error:
            # A failed build is not permission to skip the immutable-input and
            # producer checks, nor to discard raw failure evidence.
            post = {}
            try:
                context.validate_inputs()
                post['inputs_unchanged'] = True
            except Exception as check_error:
                post['inputs_unchanged'] = False
                post['input_error'] = getattr(check_error, 'code', type(check_error).__name__)
            after = sources()
            post['builders_unchanged'] = before == after
            extra = {'task_scope': 'task75_wgi_reconstruction_only',
                'failure_code': getattr(error, 'code', type(error).__name__),
                'post_failure_validation': post, 'builder_sources': {'before': before, 'after': after}}
            if context._finished:
                receipt = load(context.output / 'build.json')
                receipt.update(extra, status='failed', wgi_finalization_complete=False)
                write_json(context.output / 'build.json', receipt)
                settle_storage(context, receipt)
            else:
                try:
                    finish(context, 'failed', extra=extra)
                except BaseException:
                    # The failed receipt includes its accounting failure. Keep
                    # the original operation exception as the primary error.
                    pass
            raise


if __name__ == '__main__':
    main()
