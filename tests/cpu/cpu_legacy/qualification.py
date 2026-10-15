# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Historical configuration/normalization assertions; no qualification API.

Exact selected definitions from Pear tools/cpu/qualify.py. Current candidate
admission and code-origin validation remain production runtime responsibilities.
"""
from pathlib import Path
from pear_runtime.fixtures.controls.corpus import require
from pear_runtime.assembly import helpers as signing

CONFIGURATION=('baseline_build_sha256','baseline_input_receipts','baseline_loader_capacity',
    'cpu_correction','dependency_closure','entrypoints','input_receipts','memory_profile',
    'prior_runtime_sha256','source_ledger','test_instrumentation')


def same_configuration(left,right):
    require(left.get('passed') is True and right.get('passed') is True and
            left.get('kind')==right.get('kind')=='cpu_corpus_development_runtime','candidate_kind')
    for key in CONFIGURATION:
        require(key in left and key in right and left[key]==right[key],'candidate_configuration_'+key)
    require(left['cpu_correction']['scope']=='arm64ec_fex_only','candidate_component_scope')


def normalized_inventory(value):
    # Called only after current inventory admission and actual Mach-O code-origin
    # comparison. Only declared PE fixtures and their signature fields can vary.
    fixtures={Path(f['path']).relative_to(signing.BUNDLE).as_posix() for f in value['fixtures'].values()}
    require(all(p.startswith('Contents/Resources/runtime/libexec/pear-cpu/') for p in fixtures),'fixture_path_scope')
    natives={Path(p['path']).relative_to(signing.BUNDLE).as_posix() for p in value['native_images']}
    result={}
    for original in value['bundle_inventory']:
        row=dict(original);path=row['path']
        require(path not in result,'duplicate_inventory_path')
        if path in fixtures:continue
        if path in natives or path=='Contents/_CodeSignature/CodeResources':
            require(row['kind']=='file','signature_file_kind')
            row.pop('sha256');row.pop('size_bytes')
        result[path]=row
    return result
