# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Read synthetic historical correction receipts; never build or apply patches.

Exact selected definitions from Pear tools/cpu/fex_build.py. Each portable test
explicitly binds REPO to its temporary fixture. There is no checkout fallback.
"""
from pathlib import Path
import os
from pear_runtime.fixtures.controls.corpus import read, digest
from pear_runtime.assembly._common import encoded
from pear_runtime.errors import need

REPO = None

PATCH=Path('runtime/fex/patches/cpu/0001-private-staging-label-references.patch')


def inventory(root):
    rows=[]
    for p in sorted(root.rglob('*')):
        if p.is_symlink():rows.append(dict(path=p.relative_to(root).as_posix(),link=os.readlink(p)))
        elif p.is_file():rows.append(dict(path=p.relative_to(root).as_posix(),sha256=digest(p.read_bytes())))
    return rows


def admit_correction(root,receipts):
    record=read(root/'build.json')
    need(record['kind']=='cpu_fex_correction_build' and record['passed'] is True and
         record['baseline_receipts']==receipts,'correction_pair')
    need(record['patch_path']==str(PATCH) and record['patch_sha256']==digest((REPO/PATCH).read_bytes()),'correction_patch')
    need(record.get('patch_series_sha256')==digest((REPO/PATCH.parent/'series.json').read_bytes()),'correction_series')
    final_images={row['path']:row for row in read(REPO/PATCH.parent/'series.json')['files']}
    for key,filename in [('policy','0002-observe-effective-thread-policy.patch'),('link','0003-link-validity.patch'),('target','0004-current-shared-link-target.patch')]:
        if key+'_patch_sha256' not in record: continue
        need(record[key+'_patch_sha256']==digest((REPO/PATCH.parent/filename).read_bytes()),'supplement_patch_changed')
        series_path=REPO/PATCH.parent/(key+'-series.json')
        need(record[key+'_series_sha256']==digest(series_path.read_bytes()),'supplement_series_changed')
        final_images.update({row['path']:row for row in read(series_path)['files']})
    for row in final_images.values():
        need(digest((root/'source'/row['path']).read_bytes())==row['after'],'correction_patch_not_applied')
    need(record['producer_sha256']==digest((root/'producer.py').read_bytes()),'correction_producer_changed')
    need(record['inputs_sha256']==digest((root/'inputs.json').read_bytes()),'correction_inputs_changed')
    need(read(root/'inputs.json',limit=64*1024**2)==dict(source=inventory(root/'source'),wire=inventory(root/'wire')),'correction_source_changed')
    for command in record['commands']:
        need(command['exit_code']==0 and digest((root/command['log']).read_bytes())==command['log_sha256'],'correction_command')
    expected=['clone-source','clone-wire','patch-check','patch']
    for key in ('policy','link','target'):
        if key+'_patch_sha256' in record: expected+=[key+'-check',key]
    expected+=['arm64ec.configure','arm64ec.build','strip']
    need([c['id'] for c in record['commands']]==expected,'correction_recipe')
    need(digest((root/'deployment.dll').read_bytes())==record['dll_sha256'],'correction_binary_changed')
    return dict(path=str(root),build_sha256=digest((root/'build.json').read_bytes()),dll_sha256=record['dll_sha256'],
                patch_sha256=record['patch_sha256'],source_inputs_sha256=record['inputs_sha256'],
                scope='arm64ec_fex_only',wine_changed=False,wow64_execution=False)
