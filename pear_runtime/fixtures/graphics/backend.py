# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Original backend/module oracle with an explicit canonical payload layout.

Only the two signing.PAYLOAD references were rebound to the imported constant.
The six-argument signature, assertions and diagnostic codes are preserved.
"""
from pathlib import Path
import re

from pear_runtime.assembly.helpers import PAYLOAD
from pear_runtime.fixtures.inputs import digest, need

def backend(run,runtime,value,r,raw,modules):
    stderr=raw[('loader','stderr')]
    loader=next(x for x in r['launches'] if x['role']=='loader')
    need(loader['argv'][-1]==str(runtime/value['fixtures'][r['fixture_id']]['path']),'translated_fixture_launch')
    pid=r['processes']['loader']['identity']['pid']
    for marker in ('Metal API Validation Enabled','Metal GPU Validation Enabled'):
        need(re.search(rb'wine\['+str(pid).encode()+rb':\d+\] '+marker.encode(),stderr) is not None,'translated_validation_unobserved')
    need(b'Pear FEX init ProcessInit.complete: status=00000000' in stderr and b'Pear FEX init ECGate.' in stderr,'translated_fex_unobserved')
    need(not re.search(rb'Exception c0000005|Pear FEX assertion:|err:sync:|failed assertion|validation error',stderr,re.I),'translated_required_error')
    for name,row in modules.items():
        need(row['path'].lower()=='c:\\windows\\system32\\'+name,'translated_module_fallback')
        source=runtime/PAYLOAD/'lib/wine/aarch64-windows'/name
        actual=run/'run/prefix/drive_c/windows/system32'/name
        need(actual.is_file() and digest(actual.read_bytes())==digest(source.read_bytes()),'translated_loaded_module_bytes')
        load=re.search(rb'Loaded L"C:\\\\windows\\\\system32\\\\'+re.escape(name.encode())+rb'" at ([0-9a-fA-F]+): builtin',stderr,re.I)
        need(load is not None and int(load[1],16)==row['base'],'translated_loaded_module_address')
    images=[e for e in r['events']['loader'] if e['event']=='image']
    for name in ('winemac.so','winemetal.so','libarm64ecfex.so'):
        expected=str((runtime/PAYLOAD/'lib/wine/aarch64-unix'/name).resolve())
        need(any(str(Path(e['path']).resolve())==expected for e in images),'translated_backend_image_missing')
    need(any('/Metal.framework/' in e['path'] for e in images),'translated_metal_unobserved')
