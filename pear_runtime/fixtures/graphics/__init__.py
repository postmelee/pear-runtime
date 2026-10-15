# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Bound rendering-original branch of the original shared fixture checker.

The caller must first run render.terminal(stdout) and backend.backend with the
unchanged case evidence and fixture_id='rendering-original'. This adapter keeps
the remaining original rendering assertions. Common fixture identity, current
authority, architecture, process ownership and cleanup stay with the caller.
It does not establish the separate native pairing or presentation gates.
"""
import re

from pear_runtime.assembly.helpers import PAYLOAD
from pear_runtime.fixtures.inputs import digest, need
from . import render


def check_rendering(run, runtime, value, record, raw, terminal):
    """Return the original rendering branch fields after terminal/backend checks."""
    need(record['diagnostic_fixture']['name'] == 'rendering-original',
         'checkpoint_rendering_fixture')
    stdout,stderr=raw[('loader','stdout')],raw[('loader','stderr')]
    need(re.search(rb'Pear FEX init Unaligned.repaired: status=00000000 domain=0 code=-?\d+',stderr),'checkpoint_required_repair_marker')
    result={'repair_marker_observed':True}
    render.validation(stderr)
    env=next(x['environment'] for x in record['launches'] if x['role']=='loader')
    for key,want in {'MTL_DEBUG_LAYER':'1','MTL_SHADER_VALIDATION':'1','MTL_SHADER_VALIDATION_DEFAULT_STATE':'all','MTL_SHADER_VALIDATION_ENABLE_ERROR_REPORTING':'1','PEAR_METAL_PIPELINE_OBSERVE':'1'}.items():
        need(env[key]==want,'checkpoint_validation_settings')
    result['readbacks']=terminal['readbacks'];result['pipelines']=render.pipeline_validation(stderr,terminal['shaders'])
    for dll in ('wined3d.dll','ucrtbase.dll','kernel32.dll','ntdll.dll'):
        source=runtime/PAYLOAD/'lib/wine/aarch64-windows'/dll
        actual=run/'run/prefix/drive_c/windows/system32'/dll
        need(digest(actual.read_bytes())==digest(source.read_bytes()),'checkpoint_compiler_bytes')
        need(re.search(rb'Loaded L"C:\\\\windows\\\\system32\\\\'+re.escape(dll.encode())+rb'" at [0-9a-fA-F]+: builtin',stderr,re.I),'checkpoint_compiler_load')
    return result
