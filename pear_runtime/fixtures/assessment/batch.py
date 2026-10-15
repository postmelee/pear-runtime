# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Read bounded D3 labels only from complete hash-bound owned logs."""
from pathlib import Path
import re
from pear_runtime.fixtures.inputs import read,digest,need
from pear_runtime.fixtures.assessment.string import assess as base_assess
PHASES=('mutation','writer-linked','writer-published','writer-reserved')

def parse(raw):
    result=[];seen=set()
    for line in raw.splitlines():
        if b'PEAR_BATCH ' not in line:continue
        m=re.fullmatch(rb'(?:Pear FEX error: )?PEAR_BATCH phase=([a-z-]+) seq=(\d+) status=(\d+) domain=(\d+) code=(-?\d+)',line)
        need(m is not None,'batch_phase_syntax')
        phase=m[1].decode();seq,status,domain,code=map(int,m.groups()[1:])
        need(phase in PHASES and 0<=seq<8 and 0<status<=0xffffffff and 0<=domain<=0xffffffff and -2**31<=code<2**31,'batch_phase_values')
        need(seq not in seen,'batch_phase_ambiguous_sequence');seen.add(seq)
        result.append(dict(phase=phase,sequence=seq,status=status,domain=domain,code=code))
    need(len(result)<=8,'batch_phase_bound')
    return result

def assess(root):
    root=Path(root);v=read(root/'case.json');result=base_assess(root)
    row=next(r for r in v['logs'] if r['role']=='loader' and r['channel']=='stderr')
    raw=(root/'run'/row['path']).read_bytes();need(digest(raw)==row['sha256'],'batch_phase_log')
    result['batch_phases']=parse(raw)
    launch=next(r for r in v['launches'] if r['role']=='loader');enabled=launch['environment']['PEAR_FEX_BATCH_OBSERVE']
    need(enabled in ('0','1'),'batch_phase_opt_in');result['observation_enabled']=enabled=='1'
    need(enabled=='1' or not result['batch_phases'],'batch_disabled_emission')
    return result
