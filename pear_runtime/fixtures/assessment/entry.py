# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Closed D12B opt-in and failure-phase record validation."""
import re
from pear_runtime.fixtures.assessment import query_context as query
from pear_runtime.fixtures.inputs import need
KEY='PEAR_FEX_ENTRY_OBSERVE'
CANDIDATES=('d12-original','d12-optimized')
PHASES={1:'gate-precondition',2:'entry-identity',3:'dispatcher-absent',4:'dispatcher-entry',10:'mutation-lifetime',11:'mutation-snapshot',12:'mutation-poll',13:'mutation-wait',14:'mutation-revalidation',15:'mutation-bound',20:'entry-admission',21:'entry-lifetime',22:'entry-seal',23:'entry-bounds',24:'entry-seal-validation',25:'entry-begin-transition',26:'entry-owner-operation',27:'entry-finish-transition',28:'entry-seal-release',30:'exit-propagated'}
LINE=re.compile(rb'PEAR_ECENTRY1 pid=(\d+) tid=(\d+) mode=(\d+) phase=(\d+) status=(\d+) domain=(\d+) code=(-?\d+) facts=(\d+) known=(\d+)\n')

def environment(candidate,setting):
    need(candidate in CANDIDATES,'entry_candidate')
    return query.environment(candidate.replace('d12-','d11-',1),setting)

def settings(candidate,setting):
    need(setting in ('historical','off','on'),'entry_setting')
    need(setting=='historical' or candidate in CANDIDATES,'entry_scope')
    return {} if setting=='historical' else {KEY:'1' if setting=='on' else '0'}

def records(raw,process=None):
    lines=[x for x in raw.splitlines(keepends=True) if b'PEAR_ECENTRY' in x]
    need(len(lines)<=16,'entry_record_bound');rows=[]
    for line in lines:
        m=LINE.fullmatch(line);need(m is not None and len(line)<=512,'entry_record_shape')
        pid,tid,mode,phase,status,domain,code,facts,known=map(int,m.groups())
        need(0<pid<2**32 and 0<tid<2**32 and (process is None or process==pid),'entry_identity')
        need(mode<=2 and phase in PHASES and 1<=status<=8 and domain<2**32 and -2**31<=code<2**31,'entry_record_range')
        need((phase==11 and known==1 and 0<=facts<=3) or (phase!=11 and known==facts==0),'entry_facts')
        need((mode==2 and phase in (1,30)) or (mode!=2 and phase!=30),'entry_mode_phase')
        rows.append(dict(process=pid,thread=tid,mode=mode,phase=phase,phase_name=PHASES[phase],status=status,domain=domain,code=code,facts=facts,known=known))
    return rows

def assess(value,raw):
    # The D11B query record and launch contract remain unchanged.
    request=value['requested'];mapped={**value,'requested':{**request,'candidate':request['candidate'].replace('d12-','d11-',1)}}
    return query.assess(mapped,raw)

def assess_entry(value,raw):
    request=value['requested'];setting=request.get('entry_observation','historical');expected=settings(request['candidate'],setting)
    actual=next(x['environment'] for x in value['launches'] if x['role']=='loader')
    need({k:actual[k] for k in (KEY,) if k in actual}==expected,'entry_launch_policy')
    if setting!='historical':need(value['applied'].get('entry_environment')==expected==value['observed'].get('loader_entry_environment'),'entry_policy_contradiction')
    rows=records(raw,value['processes']['loader']['identity']['pid']);need(setting=='on' or not rows,'entry_disabled_emission')
    return dict(requested=setting,records=rows,count=len(rows),failed_predicate_proven=False)
