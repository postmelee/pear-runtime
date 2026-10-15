# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Closed D10 query observation policy and loss-intolerant record parsing."""
import re
from pear_runtime.fixtures.inputs import need

KEY='PEAR_QUERY_OBSERVE'
OPTIONS=('historical','on','off')
CANDIDATES=('d10-original','d10-optimized')
LINE=re.compile(rb'PEAR_QUERY pid=(\d+) seq=(\d+) slot=(\d+) tid=(\d+) thread_ok=([01]) sec=(\d+) nsec=(\d+) clock_ok=([01]) addr=([0-9a-f]+) status=([0-9a-f]{8}) valid=([01]) base=([0-9a-f]+) size=([0-9a-f]+) state=([0-9a-f]+) protect=([0-9a-f]+) type=([0-9a-f]+)')
FIELDS=('process','ordinal','slot','thread','thread_ok','seconds','nanoseconds','clock_ok','address','status','valid','base','size','state','protect','type')
HEX={8,9,11,12,13,14,15}


def environment(candidate,setting):
    need(type(setting) is str and setting in OPTIONS,'query_setting')
    need(setting=='historical' or candidate in CANDIDATES,'query_candidate_scope')
    return {} if setting=='historical' else {KEY:'1' if setting=='on' else '0'}


def records(raw,process=None):
    framed=[line for line in raw.splitlines(keepends=True) if b'PEAR_QUERY ' in line]
    need(all(line.endswith(b'\n') for line in framed),'query_incomplete_line')
    lines=[line[:-1] for line in framed]
    need(raw.count(b'PEAR_QUERY ')==len(lines) and len(lines)<=80,'query_record_bound')
    result=[];sequences=set();slots=set()
    for line in lines:
        need(len(line)+1<=512,'query_line_bound');m=LINE.fullmatch(line);need(m is not None,'query_record_syntax')
        r={key:int(value,16 if i in HEX else 10) for i,(key,value) in enumerate(zip(FIELDS,m.groups()))}
        need(1<r['process']<2**31 and (process is None or r['process']==process),'query_process_identity')
        n=r['ordinal'];slot=r['slot']
        need(0<n<2**64 and (n<=16 or not n&(n-1)) and n not in sequences,'query_ordinal')
        need(0<=slot<80 and slot not in slots,'query_slot');sequences.add(n);slots.add(slot)
        need(r['thread_ok']==r['clock_ok']==1 and 0<r['thread']<2**64 and 0<=r['seconds']<2**64 and 0<=r['nanoseconds']<10**9,'query_identity_clock')
        need(all(0<=r[k]<2**64 for k in ('address','base','size')) and all(0<=r[k]<2**32 for k in ('status','state','protect','type')),'query_value_range')
        need(r['valid']==int(r['status']==0),'query_status_contradiction')
        need(r['valid'] or all(r[k]==0 for k in ('base','size','state','protect','type')),'query_failed_result_read')
        result.append(r)
    need(slots==set(range(len(result))),'query_record_gap')
    return sorted(result,key=lambda r:r['ordinal'])


def assess(value,raw):
    req=value['requested'];setting=req.get('query_observation','historical');expected=environment(req['candidate'],setting)
    actual=next(r['environment'] for r in value['launches'] if r['role']=='loader')
    need({k:actual[k] for k in (KEY,) if k in actual}==expected,'query_launch_contradiction')
    if 'query_observation' in req:
        need(value['applied'].get('query_environment')==expected==value['observed'].get('loader_query_environment'),'query_policy_contradiction')
    else:need('query_environment' not in value['applied'],'query_legacy_contradiction')
    rows=records(raw,value['processes']['loader']['identity']['pid']);need(setting=='on' or not rows,'query_disabled_emission')
    return dict(requested=setting if 'query_observation' in req else None,applied=expected,records=rows,
                count=len(rows),complete_timeline=False,scope='completed self MemoryBasicInformation calls; global sparse ordinals')
