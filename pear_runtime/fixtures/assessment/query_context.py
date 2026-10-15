# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""D11B records preserve D10 refusal rules and explicit context availability."""
import re
from pear_runtime.fixtures.assessment import query as previous
from pear_runtime.fixtures.inputs import need
KEY=previous.KEY
OPTIONS=previous.OPTIONS
CANDIDATES=('d11-original','d11-optimized')
SUFFIX=re.compile(rb' ctx=([01]) syscall=([0-9a-f]+) pc=([0-9a-f]+) lr=([0-9a-f]+)\n$')

def environment(candidate,setting):
    need(candidate in CANDIDATES,'context_candidate')
    return previous.environment(candidate.replace('d11-','d10-',1),setting)

def records(raw,process=None):
    need(b'PEAR_QUERY ' not in raw,'context_mixed_legacy')
    lines=[line for line in raw.splitlines(keepends=True) if b'PEAR_QUERY2 ' in line]
    need(raw.count(b'PEAR_QUERY2 ')==len(lines),'context_framing')
    converted=[];contexts={}
    for line in lines:
        need(len(line)<=512,'context_line_bound');m=SUFFIX.search(line);need(m is not None,'context_suffix')
        body=line[:m.start()].replace(b'PEAR_QUERY2 ',b'PEAR_QUERY ',1)+b'\n'
        # Existing parser validates framing, PID and all query/result fields.
        converted.append(body);seq=re.search(rb' seq=(\d+) ',body);need(seq is not None,'context_sequence')
        available,service,pc,lr=[int(v,10 if i==0 else 16) for i,v in enumerate(m.groups())]
        need(service<2**32 and pc<2**64 and lr<2**64,'context_range')
        need((available and service==0x23 and pc!=0 and lr!=0) or (not available and service==pc==lr==0),'context_availability')
        contexts[int(seq[1])]=dict(available=bool(available),syscall_id=service,pc=pc,lr=lr,caller_attributed=False)
    rows=previous.records(b''.join(converted),process)
    for r in rows:r['context']=contexts[r['ordinal']]
    return rows

def assess(value,raw):
    requested=value['requested'];setting=requested.get('query_observation','historical');expected=environment(requested['candidate'],setting)
    actual=next(r['environment'] for r in value['launches'] if r['role']=='loader')
    need({k:actual[k] for k in (KEY,) if k in actual}==expected,'context_launch_contradiction')
    need(value['applied'].get('query_environment')==expected==value['observed'].get('loader_query_environment'),'context_policy_contradiction')
    rows=records(raw,value['processes']['loader']['identity']['pid']);need(setting=='on' or not rows,'context_disabled_emission')
    return dict(requested=setting,applied=expected,records=rows,count=len(rows),complete_timeline=False,scope='completed self MemoryBasicInformation; saved native syscall context, not an attributed stack trace')
