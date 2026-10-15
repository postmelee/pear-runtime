# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Bounded D15 failure callsites; sparse concurrency is not causal ordering."""
import re
from pear_runtime.fixtures.inputs import need
LINE=re.compile(rb'PEAR_FAILURE1 pid=(\d+) tid=(\d+) seq=(\d+) kind=(\d+) caller=([0-9a-f]+) prior=([01]) status=(\d+) domain=(\d+) code=(-?\d+) first=(\d+) allocation=([01])\n')
def records(raw,owned):
    lines=[r for r in raw.splitlines(keepends=True) if b'PEAR_FAILURE' in r]
    need(len(lines)<=16*len(owned),'failure_bound');seen=set();rows=[]
    for line in lines:
        m=LINE.fullmatch(line);need(m is not None and len(line)<=256,'failure_shape')
        values=[int(x,16 if i==4 else 10) for i,x in enumerate(m.groups())]
        pid,tid,seq,kind,caller,prior,status,domain,code,first,allocation=values
        need(pid in owned and 0<tid<2**32,'failure_identity')
        need(0<=seq<16 and (pid,seq) not in seen,'failure_sequence');seen.add((pid,seq))
        need(kind in (1,2,3) and 0<caller<2**64 and 0<=status<=8 and 0<=first<=8 and 0<=domain<2**32 and -2**31<=code<2**31,'failure_range')
        need(kind==1 or status!=0,'failure_result')
        rows.append(dict(process=pid,thread=tid,sequence=seq,kind=kind,caller=caller,prior=bool(prior),status=status,domain=domain,code=code,first_status=first,has_allocation=bool(allocation)))
    return rows

def assess(value,raw):
    owned={value['processes']['loader']['identity']['pid']}
    owned.update(row['identity']['pid'] for row in value.get('registrations',[]))
    rows=records(raw,owned)
    need(not rows or (value['requested']['candidate'] in ('d15-optimized','d16-optimized','d17-optimized','d18-optimized','d19-optimized','d20-optimized','d21-optimized','d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game','n1-optimized') and value['requested'].get('entry_observation')=='on'),'failure_disabled_emission')
    return dict(count=len(rows),records=rows,first_cause_proven=False,complete_timeline=False)
