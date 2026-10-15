# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""D18 bounded contention counters; snapshots are not a clock or a full timeline."""
import re
from pear_runtime.fixtures.inputs import need
LINE=re.compile(rb'PEAR_MUTATION1 pid=(\d+) tid=(\d+) seq=(\d+) executor=(\d+) first=(\d+) last=(\d+) attempts=(\d+) owner_changes=(\d+) sequence_changes=(\d+) waits_ok=(\d+) wait_timeouts=(\d+) polls=(\d+)\n')
def records(raw,owned):
    lines=[line for line in raw.splitlines(keepends=True) if b'PEAR_MUTATION' in line]
    need(len(lines)<=16*len(owned),'mutation_record_bound');seen=set();rows=[]
    for line in lines:
        m=LINE.fullmatch(line);need(m is not None and len(line)<=512,'mutation_record_shape')
        pid,tid,seq,executor,first,last,attempts,owners,sequences,ok,timeouts,polls=map(int,m.groups())
        need(pid in owned and 0<tid<2**32 and 0<=seq<16 and (pid,seq) not in seen,'mutation_record_identity');seen.add((pid,seq))
        need(all(0<x<2**64 for x in (executor,first,last)) and executor not in (first,last),'mutation_owner_identity')
        need(attempts==1000 and 0<=owners<attempts and 0<=sequences<attempts and
             0<=ok<=attempts and 0<=timeouts<=attempts and ok+timeouts==attempts and 0<=polls<=attempts,'mutation_counters')
        need(owners!=0 or first==last,'mutation_owner_contradiction')
        rows.append(dict(process=pid,thread=tid,sequence=seq,executor=executor,first_owner=first,last_owner=last,
            attempts=attempts,observed_owner_changes=owners,observed_sequence_changes=sequences,
            successful_waits=ok,timeout_waits=timeouts,cooperative_polls=polls))
    return rows

def assess(value,raw):
    owned={value['processes']['loader']['identity']['pid']}|{r['identity']['pid'] for r in value.get('registrations',[])}
    rows=records(raw,owned)
    need(not rows or (value['requested']['candidate'] in ('d18-optimized','d19-optimized','d20-optimized','d21-optimized','d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game') and value['requested'].get('entry_observation')=='on'),'mutation_disabled_emission')
    return dict(count=len(rows),records=rows,elapsed_wait_time_known=False,complete_timeline=False,first_cause_proven=False)
