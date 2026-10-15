# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Failure-only source binding facts; Wine IDs are not native macOS thread IDs."""
import re
from pear_runtime.fixtures.inputs import need
LINE=re.compile(rb'PEAR_SOURCE_OWNER1 pid=(\d+) tid=(\d+) seq=(\d+) executor=(\d+) owner=(\d+) state=(\d+) wine_tid=(\d+) serial=(\d+) role=(\d+) lease=(\d+) holds=(\d+) flags=(\d+)\n')
def records(raw,owned):
    lines=[x for x in raw.splitlines(keepends=True) if b'PEAR_SOURCE_OWNER' in x]
    need(len(lines)<=16*len(owned),'source_owner_bound');seen=set();rows=[]
    for line in lines:
        m=LINE.fullmatch(line);need(m is not None and len(line)<=512,'source_owner_shape')
        pid,tid,seq,executor,owner,state,wine_tid,serial,role,lease,holds,flags=map(int,m.groups())
        need(pid in owned and 0<tid<2**32 and seq<16 and (pid,seq) not in seen,'source_owner_identity');seen.add((pid,seq))
        need(0<executor<2**64 and 0<owner<2**64 and executor!=owner and 1<=state<=5,'source_owner_values')
        if state==1:
            need(0<wine_tid<2**32 and serial<2**64 and role in (1,2) and lease<=3 and holds<2**32 and flags<64,'source_owner_metadata')
        else:need((wine_tid,serial,role,lease,holds,flags)==(0,0,0,0,0,0),'source_owner_unknown_metadata')
        rows.append(dict(process=pid,thread=tid,sequence=seq,executor=executor,owner=owner,state=state,
                         available=state==1,wine_thread=wine_tid,lifetime_serial=serial,role=role,lease=lease,lifetime_holds=holds,flags=flags))
    return rows

def assess(value,raw):
    owned={value['processes']['loader']['identity']['pid']}|{r['identity']['pid'] for r in value.get('registrations',[])}
    rows=records(raw,owned)
    need(not rows or (value['requested']['candidate']=='d20-optimized' and value['requested'].get('entry_observation')=='on'),'source_owner_disabled_emission')
    from pear_runtime.fixtures.assessment.mutation_bound import records as mutation_records
    waits=mutation_records(raw,owned)
    for r in rows:
        matches=[w for w in waits if (w['process'],w['thread'],w['executor'],w['last_owner'])==(r['process'],r['thread'],r['executor'],r['owner'])]
        need(len(matches)==1,'source_owner_wait_join')
    return dict(count=len(rows),records=rows,native_thread_mapping_proven=False,complete_timeline=False,first_cause_proven=False)
