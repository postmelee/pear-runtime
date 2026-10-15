# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Finite same-identity repair revalidation facts; no qualification claim."""
import re
from pear_runtime.fixtures.inputs import need
LINE=re.compile(rb'PEAR_REPAIR1 pid=(\d+) tid=(\d+) seq=(\d+) reason=(\d+) a0=(\d+) a1=(\d+) d0=(\d+) d1=(\d+)\n')
def records(raw,owned):
 lines=[r for r in raw.splitlines(keepends=True) if b'PEAR_REPAIR' in r];need(len(lines)<=16*len(owned),'repair_bound');rows=[];seen=set()
 for line in lines:
  m=LINE.fullmatch(line);need(m is not None and len(line)<=256,'repair_shape')
  pid,tid,seq,reason,a0,a1,d0,d1=map(int,m.groups());need(pid in owned and 0<tid<2**32,'repair_identity')
  need(0<=seq<16 and (pid,seq) not in seen,'repair_sequence');seen.add((pid,seq))
  need(reason in (1,2,3) and all(0<=n<2**64 for n in (a0,a1,d0,d1)),'repair_range')
  if reason==1:need(a0>0 and d0>0 and a1>=a0 and d1>=d0 and (a1>a0 or d1>d0),'repair_advance')
  rows.append(dict(process=pid,thread=tid,sequence=seq,reason=reason,target_before=a0,target_after=a1,dispatcher_before=d0,dispatcher_after=d1))
 return rows

def assess(value,raw):
 owned={value['processes']['loader']['identity']['pid']}|{r['identity']['pid'] for r in value.get('registrations',[])}
 rows=records(raw,owned);need(not rows or (value['requested']['candidate'] in ('d16-optimized','d17-optimized','d18-optimized','d19-optimized','d20-optimized','d21-optimized','d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game','n1-optimized') and value['requested'].get('entry_observation')=='on'),'repair_disabled_emission')
 return dict(count=len(rows),records=rows,complete_timeline=False,successful_publication_proven=False)
