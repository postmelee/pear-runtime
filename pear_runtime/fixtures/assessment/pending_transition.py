# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Source transition kind at a failed wait; no native opcode or stack claim."""
import re
from pear_runtime.fixtures.assessment import source_owner as prior
from pear_runtime.fixtures.assessment.mutation_bound import records as mutation_records
from pear_runtime.fixtures.inputs import need
KINDS=('unknown','entry','exit','handoff','poll','resume','unpin','unregister')
SUFFIX=re.compile(rb' transition=(\d+)\n$')

def records(raw,owned):
    lines=[line for line in raw.splitlines(keepends=True) if b'PEAR_SOURCE_OWNER' in line]
    converted=[];kinds=[]
    for line in lines:
        need(line.startswith(b'PEAR_SOURCE_OWNER2 ') and len(line)<=512,'pending_transition_protocol')
        match=SUFFIX.search(line);need(match is not None,'pending_transition_shape')
        kind=int(match[1]);need(kind<len(KINDS),'pending_transition_kind')
        converted.append(line[:match.start()].replace(b'PEAR_SOURCE_OWNER2 ',b'PEAR_SOURCE_OWNER1 ',1)+b'\n');kinds.append(kind)
    rows=prior.records(b''.join(converted),owned)
    for row,kind in zip(rows,kinds):
        need(kind==0 or (row['available'] and row['flags']&1),'pending_transition_unknown')
        row.update(transition=kind,transition_name=KINDS[kind])
    return rows

def assess(value,raw):
    owned={value['processes']['loader']['identity']['pid']}|{r['identity']['pid'] for r in value.get('registrations',[])}
    rows=records(raw,owned)
    need(not rows or (value['requested']['candidate']=='d21-optimized' and value['requested'].get('entry_observation')=='on'),'pending_transition_disabled_emission')
    waits=mutation_records(raw,owned)
    for row in rows:
        matches=[w for w in waits if (w['process'],w['thread'],w['executor'],w['last_owner'])==(row['process'],row['thread'],row['executor'],row['owner'])]
        need(len(matches)==1,'pending_transition_wait_join')
    return dict(count=len(rows),records=rows,native_thread_mapping_proven=False,complete_timeline=False,first_cause_proven=False,native_opcode_proven=False)
