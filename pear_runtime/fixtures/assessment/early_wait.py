# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""D22 bounded early-wait and native registration facts; no causal conclusion."""
import re
from pear_runtime.fixtures.inputs import need
from pear_runtime.fixtures.assessment import pending_transition as prior
WAIT_END=re.compile(rb' mutation_seq=(\d+) attempts=200\n$')
REGISTER=re.compile(rb'PEAR_OWNER_REGISTER1 pid=(\d+) seq=(\d+) id=(\d+) role=(\d+) valid=(\d+) host=(\d+) register_lo=(\d+) register_hi=(\d+)\n')

def wait_records(raw, owned):
    lines=[line for line in raw.splitlines(keepends=True) if b'PEAR_SOURCE_WAIT' in line]
    converted=[];sequences=[]
    for line in lines:
        m=WAIT_END.search(line)
        need(line.startswith(b'PEAR_SOURCE_WAIT1 ') and m is not None and len(line)<=512,'early_wait_shape')
        sequence=int(m[1]);need(sequence<2**32,'early_wait_sequence')
        converted.append(line[:m.start()].replace(b'PEAR_SOURCE_WAIT1 ',b'PEAR_SOURCE_OWNER2 ',1)+b'\n')
        sequences.append(sequence)
    rows=prior.records(b''.join(converted),owned)
    for row,sequence in zip(rows,sequences):row.update(mutation_sequence=sequence,attempts=200)
    return rows

def registration_records(raw, owned):
    lines=[line for line in raw.splitlines(keepends=True) if b'PEAR_OWNER_REGISTER' in line]
    need(len(lines)<=128*len(owned),'registration_bound');seen=set();ids=set();rows=[]
    for line in lines:
        m=REGISTER.fullmatch(line);need(m is not None and len(line)<=512,'registration_shape')
        pid,sequence,executor,role,valid,host,lo,hi=map(int,m.groups())
        need(pid in owned and sequence<128 and (pid,sequence) not in seen and (pid,executor) not in ids,'registration_identity')
        seen.add((pid,sequence));ids.add((pid,executor))
        need(0<executor<2**64 and role in (1,2) and valid in (0,1),'registration_values')
        if valid:need(0<host<2**64 and 0<lo<=hi<2**64,'registration_host_identity')
        else:need((host,lo,hi)==(0,0,0),'registration_unknown_identity')
        rows.append(dict(process=pid,sequence=sequence,executor=executor,role=role,valid=bool(valid),host_thread=host,register_lo=lo,register_hi=hi))
    return rows

def owner_joins(waits, registrations):
    """Join immutable executor identity; missing/unknown rows remain unknown."""
    result=[]
    for wait in waits:
        matches=[r for r in registrations if (r['process'],r['executor'])==(wait['process'],wait['owner'])]
        need(len(matches)<=1,'registration_ambiguous_join')
        row=matches[0] if matches else None
        mapped=bool(wait['available'] and row and row['valid'] and row['role']==wait['role'])
        result.append(dict(process=wait['process'],wait_sequence=wait['sequence'],owner=wait['owner'],mapped=mapped,
                           host_thread=row['host_thread'] if mapped else None,
                           registration_sequence=row['sequence'] if row else None))
    return result


def trigger(raw, pid, owned=None):
    # An in-progress pipe read may end halfway through a line. Final assessment
    # still rejects an incomplete record; triggering considers complete lines.
    if b'PEAR_SOURCE_WAIT' not in raw:return None
    complete=raw[:raw.rfind(b'\n')+1]
    owned={pid} if owned is None else set(owned)
    need(pid in owned,'early_wait_target_not_owned')
    waits=wait_records(complete,owned)
    registrations=registration_records(complete,owned)
    # Shared stderr includes registered children. Validate their records too,
    # but only the requested game's event can launch its sampler.
    waits=[row for row in waits if row['process']==pid]
    if not waits:return None
    joins=owner_joins(waits,registrations)
    return dict(wait=waits[0],owner_identity=joins[0])

def assess_owner(value, raw):
    need(value['requested']['candidate'] in ('d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game'),'early_wait_candidate')
    return prior.assess({**value,'requested':{**value['requested'],'candidate':'d21-optimized'}},raw)

def assess(value, raw):
    owned={value['processes']['loader']['identity']['pid']}|{r['identity']['pid'] for r in value.get('registrations',[])}
    waits=wait_records(raw,owned);registrations=registration_records(raw,owned);request=value['requested']
    need(not (waits or registrations) or request['candidate'] in ('d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game'),'early_wait_emission_scope')
    need(not waits or request.get('entry_observation')=='on','early_wait_disabled_emission')
    need(not registrations or request.get('observations',{}).get('PEAR_FEX_THREAD_OBSERVE')=='1','registration_disabled_emission')
    samples=value.get('observed',{}).get('samples',[])
    if request.get('samples') in (['source-wait'],['source-wait-short']):
        need(request['candidate'] in ('d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game') and request.get('fixture') is None and request.get('entry_observation')=='on','early_wait_sample_scope')
        need(len(samples)<=1,'early_wait_sample_bound')
        expected=trigger(raw,value['processes']['loader']['identity']['pid'],owned)
        for sample in samples:
            need(expected is not None and sample.get('source_wait_trigger')==expected and sample.get('requested_offset_seconds') is None,'early_wait_sample_trigger')
            need(sample.get('interval_ms')==10 and sample.get('duration_seconds')==(1 if request['samples']==['source-wait-short'] else 2),'early_wait_sample_density')
    else:need(not any('source_wait_trigger' in row for row in samples),'early_wait_unrequested_sample')
    return dict(waits=waits,registrations=registrations,owner_joins=owner_joins(waits,registrations),complete_timeline=False,first_cause_proven=False)
