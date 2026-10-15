# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Strict D4 provenance and bounded native timeout evidence from complete logs."""
from pathlib import Path
import re
from pear_runtime.fixtures.inputs import read,digest,need
from pear_runtime.fixtures.assessment.batch import assess as base_assess

def parse(raw):
    writes=[];snapshots={};write_sequences=set()
    for line in raw.splitlines():
        if b'PEAR_WRITE ' in line:
            m=re.fullmatch(rb'(?:Pear FEX error: )?PEAR_WRITE phase=(admission|invoke) seq=(\d+) status=(\d+) domain=(\d+) code=(-?\d+) called=([01]) validated=([01])',line)
            need(m is not None,'write_syntax');phase=m[1].decode();seq,status,domain,code,called,valid=map(int,m.groups()[1:])
            need(seq<8 and seq not in write_sequences and 0<status<=0xffffffff and domain<=0xffffffff and -2**31<=code<2**31,'write_values')
            need((phase!='admission' or not called and not valid) and (not valid or called),'write_invocation_facts')
            write_sequences.add(seq);writes.append(dict(phase=phase,sequence=seq,status=status,domain=domain,code=code,bridge_called=bool(called),validated_refusal=bool(valid)))
        elif b'PEAR_OWNER_TIMEOUT ' in line:
            m=re.fullmatch(rb'PEAR_OWNER_TIMEOUT seq=(\d+) opcode=(\d+) writer=(\d+) active=(\d+) pinned=(\d+) rows=(\d+) truncated=(\d+)',line)
            need(m is not None,'owner_syntax');seq,op,writer,active,pinned,rows,truncated=map(int,m.groups())
            need(seq<8 and seq not in snapshots and op in (2,5) and 0<writer<2**64 and rows<=8 and active+pinned<=64 and active+pinned==rows+truncated and rows==min(8,active+pinned),'owner_values')
            snapshots[seq]=dict(sequence=seq,opcode=op,writer=writer,active=active,pinned=pinned,row_count=rows,truncated=truncated,rows=[])
        elif b'PEAR_OWNER_ROW ' in line:
            m=re.fullmatch(rb'PEAR_OWNER_ROW seq=(\d+) index=(\d+) id=(\d+) state=(\d+) role=(\d+)',line)
            need(m is not None,'owner_row_syntax');seq,index,ident,state,role=map(int,m.groups());need(seq in snapshots,'owner_row_header')
            s=snapshots[seq];need(index==len(s['rows']) and index<s['row_count'] and 0<ident<2**64 and state in (2,3) and role in (1,2),'owner_row_values')
            need(ident not in [r['id'] for r in s['rows']] and (state!=3 or ident!=s['writer']),'owner_row_identity')
            s['rows'].append(dict(index=index,id=ident,state=state,role=role))
    for s in snapshots.values():
        need(len(s['rows'])==s['row_count'],'owner_incomplete')
        a=sum(r['state']==2 for r in s['rows']);p=sum(r['state']==3 for r in s['rows'])
        need(a<=s['active'] and p<=s['pinned'] and (s['truncated'] or (a==s['active'] and p==s['pinned'])),'owner_counts')
    return dict(write_failures=writes,native_timeouts=list(snapshots.values()))

def assess(root):
    root=Path(root);v=read(root/'case.json');result=base_assess(root)
    row=next(r for r in v['logs'] if r['role']=='loader' and r['channel']=='stderr');raw=(root/'run'/row['path']).read_bytes()
    need(digest(raw)==row['sha256'],'write_log');result.update(parse(raw))
    env=next(r for r in v['launches'] if r['role']=='loader')['environment'];setting=env['PEAR_FEX_WRITE_OBSERVE']
    need(setting in ('0','1') and env['PEAR_FEX_OWNER_OBSERVE']==setting==env['PEAR_FEX_BATCH_OBSERVE'],'write_optin')
    need(setting=='1' or not result['write_failures'] and not result['native_timeouts'],'write_disabled_emission')
    return result
