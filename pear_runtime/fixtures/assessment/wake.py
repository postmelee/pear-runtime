# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Correlate bounded D5 source scan facts with exact D4 native writer snapshots."""
from pathlib import Path
import re
from pear_runtime.fixtures.inputs import read,digest,need
from pear_runtime.fixtures.assessment.write import assess as base_assess

def parse(raw):
    snapshots={}
    for line in raw.splitlines():
        if b'PEAR_WAKE ' in line:
            m=re.fullmatch(rb'(?:Pear FEX error: )?PEAR_WAKE seq=(\d+) writer=(\d+) epoch=(\d+) writing=([01]) nested=(\d+) rows=(\d+)',line)
            need(m is not None,'wake_syntax');seq,writer,epoch,writing,nested,rows=map(int,m.groups())
            need(seq<8 and seq not in snapshots and 0<writer<2**64 and epoch<2**32 and nested<2**32 and rows<=64 and (writing or rows==0),'wake_values')
            snapshots[seq]=dict(sequence=seq,writer=writer,epoch=epoch,owning_turn_writing=bool(writing),nested_writing=nested,row_count=rows,peers=[])
        elif b'PEAR_WAKE_PEER ' in line:
            m=re.fullmatch(rb'(?:Pear FEX error: )?PEAR_WAKE_PEER seq=(\d+) index=(\d+) id=(\d+) serial=(\d+) role=(\d+) lease=(\d+) flags=(\d+) before=(\d+) checkpoint=([01]) phase=(\d+) status=(\d+)',line)
            need(m is not None,'wake_peer_syntax');seq,index,ident,serial,role,lease,flags,before,checkpoint,phase,status=map(int,m.groups())
            need(seq in snapshots,'wake_peer_header');s=snapshots[seq]
            need(index==len(s['peers']) and index<s['row_count'] and 0<ident<2**64 and ident!=s['writer'] and 0<serial<2**64 and role in (1,2) and lease<=3 and flags<8192 and before<2**32,'wake_peer_values')
            need(ident not in [p['id'] for p in s['peers']],'wake_peer_duplicate')
            need(not flags&1024 or flags&(1|2|4|64|128|256|512)==(1|2|4|64|128|256|512) and not flags&(8|16|32),'wake_publication_flags')
            need(bool(flags&2)==(role==1) and bool(flags&4)==(lease==1),'wake_state_flags')
            need(not before or flags&1024,'wake_before_without_publication')
            need((not checkpoint and phase==status==0) or (checkpoint and s['epoch']>0 and serial<=65535 and 1<=phase<=6 and status<=8 and (phase in (4,6) or status==0)),'wake_checkpoint_values')
            s['peers'].append(dict(index=index,id=ident,serial=serial,role=role,lease=lease,flags=flags,doorbell_before=before,wake_published=bool(flags&1024),checkpoint_available=bool(checkpoint),checkpoint_phase=phase,checkpoint_status=status))
    for s in snapshots.values():need(len(s['peers'])==s['row_count'],'wake_incomplete')
    return list(snapshots.values())

def assess(root):
    root=Path(root);result=base_assess(root);v=read(root/'case.json')
    row=next(r for r in v['logs'] if r['role']=='loader' and r['channel']=='stderr');raw=(root/'run'/row['path']).read_bytes();need(digest(raw)==row['sha256'],'wake_log')
    env=next(r for r in v['launches'] if r['role']=='loader')['environment'];setting=env['PEAR_FEX_WAKE_OBSERVE']
    need(setting in ('0','1') and setting==env['PEAR_FEX_WRITE_OBSERVE'],'wake_optin');scans=parse(raw)
    need(setting=='1' or not scans,'wake_disabled_emission');result['wake_scans']=scans
    matched=[]
    for native in result['native_timeouts']:
        candidates=[s for s in scans if s['writer']==native['writer']]
        # A writer may have multiple failing requests. Do not guess the match.
        for row in native['rows']:
            peers=[p for s in candidates for p in s['peers'] if p['id']==row['id']]
            matched.append(dict(writer=native['writer'],blocker=row['id'],unique_scan=len(candidates)==1,peer_record=peers[0] if len(candidates)==1 and len(peers)==1 else None))
    result['native_source_correlations']=matched
    return result
