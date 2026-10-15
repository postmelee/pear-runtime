# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""D27 proposed three-party Abort evidence join; no runtime policy or execution."""
import re
from .errors import need

TUPLE = 'pid executor allocation generation extent size epoch expected aclass role continuation'.split()
FIELDS = {
 'core': 'pid tid guard call life allocation generation extent size epoch expected aclass role continuation before_epoch before_state begin_state status domain code'.split(),
 'source': 'pid tid guard call life executor allocation generation extent size epoch expected aclass role continuation bridge validated status domain code'.split(),
 'owner': 'pid executor allocation generation extent size epoch expected aclass role continuation reason previous_known previous status domain code'.split(),
}
REASONS = {1:'preexisting-owner-quarantine', 2:'preexisting-extent-quarantine',
           3:'abort-nonreserved-write', 4:'restore-failure'}
CORE_KEY = 'pid tid guard call life allocation generation extent size epoch expected aclass role continuation'.split()

def records(raw, owned):
    need(type(raw) is bytes and len(raw) <= 64*1024**2, 'abort_stream_bound')
    rows=[]
    for line in raw.splitlines(keepends=True):
        if b'PEAR_ABORT' not in line: continue
        need(line.endswith(b'\n') and len(line)<1536, 'abort_line')
        parts=line[:-1].split(b' ')
        need(parts[0]==b'PEAR_ABORT1' and len(parts)>1, 'abort_version')
        need(parts[1].startswith(b'side='), 'abort_side')
        side=parts[1][5:].decode('ascii');need(side in FIELDS, 'abort_side')
        fields=FIELDS[side];need(len(parts)==len(fields)+2, 'abort_fields')
        r={'side':side}
        for k,p in zip(fields,parts[2:]):
            prefix=(k+'=').encode();need(p.startswith(prefix), 'abort_field_order')
            value=p[len(prefix):]
            need(re.fullmatch(rb'-?[0-9]+' if k=='code' else rb'[0-9]+',value), 'abort_number')
            n=int(value);need((-2**31<=n<2**31) if k=='code' else (0<=n<2**64), 'abort_range');r[k]=n
        need(r['pid'] in owned and 0<r['pid']<2**32, 'abort_pid')
        need(r['epoch']>0 and 1<=r['status']<=8 and r['domain']<=3, 'abort_result')
        need(r['domain']!=0 or r['code']==0, 'abort_error_shape')
        if side!='owner':need(0<r['tid']<2**32 and r['guard']>0 and 0<r['call']<=8 and r['life']>0, 'abort_guard')
        if side=='core':
            need(r['life']>0 and 0<r['before_epoch']<r['epoch'], 'abort_lifetime_epoch')
            need(r['before_state'] in (1,3) and r['begin_state']==2, 'abort_begin_states')
        else:
            need(all(r[k]>0 for k in ('executor','allocation','generation','size')), 'abort_tuple')
            need(r['extent']+r['size']<2**64, 'abort_extent')
            need(r['expected']==2 and r['aclass'] in (1,2) and r['role'] in (1,2), 'abort_request_states')
        if side=='source':need(r['bridge']==1 and r['validated']==1, 'abort_validated_refusal')
        if side=='owner':
            need(r['reason'] in REASONS and r['previous_known'] in (0,1), 'abort_reason')
            need(r['previous_known']==1 or r['previous']==0, 'abort_unknown_previous')
            need(r['reason'] not in (3,4) or r['previous_known']==1, 'abort_branch_previous')
            need(r['reason']!=3 or r['previous']!=1, 'abort_nonreserved')
            need(r['reason']!=4 or r['previous']==1, 'abort_restore_reserved')
            need(r['status']==8, 'abort_quarantine')
        rows.append(r);need(len(rows)<=24, 'abort_record_bound')
    return rows

def assess(raw, owned):
    rows=records(raw,owned);by_side={k:[] for k in FIELDS}
    for r in rows:by_side[r['side']].append(r)
    def index(side,keys):
        out={}
        for r in by_side[side]:
            key=tuple(r[k] for k in keys);need(key not in out, 'abort_ambiguous_'+side);out[key]=r
        return out
    cores=index('core',CORE_KEY);sources=index('source',CORE_KEY);owners=index('owner',TUPLE)
    # Repeated source wire tuples cannot identify a unique owner invocation.
    index('source',TUPLE)
    joined=[]
    for key,s in sources.items():
        c=cores.get(key);wire=tuple(s[k] for k in TUPLE);o=owners.get(wire)
        if c is None or o is None:continue
        need(all(c[k]==s[k]==o[k] for k in ('status','domain','code')), 'abort_outcome_mismatch')
        need(c['begin_state']==s['expected'], 'abort_state_mismatch')
        if o['reason'] in (3,4):need(c['before_state']==o['previous'], 'abort_previous_mismatch')
        joined.append(dict(call_id=list(key),source_lifetime=c['life'],request={k:s[k] for k in TUPLE},
          before_epoch=c['before_epoch'],before_state=c['before_state'],reason=REASONS[o['reason']],
          previous_known=bool(o['previous_known']),previous=o['previous'],status=s['status'],domain=s['domain'],code=s['code']))
    return dict(records=len(rows),joined=joined,received_records_joined=bool(joined) and len(joined)==len(cores)==len(sources)==len(owners),
                unmatched_records=len(rows)-3*len(joined),observation_complete=False,invocation_uniqueness_proven=False,record_cap_reached=any(len(v)>=8 for v in by_side.values()),first_global_cause_proven=False,
                mismatch_cause_proven=False,menu_verified=False,steamworks_verified=False,
                scope='Synthetic schema until a selected runtime emits all three records')
