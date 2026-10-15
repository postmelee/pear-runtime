# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Closed D13 completed-link and optional-link admission observations."""
import re
from pear_runtime.fixtures.assessment import entry as entry
from pear_runtime.fixtures.inputs import need
KEY='PEAR_FEX_LINK_OBSERVE'
CANDIDATES=('d13-optimized','d14-optimized','d15-optimized','d16-optimized','d17-optimized','d18-optimized','d19-optimized','d20-optimized','d21-optimized','d22-optimized','d23-16384','d23-65536','d24-131072','d25-fixture','d25-game','n1-optimized')
LINE=re.compile(rb'PEAR_LINK1 pid=(\d+) tid=(\d+) kind=(\d+) reason=(\d+) ordinal=(\d+) a=(\d+) b=(\d+)\n')
def mapped_name(name):
    if name in ('d23-16384','d23-65536','d24-131072','d25-fixture','d25-game'):return 'd12-optimized'
    return name.replace('d22-','d12-',1).replace('d21-','d12-',1).replace('d20-','d12-',1).replace('d19-','d12-',1).replace('n1-','d12-',1).replace('d18-','d12-',1).replace('d17-','d12-',1).replace('d16-','d12-',1).replace('d15-','d12-',1).replace('d14-','d12-',1).replace('d13-','d12-',1)
def mapped(value):return {**value,'requested':{**value['requested'],'candidate':mapped_name(value['requested']['candidate'])}}
def environment(name,setting):return entry.environment(mapped_name(name),setting)
def entry_settings(name,setting):return entry.settings(mapped_name(name),setting)
def settings(name,setting):
    need(setting in ('historical','off','on'),'link_setting')
    need(setting=='historical' or name in CANDIDATES,'link_scope')
    return {} if setting=='historical' else {KEY:'1' if setting=='on' else '0'}
def records(raw,process=None,capacity=64):
    need(capacity in (64,16384,65536,131072),'link_selected_capacity')
    allowed=None if process is None else ({process} if type(process) is int else set(process))
    need(allowed is None or (allowed and all(type(p) is int and 0<p<2**32 for p in allowed)),'link_process_set')
    lines=[s for s in raw.splitlines(keepends=True) if b'PEAR_LINK' in s];need(len(lines)<=136*(len(allowed) if allowed else 1),'link_bound');rows=[];seen=set();counts={}
    for line in lines:
        m=LINE.fullmatch(line);need(m is not None and len(line)<=256,'link_shape')
        pid,tid,kind,reason,n,a,b=map(int,m.groups())
        need(0<pid<2**32 and 0<tid<2**32 and (allowed is None or pid in allowed),'link_identity')
        need(kind in (1,2) and 0<n<=2**63 and (n<=8 or n&(n-1)==0),'link_ordinal')
        need((pid,kind,n) not in seen,'link_duplicate');seen.add((pid,kind,n))
        counts[pid]=counts.get(pid,0)+1;need(counts[pid]<=136,'link_process_bound')
        need(0<=a<2**64 and 0<=b<2**64,'link_values')
        if kind==1:need(0<=reason<128 and (not reason&64 or reason&32) and a>0 and b>0,'link_completed')
        else:
            need(1<=reason<=5 and b==capacity and a<=b,'link_prepare')
            need(reason!=3 or a==b,'link_capacity')
        rows.append(dict(process=pid,thread=tid,kind=kind,reason=reason,ordinal=n,a=a,b=b))
    return rows

def assess(value,raw):return entry.assess(mapped(value),raw)
def assess_entry(value,raw):return entry.assess_entry(mapped(value),raw)
def assess_link(value,raw):
    r=value['requested'];setting=r.get('link_observation','historical');expected=settings(r['candidate'],setting)
    actual=next(x['environment'] for x in value['launches'] if x['role']=='loader')
    need({k:actual[k] for k in (KEY,) if k in actual}==expected,'link_launch_policy')
    if setting!='historical':need(value['applied'].get('link_environment')==expected==value['observed'].get('loader_link_environment'),'link_policy_contradiction')
    # direct.assess validates owned lifecycle/registrations before this parser.
    # Children inherit the stderr sink but have independent saturating ordinals.
    owned={value['processes']['loader']['identity']['pid']}
    owned.update(row['identity']['pid'] for row in value.get('registrations',[]))
    rows=records(raw,owned,131072 if r['candidate'] in ('d24-131072','d25-fixture','d25-game') else 65536 if r['candidate'] in ('d19-optimized','d20-optimized','d21-optimized','d22-optimized','d23-65536') else 16384 if r['candidate'] in ('d14-optimized','d15-optimized','d16-optimized','d17-optimized','d18-optimized','d23-16384','n1-optimized') else 64);need(setting=='on' or not rows,'link_disabled_emission')
    return dict(requested=setting,records=rows,count=len(rows),complete_timeline=False,causality_proven=False)
