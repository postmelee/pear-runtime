# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Assess complete owned D2 logs and selected bytes without qualifying a game."""
from pathlib import Path
import json,re
from pear_runtime.fixtures.inputs import read,fact,digest,need


def assess(root):
    root=Path(root);v=read(root/'case.json');texts={}
    for row in v['logs']:
        key=(row['role'],row['channel']);need(key not in texts and row['path']=='.'.join(key)+'.log' and '/' not in row['path'],'string_log_path')
        b=(root/'run'/row['path']).read_bytes()
        need(len(b)==row['bytes']==row['observed_bytes'] and digest(b)==row['sha256'] and row['eof'] and row['write_error'] is None,'string_log_changed')
        texts[key]=b
    selected=read(root/'prefix-ntdll.json')
    for k in ('after','source','fex'):need(fact(selected[k]['path'])==selected[k],'string_selection_changed')
    clean=(v['cleanup']['complete'] and v['sentinel_cleanup']['complete'] and v['sentinel_survived'] and not v['cleanup_errors'] and not v['stream_error'])
    authority=v.get('authorization_before_after_passed') is True
    stdout=texts[('loader','stdout')];stderr=texts[('loader','stderr')]
    counts=re.findall(rb'^PEAR_STRING_PASS checks=([0-9a-f]{16})$',stdout,re.M)
    fixture='fixtures_ref' in v
    host=[json.loads(line) for line in stdout.splitlines() if line.startswith(b'{') and b'pear_bootstrap_helper' in line]
    native=(len(host)==1 and host[0]['cpu_type']==16777228 and host[0]['translation_value']==0 and host[0]['query_errno']==0 and all(host[0][k]==v['processes']['loader']['identity'][k] for k in ('pid','ppid','start_sec','start_usec')))
    checks=int(counts[0],16) if len(counts)==1 else None
    guards=sum(b'Pear source guard refused' in line or b'Pear FEX assertion:' in line for line in stderr.splitlines())
    notifications=[dict(status=int(s,16),domain=int(d),code=int(c)) for s,d,c in re.findall(rb'Pear FEX init MemoryNotification.refused: status=([0-9a-f]{8}) domain=(\d+) code=(-?\d+)',stderr)]
    result=dict(run=root.name,case_sha256=fact(root/'case.json')['sha256'],runtime_sha256=v['runtime_ref']['sha256'],
        selected_ntdll_sha256=selected['after']['sha256'],selected_fex_sha256=selected['fex']['sha256'],
        outcome=v['outcome'],loader_exit=v['processes']['loader']['exit_code'],elapsed_ms=v['elapsed_ms'],
        host_bootstrap_arm64_no_rosetta=native,cleanup_passed=bool(clean),authority_passed=authority,runtime_unchanged=v.get('runtime_unchanged') is True,
        source_guard_count=guards,memory_notification_refusals=notifications,illegal_instruction_count=stderr.count(b'code=c000001d'),
        stderr_sha256=digest(stderr),stdout_sha256=digest(stdout),fixture_checks=checks,
        direct_menu_success=False,steamworks_success=False)
    if fixture:
        result['fixture_passed']=bool(native and clean and authority and v.get('fixtures_unchanged') and v.get('runtime_unchanged') and v['outcome']=='exited' and result['loader_exit']==0 and checks==33346 and b'PEAR_STRING_FAIL' not in stdout and not guards and not v['error'])
    else:
        # Original fallback also handles diagnostic fixtures; direct.assess sets their verdict.
        attached=re.search(rb'MODULE_InitDLL \(([0-9A-Fa-f]+) L"GameAssembly\.dll",PROCESS_ATTACH,[^\n]* - CALL',stderr)
        attach_success=bool(attached and re.search(rb'MODULE_InitDLL \('+attached[1]+rb',PROCESS_ATTACH,[^\n]* - RETURN 1',stderr))
        result.update(original_files_unchanged=v.get('original_files_unchanged') is True,
                      player_log_bytes=(root/'Player.log').stat().st_size if (root/'Player.log').exists() else None,
                      gameassembly_attach_success=attach_success)
    return result
