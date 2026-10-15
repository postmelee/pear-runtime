# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Original full seven-fixture verdicts bound to the new completed context."""
from pathlib import Path
from pear_runtime.assembly import core
import json
from . import direct
from .inputs import read,fact,need,save
from .types import CandidateDescription
from .context import FixtureContext,NAMES
from .graphics import render,check_rendering
from .graphics.backend import backend


def fixture(run, description, *, fixture_context=None):
    need(type(description) is CandidateDescription and description.name in direct.CANDIDATES,
         'fixture_candidate_description')
    run=Path(run);record=read(run/'case.json');name=record['diagnostic_fixture']['name']
    runtime=Path(record['runtime_ref']['path']).parent
    need(record['requested']['candidate']==description.name,'fixture_candidate_binding')
    need(type(fixture_context) is FixtureContext and name in NAMES,'fixture_context_type')
    _,value=fixture_context.assessed_runtime(run,record)
    assessed=direct.assess(run)
    need(assessed['fixture_passed'] and record['error'] is None and record['cleanup_errors']==[],'checkpoint_fixture_execution')
    need(record['runtime_ref']==fact(runtime/'runtime.json'),'checkpoint_fixture_runtime')
    declared=value['fixtures'][name]
    need(record['diagnostic_fixture']['artifact']==fact(runtime/declared['path']) and
         fact(runtime/declared['path'])['sha256']==declared['sha256'],'checkpoint_fixture_binding')
    for side in ('before','after'):
        c=core.read_ref(fact(run/side/'control.json'));need(c['passed'] is True and c['runtime_sha256']==record['runtime_sha256'] and c['operation_ref']==fixture_context.value['operation_ref'],'checkpoint_fixture_authority')
    raw={(r['role'],r['channel']):(run/'run'/r['path']).read_bytes() for r in record['logs']}
    events=[e for rows in record['events'].values() for e in rows]
    for role,rows in record['events'].items():
        need([json.loads(line) for line in raw[(role,'events')].splitlines()]==rows,'checkpoint_fixture_events')
    native=[e for e in events if 'translation_value' in e];images=[e for e in events if e['event']=='image']
    need(native and all(e['cpu_type']==16777228 and e['translation_value']==0 and e['translation_error']==0 for e in native),'checkpoint_fixture_architecture')
    need(images and all(e['cpu_type']==16777228 for e in images),'checkpoint_fixture_images')
    exit_event='stage3_guest_exit' if name=='rendering-original' else 'stage3_process_exit'
    need(any(e['event']==exit_event and e['exit_code']==42 for e in record['events']['loader']),'checkpoint_fixture_guest_exit')
    result=dict(passed=True,scope=description.scope,fixture=name,run_ref=fact(run/'case.json'),runtime_ref=fact(runtime/'runtime.json'),checker=fact(Path(__file__)),full_graphics_qualification=False,menu_success=False,steamworks_success=False)
    if name=='rendering-original':
        terminal=render.terminal(raw[('loader','stdout')])
        backend(run,runtime,value,{**record,'fixture_id':name},raw,terminal['modules'])
        result.update(check_rendering(run,runtime,value,record,raw,terminal))
    result['signal_resume']=assessed['signal_resume']
    result['query_observation']=assessed['query_observation']
    if record['requested']['signal_resume']=='on' and name=='suspend-context':
        need(assessed['signal_resume']['observed_message_count']>0,'signal_fixture_emission_missing')
    save(run/'shared-fixture-assessment.json',result)
    return result

