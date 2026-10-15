# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
# Adapted from the retained Task11 D36 game_owner.py; see fixture-game-seam.json.
"""Original D36 post-run observations through the sole canonical FEX readers."""
from pathlib import Path
from pear_runtime import build
from pear_runtime.assembly import core
from pear_runtime.errors import need
from Pear.Diagnostics import attach_observation,binding_census_observation,slot_lifetime_observation


def observe(output):
    output=Path(output);result=dict(schema_version=1,scope='owned_game_fex_observations',
        producer_ref=build.fact(Path(__file__).resolve()),game_qualified=False,guest_execution_qualified=False)
    # Retain the original owner's final evidence links even after an owned-run error.
    result['play_receipts']={}
    for name in ('handoff-request.json','handoff-ack.json','companion-result.json','hud-result.json'):
        path=output/'play'/name
        if path.is_file():result['play_receipts'][name]=build.fact(path)
    assessment=output/'assessment.json'
    if assessment.is_file():result['assessment_ref']=build.fact(assessment)
    case_path=output/'case.json'
    if not case_path.exists():return dict(result,status='unavailable',reason='case_unavailable')
    case_ref=build.fact(case_path);case=core.read_ref(case_ref)
    result.update(case_ref=case_ref,owner_outcome=case['outcome'],owner_error=case['error'],play_handoff=case.get('play_handoff'))
    raw=output/'run/loader.stderr.log'
    if not raw.exists():return dict(result,status='unavailable',reason='loader_log_unavailable')
    need(raw.stat().st_size<=64*1024**2,'game_fex_observation_log_bound')
    raw_ref=build.fact(raw);core.checked_ref(raw_ref,limit=64*1024**2);result['loader_stderr_ref']=raw_ref
    owned={row['identity']['pid'] for row in case['processes'].values()}|{row['identity']['pid'] for row in case['registrations']}
    try:
        result['attach_observation']=attach_observation.assess(raw.read_bytes(),owned)
        result['binding_census']=binding_census_observation.assess(raw.read_bytes(),owned)
        result['slot_lifetime']=slot_lifetime_observation.assess(raw.read_bytes(),owned)
        result['status']='assessed'
    except BaseException as failure:
        result.update(status='failed',attach_assessment_error=dict(type=type(failure).__name__,message=str(failure)))
    core.checked_ref(case_ref);core.checked_ref(raw_ref,limit=64*1024**2)
    return result
