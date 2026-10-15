"""Self-owned, non-executable bytes for contract tests; never runtime evidence."""
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def encoded(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def build_fixture(root, context='fixture'):
    """Write an isolated synthetic DAG. Runtime context is for negative/synthetic tests only."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    records = {}
    references = {}

    def blob(name, data, scope='file_bytes'):
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return {'ref_type': 'blob', 'path': name, 'digest': {'algorithm': 'sha256', 'scope': scope, 'value': hashlib.sha256(data).hexdigest()}}

    source = blob('blobs/source.txt', b'Pear self-owned source fixture, not upstream source.\n', 'source_archive_bytes')
    payload = blob('blobs/payload.txt', b'Pear non-executable payload fixture.\n')
    evidence = blob('blobs/evidence.json', b'{"synthetic":true,"observation":"not executed"}\n', 'evidence_json_bytes')
    build_config = blob('blobs/build-config.json', b'{"schema_version":1,"options":["fixture-only"]}\n', 'build_configuration_bytes')
    terms = blob('blobs/terms.txt', b'Pear test data only; no upstream license claim.\n')

    def put(name, kind, fields):
        value = {'record_kind': kind, 'schema_version': 1, 'record_context': context,
                 'record_id': 'fixture.' + name, 'disclosure': {'mode': 'full', 'withheld': [], 'origin_token': None}, **fields}
        path = 'records/' + name + '.json'
        (root / 'records').mkdir(exist_ok=True)
        data = encoded(value)
        (root / path).write_bytes(data)
        records[name] = value
        references[name] = {'ref_type': 'record', 'path': path, 'record_kind': kind, 'schema_version': 1,
                            'digest': {'algorithm': 'sha256', 'scope': 'exact_utf8_file_bytes', 'value': hashlib.sha256(data).hexdigest()}}
        return copy.deepcopy(references[name])

    host = {'os': 'macos', 'architecture': 'arm64', 'version': [26, 0, 0], 'capabilities': ['fixture-capability']}
    configuration = {'host': host, 'chip': 'synthetic-arm64', 'game_build': 'fixture-game', 'steam_build': 'fixture-steam', 'renderer': 'fixture-renderer', 'translator': 'fixture-translator'}
    lock = put('lock', 'runtime_lock', {
        'source_inventory_ref': None,
        'compatibility_family': {'status': 'known', 'value': 'fixture-family', 'reason': 'Synthetic only.'},
        'component_coverage': {'status': 'known', 'complete': True, 'reason': 'Complete only for this self-owned fixture.'},
        'components': [{'component_id': 'fixture-translator', 'role': 'fixture',
                        'source': {'status': 'known', 'url': 'https://pear.invalid/self-owned-fixture', 'immutable_ref': {'kind': 'archive', 'object_format': None, 'value': None}, 'content': source, 'reason': 'Synthetic bytes.'},
                        'dependencies': {'status': 'known', 'component_ids': [], 'reason': 'No fixture dependencies.'},
                        'patches': {'status': 'known', 'items': [], 'reason': 'No fixture patches.'},
                        'build_context': {'status': 'known', 'toolchain_ids': ['fixture-toolchain'], 'targets': [{'role': 'host', 'format': 'fixture', 'architecture': 'arm64', 'triple': 'fixture-arm64-apple-macos'}], 'configuration': build_config, 'reason': 'No compilation occurred.'},
                        'terms': {'status': 'known', 'references': [terms], 'reason': 'Self-owned fixture terms only.'}, 'evidence': [evidence]}],
        'toolchains': [{'toolchain_id': 'fixture-toolchain', 'version': 'synthetic-v1', 'sdk': 'synthetic-sdk'}],
        'host_requirements': {'status': 'known', 'value': host, 'reason': 'Synthetic requirement.'},
        'signing_requirements': {'status': 'known', 'value': 'development', 'reason': 'No signing occurred.'}, 'evidence': [evidence]})
    artifact = put('artifact', 'runtime_artifact', {'lock': lock, 'compatibility_family': 'fixture-family', 'abi': 'fixture-abi', 'translator_component': 'fixture-translator',
        'files': [{'file_id': 'fixture-main', 'content': payload, 'role': 'host', 'format': 'fixture', 'architecture': 'arm64'}],
        'signing': {'status': 'passed', 'scope': 'development', 'payload_digests': [payload['digest']['value']], 'evidence': evidence}, 'build_evidence': [evidence]})
    profile = put('profile', 'game_profile', {'store': 'fixture', 'app_id': 1, 'game_build': 'fixture-game',
        'executable': {'path_type': 'guest_relative', 'path': 'game.exe'}, 'compatibility_family': 'fixture-family', 'renderer': 'fixture-renderer',
        'arguments': ['value with spaces', '한글'], 'environment': [], 'operations': [{'operation': 'set_setting', 'root': 'prefix', 'path': 'config/options.json', 'key': 'fixture_flag', 'value': True}],
        'required_checks': ['fixture-check'], 'required_processes': ['game'], 'save_paths': [{'root': 'saves', 'path': 'game/save.dat'}]})
    request_fields = {'variant': 'request', 'run_id': 'fixture-run', 'purpose': 'fixture_launch' if context == 'fixture' else 'qualification_run',
        'lock': lock, 'artifact': artifact, 'profile': profile, 'qualification': None,
        'roots': {'runtime': 'state/runtime', 'prefix': 'state/prefix', 'saves': 'state/saves', 'cache': 'state/cache', 'logs': 'state/logs'},
        'prefix_family': 'fixture-family', 'cache_identity': {'lock_digest': lock['digest']['value'], 'artifact_digest': artifact['digest']['value'], 'profile_digest': profile['digest']['value'], 'cpu_features': ['fixture-capability'], 'translator_component': 'fixture-translator', 'abi': 'fixture-abi'},
        'entry_file_id': 'fixture-main', 'observer_required': True, 'configuration': configuration, 'signing_scope': 'development'}
    request = put('request', 'launch', request_fields)
    identity = {'token': 'fixture-process', 'pid': 123, 'generation': 'fixture-generation'}
    events = []
    last = {}
    for name, producer, event, sequence, elapsed, process, covers in [
        ('ready', 'observer', 'observer_ready', 0, 0, None, []),
        ('spawned', 'supervisor', 'spawned', 0, 1, identity, []),
        ('exited', 'supervisor', 'exited', 1, 2, identity, []),
        ('complete', 'observer', 'observer_complete', 1, 3, None, ['fixture-process']),
    ]:
        ref = put(name, 'launch', {'variant': 'event', 'request': request, 'run_id': 'fixture-run', 'producer': producer, 'sequence': sequence,
            'previous': last.get(producer), 'event': event, 'clock_id': 'fixture-clock', 'elapsed_ns': elapsed, 'process': process, 'status': 'passed', 'covers': covers, 'ready_ack': copy.deepcopy(references['ready']) if event == 'spawned' else None, 'completed_exits': [copy.deepcopy(references['exited'])] if event == 'observer_complete' else []})
        last[producer] = ref
        events.append(ref)
    run = put('run', 'run', {'request': request, 'run_id': 'fixture-run', 'events': events, 'failures': [], 'configuration': configuration,
        'started_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'processes': [{'identity': identity, 'purpose': 'game', 'required': True, 'observed': True, 'host_architecture': 'arm64', 'translated': False,
                       'modules': [{'module_id': 'fixture-host-module', 'kind': 'host', 'architecture': 'arm64', 'observed': True, 'source': 'artifact', 'artifact_file_id': 'fixture-main', 'observed_sha256': payload['digest']['value'], 'evidence': [evidence], 'content': payload}, {'module_id': 'fixture-guest-module', 'kind': 'guest', 'architecture': 'x86_64', 'observed': True, 'source': 'game', 'artifact_file_id': None, 'observed_sha256': payload['digest']['value'], 'evidence': [evidence], 'content': None}]}],
        'coverage': {'status': 'passed', 'required_processes': ['game'], 'missing_processes': [], 'missing_modules': [], 'dropped_events': 0},
        'checks': [{'check_id': 'fixture-check', 'status': 'passed', 'evidence': [evidence]}], 'exit': {'kind': 'exited', 'code': 0, 'signal': None, 'cleanup': 'passed'}})
    qualification = put('qualification', 'qualification', {'runs': [run], 'decision': 'supported', 'reviewer': 'fixture-reviewer', 'required_checks': ['fixture-check'],
        'configuration': configuration, 'scope': 'development', 'reviewed_at': records['run']['started_at'], 'test_revision': 'fixture-test-v1', 'limitations': []})
    failure = put('failure', 'failure', {'request': request, 'run_id': 'fixture-run', 'category': 'unknown', 'phase': 'fixture', 'reason_code': 'synthetic_failure', 'component_id': None, 'process_token': None, 'error_code': None, 'evidence': []})
    policy = {'policy_version': 1, 'approved_record_digests': [ref['digest']['value'] for ref in references.values()], 'trusted_reviewers': ['fixture-reviewer'], 'required_checks': ['fixture-check'], 'required_processes': ['game'], 'required_host_modules': ['fixture-host-module'], 'required_guest_modules': ['fixture-guest-module'], 'module_expectations': [{'module_id':'fixture-host-module','kind':'host','source':'artifact','observed_sha256':payload['digest']['value']},{'module_id':'fixture-guest-module','kind':'guest','source':'game','observed_sha256':payload['digest']['value']}], 'host': host, 'allowed_signing_scopes': ['development'], 'max_age_days': 30}
    return {'records': records, 'refs': references, 'paths': {name: ref['path'] for name, ref in references.items()}, 'policy': policy, 'payload': payload, 'evidence': evidence}


def rewrite(root, fixture, name, mutate, *, sync_cache=True):
    """Repair DAG digests after a mutation; optionally keep derived cache identity aligned."""
    root = Path(root)
    value = json.loads((root / fixture['paths'][name]).read_bytes())
    mutate(value)
    (root / fixture['paths'][name]).write_bytes(encoded(value))
    target_paths = set(fixture['paths'].values())
    for _ in range(len(target_paths) + 1):
        changed = False
        for path in sorted(target_paths):
            value = json.loads((root / path).read_bytes())
            def repair(node):
                nonlocal changed
                if isinstance(node, dict):
                    if node.get('ref_type') == 'record' and node.get('path') in target_paths:
                        digest = hashlib.sha256((root / node['path']).read_bytes()).hexdigest()
                        if node['digest']['value'] != digest:
                            node['digest']['value'] = digest
                            changed = True
                    for item in node.values(): repair(item)
                elif isinstance(node, list):
                    for item in node: repair(item)
            repair(value)
            if sync_cache and value.get('record_kind') == 'launch' and value.get('variant') == 'request':
                for field in ('lock', 'artifact', 'profile'):
                    if value[field]:
                        expected = value[field]['digest']['value']
                        if value['cache_identity'][field + '_digest'] != expected:
                            value['cache_identity'][field + '_digest'] = expected
                            changed = True
            (root / path).write_bytes(encoded(value))
        if not changed:
            break
    for key, path in fixture['paths'].items():
        fixture['records'][key] = json.loads((root / path).read_bytes())
        fixture['refs'][key]['digest']['value'] = hashlib.sha256((root / path).read_bytes()).hexdigest()
    fixture['policy']['approved_record_digests'] = [ref['digest']['value'] for ref in fixture['refs'].values()]
