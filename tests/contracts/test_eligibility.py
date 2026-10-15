"""Policy evaluation using explicitly synthetic, caller-trusted test data only."""
import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from fixture_factory import build_fixture, encoded, rewrite
from validate import REPO, validate_bundle


def synthetic_candidate(root):
    """Model trusted input relationships; bytes are NOT a real Mach-O/signature/source audit."""
    fixture = build_fixture(root, context='runtime')
    inventory = copy.deepcopy(fixture['evidence']); inventory['digest']['scope'] = 'source_inventory_json_bytes'
    rewrite(root, fixture, 'lock', lambda v: (v.update(source_inventory_ref=inventory), v['components'][0]['build_context']['targets'][0].update(format='mach_o',triple='arm64-apple-macos')))
    rewrite(root, fixture, 'artifact', lambda v: v['files'][0].update(format='mach_o'))
    rewrite(root, fixture, 'profile', lambda v: v.update(store='steam', operations=[]))
    return fixture


class EligibilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.fixture = synthetic_candidate(self.root)

    def tearDown(self): self.tmp.cleanup()

    def evaluate(self, purpose='qualify', name='qualification', policy=True):
        selected = self.fixture['policy'] if policy is True else policy if policy else None
        return validate_bundle(self.root, self.fixture['paths'][name], context='runtime', purpose=purpose, policy=selected)

    def mutate(self, name, fn): rewrite(self.root, self.fixture, name, fn)

    def deny(self, code, **kwargs):
        result = self.evaluate(**kwargs)
        self.assertTrue(result['record_valid'], result)
        self.assertFalse(result['eligible'], result)
        self.assertIn(code, result['outcome_codes'], result)
        self.assertTrue(result['evaluation_only'])

    def test_synthetic_trusted_policy_model_passes_without_execution(self):
        result = self.evaluate()
        self.assertTrue(result['eligible'], result)
        self.assertTrue(result['evaluation_only'])

    def test_fixture_launch_evaluation_allowed_only_in_fixture_context(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); build_fixture(root)
            good = validate_bundle(root, 'records/request.json', context='fixture', purpose='fixture_launch')
            self.assertTrue(good['eligible'], good)
            bad = validate_bundle(root, 'records/qualification.json', context='fixture', purpose='qualify', policy=self.fixture['policy'])
            self.assertFalse(bad['eligible'], bad)
            self.assertIn('runtime_context_required', bad['outcome_codes'])

    def test_research_record_cannot_launch(self):
        result = validate_bundle(REPO/'runtime/contracts/examples', 'research-lock.json', purpose='qualification_run')
        self.assertTrue(result['record_valid'], result)
        self.assertFalse(result['eligible'], result)
        self.assertIn('runtime_context_required', result['outcome_codes'])

    def test_no_self_asserted_support_without_external_policy(self): self.deny('external_policy_required', policy=False)

    def test_reviewer_name_does_not_grant_trust(self):
        self.fixture['policy']['trusted_reviewers'] = []
        self.deny('reviewer_not_trusted')

    def test_matching_hashes_do_not_grant_authenticity(self):
        self.fixture['policy']['approved_record_digests'] = []
        self.deny('identity_not_trusted')

    def test_build_configuration_unknown_blocks_execution(self):
        self.mutate('lock', lambda v: v['components'][0]['build_context'].update(configuration=None))
        self.deny('incomplete_identity')

    def test_target_triple_unknown_blocks_execution(self):
        self.mutate('lock', lambda v: v['components'][0]['build_context']['targets'][0].update(triple=None))
        self.deny('incomplete_identity')

    def test_source_inventory_required_for_runtime(self):
        self.mutate('lock', lambda v: v.update(source_inventory_ref=None))
        self.deny('source_inventory_required')

    def test_source_unknown_remains_inspectable_not_launchable(self):
        self.mutate('lock', lambda v: v['components'][0]['source'].update(status='unknown', reason='Not verified.'))
        self.deny('incomplete_identity')

    def test_failed_build_observation_cannot_use_empty_evidence(self):
        self.mutate('artifact', lambda v: v.update(build_evidence=[]))
        self.deny('missing_build_evidence')

    def test_missing_process_outside_submitted_required_set(self):
        self.fixture['policy']['required_processes'].append('steam-helper')
        self.deny('incomplete_observation')

    def test_submitted_required_process_must_also_be_present(self):
        self.mutate('run', lambda v: v['coverage']['required_processes'].append('missing-helper'))
        self.deny('incomplete_observation')

    def test_fixture_build_target_cannot_qualify_runtime(self):
        self.mutate('lock', lambda v: v['components'][0]['build_context']['targets'][0].update(format='fixture'))
        self.deny('fixture_not_runtime')

    def test_required_artifact_module_matches_actual_artifact_payload(self):
        self.mutate('run', lambda v: v['processes'][0]['modules'][0].update(content=self.fixture['evidence']))
        self.deny('module_identity_mismatch')

    def test_external_module_requires_exact_policy_observation_digest(self):
        self.mutate('run', lambda v: v['processes'][0]['modules'][1].update(observed_sha256='a'*64))
        self.deny('module_policy_mismatch')

    def test_artifact_module_cannot_relabel_itself_as_system(self):
        self.mutate('run', lambda v: v['processes'][0]['modules'][0].update(source='system',artifact_file_id=None,content=None))
        self.deny('module_policy_mismatch')

    def test_missing_module_outside_submitted_list(self):
        self.fixture['policy']['required_host_modules'].append('required-native-helper')
        self.deny('incomplete_module_observation')

    def test_required_check_cannot_be_removed_from_profile(self):
        self.fixture['policy']['required_checks'].append('external-qualification-check')
        self.deny('required_check_not_passed')

    def test_guest_x64_module_is_not_host_rosetta(self):
        self.assertTrue(self.evaluate()['eligible'])
        self.mutate('run', lambda v: v['processes'][0]['modules'][1].update(kind='host',source='system'))
        self.deny('incomplete_module_observation')

    def test_translated_host_blocks_qualification(self):
        self.mutate('run', lambda v: v['processes'][0].update(translated=True))
        self.deny('host_not_native')

    def test_unknown_host_translation_blocks_qualification(self):
        self.mutate('run', lambda v: v['processes'][0].update(translated=None))
        self.deny('host_not_native')

    def test_x64_host_payload_blocks_qualification(self):
        self.mutate('artifact', lambda v: v['files'][0].update(architecture='x86_64'))
        self.deny('host_not_native')

    def test_observer_must_be_ready_before_spawn(self):
        self.mutate('ready', lambda v: v.update(elapsed_ns=1))
        self.deny('observer_lifecycle_incomplete')

    def test_observer_must_complete_after_exit(self):
        self.mutate('complete', lambda v: v.update(elapsed_ns=2))
        self.deny('observer_lifecycle_incomplete')

    def test_omitted_event_still_reachable_via_previous_is_not_coverage(self):
        self.mutate('run', lambda v: v.update(events=[e for e in v['events'] if e['path'] != self.fixture['paths']['spawned']]))
        self.deny('event_gap')

    def test_spawn_without_explicit_ready_ack_is_ineligible(self):
        self.mutate('spawned', lambda v: v.update(ready_ack=None))
        self.deny('readiness_ack_missing')

    def test_ready_ack_on_wrong_receiving_event_is_invalid(self):
        self.mutate('exited', lambda v: v.update(ready_ack=self.fixture['refs']['ready']))
        result = self.evaluate()
        self.assertFalse(result['record_valid'], result)
        self.assertEqual(result['outcome_codes'], ['invalid_ready_ack'])

    def test_spawn_ack_cannot_target_a_nonready_event(self):
        self.mutate('ready', lambda v: v.update(event='gap'))
        result = self.evaluate()
        self.assertFalse(result['record_valid'], result)
        self.assertEqual(result['outcome_codes'], ['invalid_ready_ack'])

    def test_observer_completion_requires_exact_exit_references(self):
        self.mutate('complete', lambda v: v.update(completed_exits=[]))
        self.deny('completion_basis_incomplete')

    def test_completion_basis_to_non_exit_is_invalid(self):
        self.mutate('complete', lambda v: v.update(completed_exits=[self.fixture['refs']['spawned']]))
        result = self.evaluate()
        self.assertFalse(result['record_valid'], result)
        self.assertEqual(result['outcome_codes'], ['invalid_completion_basis'])

    def test_pid_without_matching_creation_generation_is_not_identity(self):
        self.mutate('run', lambda v: v['processes'][0]['identity'].update(generation='reused-pid-generation'))
        self.deny('process_lifecycle_incomplete')

    def test_event_loss_blocks_support(self):
        self.mutate('run', lambda v: v['coverage'].update(dropped_events=1))
        self.deny('incomplete_observation')

    def test_cleanup_failure_blocks_support(self):
        self.mutate('run', lambda v: v['exit'].update(cleanup='failed'))
        self.deny('run_not_passed')

    def test_nonzero_exit_blocks_support(self):
        self.mutate('run', lambda v: v['exit'].update(code=1))
        self.deny('run_not_passed')

    def test_declared_unsupported_check_stays_unsupported(self):
        self.mutate('run', lambda v: v['checks'][0].update(status='unsupported'))
        self.deny('required_check_not_passed')

    def test_failed_qualification_label_cannot_pass(self):
        self.mutate('qualification', lambda v: v.update(decision='failed'))
        self.deny('qualification_not_supported')

    def test_stale_evidence_rejected_by_consumer_age_policy(self):
        old = (datetime.now(timezone.utc) - timedelta(days=60)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.mutate('run', lambda v: v.update(started_at=old))
        self.mutate('qualification', lambda v: v.update(reviewed_at=old))
        self.deny('qualification_expired')

    def test_public_partial_bundle_cannot_qualify(self):
        self.mutate('qualification', lambda v: v.update(disclosure={'mode':'public_partial','withheld':['private_evidence'],'origin_token':'opaque-export-token'}))
        self.deny('partial_bundle')

    def test_policy_is_closed_caller_data(self):
        self.fixture['policy']['grant_everything'] = True
        result = self.evaluate()
        self.assertFalse(result['record_valid'])
        self.assertEqual(result['outcome_codes'], ['invalid_policy'])

    def test_qualification_run_does_not_require_prior_qualification(self):
        result = self.evaluate(purpose='qualification_run', name='request')
        self.assertTrue(result['eligible'], result)

    def test_supported_launch_requires_prior_matching_qualification(self):
        self.mutate('request', lambda v: v.update(purpose='supported_launch'))
        self.deny('qualification_required', purpose='supported_launch', name='request')

    def supported_request(self):
        value = copy.deepcopy(self.fixture['records']['request'])
        value.update(record_id='fixture.supported-request', run_id='fixture-supported-run', purpose='supported_launch', qualification=self.fixture['refs']['qualification'])
        path = 'records/supported-request.json'; (self.root/path).write_bytes(encoded(value))
        self.fixture['paths']['supported-request'] = path
        return value

    def test_supported_launch_matches_exact_prior_inputs(self):
        self.supported_request()
        result = self.evaluate(purpose='supported_launch', name='supported-request')
        self.assertTrue(result['eligible'], result)

    def test_supported_launch_cannot_switch_entry_file_within_same_artifact(self):
        def add_file(value):
            extra = copy.deepcopy(value['files'][0]); extra['file_id'] = 'other-main'
            extra['content'] = copy.deepcopy(extra['content']); extra['content']['path'] = 'blobs/other-payload.txt'
            (self.root / extra['content']['path']).write_bytes((self.root / value['files'][0]['content']['path']).read_bytes())
            value['files'].append(extra)
        self.mutate('artifact', add_file)
        value = self.supported_request(); value['entry_file_id'] = 'other-main'
        (self.root/self.fixture['paths']['supported-request']).write_bytes(encoded(value))
        self.deny('qualified_identity_mismatch', purpose='supported_launch', name='supported-request')

    def test_supported_launch_wrong_configuration_is_not_inferred(self):
        value = self.supported_request(); value['configuration']['chip'] = 'different-chip'
        (self.root/self.fixture['paths']['supported-request']).write_bytes(encoded(value))
        self.deny('qualified_identity_mismatch', purpose='supported_launch', name='supported-request')


if __name__ == '__main__': unittest.main()
