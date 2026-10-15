"""Raw-input, schema, byte-identity and graph contract tests."""
import copy
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
import shutil
from pathlib import Path

from fixture_factory import build_fixture, encoded, rewrite
from validate import REPO, Schemas, validate_bundle


class StructureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.fixture = build_fixture(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def inspect(self, name='qualification'):
        return validate_bundle(self.root, self.fixture['paths'][name], context='fixture')

    def expect(self, code, name='qualification'):
        result = self.inspect(name)
        self.assertFalse(result['record_valid'], result)
        self.assertEqual(result['outcome_codes'], [code], result)
        self.assertTrue(result['evaluation_only'])

    def mutate(self, name, fn):
        rewrite(self.root, self.fixture, name, fn)

    def test_all_seven_kinds_and_schema_store(self):
        Schemas()
        for name in ('lock', 'artifact', 'profile', 'request', 'run', 'qualification', 'failure'):
            self.assertTrue(self.inspect(name)['eligible'], name)

    def test_valid_incomplete_research_is_inspectable(self):
        result = validate_bundle(REPO / 'runtime/contracts/examples', 'research-lock.json')
        self.assertTrue(result['record_valid'], result)
        self.assertTrue(result['eligible'], result)

    def test_schema_registry_cannot_redirect_to_remote_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); shutil.copytree(REPO / 'runtime/contracts/v1', root / 'v1')
            index = json.loads((REPO / 'runtime/contracts/contract-index.json').read_bytes())
            index['records'][0]['schema_path'] = 'https://untrusted.invalid/schema'
            (root / 'contract-index.json').write_bytes(encoded(index))
            with patch('validate.SCHEMAS', root / 'v1'):
                result = self.inspect()
            self.assertEqual(result['outcome_codes'], ['invalid_schema_registry'])

    def test_unknown_schema_ref_is_rejected_without_retrieval(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); shutil.copytree(REPO / 'runtime/contracts/v1', root / 'v1')
            shutil.copyfile(REPO / 'runtime/contracts/contract-index.json', root / 'contract-index.json')
            schema_path = root / 'v1/runtime-lock.schema.json'
            value = json.loads(schema_path.read_bytes()); value['properties']['components']['items'] = {'$ref':'https://untrusted.invalid/schema'}
            schema_path.write_bytes(encoded(value))
            with patch('validate.SCHEMAS', root / 'v1'):
                result = self.inspect()
            self.assertEqual(result['outcome_codes'], ['remote_schema_ref'])

    def test_unresolved_local_definition_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); shutil.copytree(REPO / 'runtime/contracts/v1', root / 'v1')
            shutil.copyfile(REPO / 'runtime/contracts/contract-index.json', root / 'contract-index.json')
            schema_path = root / 'v1/runtime-lock.schema.json'
            value = json.loads(schema_path.read_bytes()); value['properties']['components']['items'] = {'$ref':'https://pear.invalid/contracts/v1/common.schema.json#/$defs/not-present'}
            schema_path.write_bytes(encoded(value))
            with patch('validate.SCHEMAS', root / 'v1'):
                result = self.inspect()
            self.assertEqual(result['outcome_codes'], ['unresolved_schema_ref'])

    def test_unknown_field_is_rejected(self):
        self.mutate('lock', lambda v: v.update(required_policy='self-trusted'))
        self.expect('schema_invalid')

    def test_unsupported_version(self):
        path = self.root / self.fixture['paths']['profile']
        record = json.loads(path.read_bytes()); record['schema_version'] = 2; path.write_bytes(encoded(record))
        self.expect('unsupported_schema_version')

    def test_boolean_schema_version(self):
        self.mutate('lock', lambda v: v.update(schema_version=True))
        self.expect('unsupported_schema_version')

    def test_digest_is_over_actual_record_bytes(self):
        path = self.root / self.fixture['paths']['lock']
        path.write_bytes(path.read_bytes() + b' ')
        self.expect('digest_mismatch')

    def test_digest_is_over_actual_blob_bytes(self):
        path = self.root / self.fixture['payload']['path']
        path.write_bytes(path.read_bytes() + b'changed')
        self.expect('digest_mismatch')

    def test_signature_digest_cannot_replace_payload_digest(self):
        self.mutate('artifact', lambda v: v['signing'].update(payload_digests=[self.fixture['evidence']['digest']['value']]))
        self.expect('signing_payload_mismatch')

    def test_typed_signature_blob_cannot_be_build_payload(self):
        self.mutate('artifact', lambda v: v['files'][0]['content']['digest'].update(scope='signature_bytes'))
        self.expect('digest_scope_mismatch')

    def test_reference_kind_disagreement(self):
        self.mutate('artifact', lambda v: v['lock'].update(record_kind='game_profile'))
        self.expect('reference_kind_mismatch')

    def test_reused_logical_record_id(self):
        self.mutate('profile', lambda v: v.update(record_id='fixture.lock'))
        self.expect('duplicate_identity')

    def test_dependency_cycle(self):
        self.mutate('lock', lambda v: v['components'][0]['dependencies'].update(component_ids=['fixture-translator']))
        self.expect('component_cycle')

    def test_record_cycle_is_bounded_before_hash_check(self):
        value = json.loads((self.root / self.fixture['paths']['artifact']).read_bytes())
        value['lock'] = copy.deepcopy(self.fixture['refs']['qualification'])
        (self.root / self.fixture['paths']['artifact']).write_bytes(encoded(value))
        self.expect('reference_cycle')

    def test_unknown_toolchain(self):
        self.mutate('lock', lambda v: v['components'][0]['build_context'].update(toolchain_ids=['not-listed']))
        self.expect('unknown_toolchain')

    def test_unknown_dependency(self):
        self.mutate('lock', lambda v: v['components'][0]['dependencies'].update(component_ids=['not-listed']))
        self.expect('unknown_component')

    def test_git_object_length_and_type(self):
        self.mutate('lock', lambda v: v['components'][0]['source'].update(immutable_ref={'kind':'git_commit','object_format':'sha256','value':'a'*40}))
        self.expect('immutable_ref_invalid')

    def test_real_calendar_date(self):
        self.mutate('run', lambda v: v.update(started_at='2026-99-28T00:00:00Z'))
        self.expect('invalid_timestamp')

    def test_duplicate_process_generation_identity(self):
        def change(value):
            clone = copy.deepcopy(value['processes'][0]); clone['identity']['token'] = 'second-token'; value['processes'].append(clone)
        self.mutate('run', change)
        self.expect('duplicate_identity')

    def test_duplicate_module_identity(self):
        self.mutate('run', lambda v: v['processes'][0]['modules'].append(copy.deepcopy(v['processes'][0]['modules'][0])))
        self.expect('duplicate_identity')

    def test_event_previous_generation_is_exact_request(self):
        self.mutate('complete', lambda v: v.update(sequence=7))
        self.expect('event_sequence')

    def test_event_owner_cannot_claim_supervisor_event(self):
        self.mutate('spawned', lambda v: v.update(producer='observer'))
        self.expect('event_ownership')

    def test_mixed_context_bundle(self):
        self.mutate('artifact', lambda v: v.update(record_context='runtime'))
        self.expect('context_mismatch')

    def test_raw_duplicate_key(self):
        path = self.root / self.fixture['paths']['lock']
        raw = path.read_bytes().replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1')
        path.write_bytes(raw)
        self.expect('duplicate_key')

    def test_json_depth_bound(self):
        (self.root / 'deep.json').write_text('[' * 33 + '0' + ']' * 33)
        result = validate_bundle(self.root, 'deep.json', context='fixture')
        self.assertEqual(result['outcome_codes'], ['json_depth_limit'])

    def test_json_size_bound(self):
        (self.root / 'large.json').write_bytes(b' ' * (256 * 1024 + 1))
        result = validate_bundle(self.root, 'large.json', context='fixture')
        self.assertEqual(result['outcome_codes'], ['json_size_limit'])

    def test_json_node_limit_is_bounded_before_schema_evaluation(self):
        (self.root / 'nodes.json').write_bytes(b'[' + b','.join([b'0'] * 8192) + b']')
        result = validate_bundle(self.root, 'nodes.json', context='fixture')
        self.assertEqual(result['outcome_codes'], ['json_node_limit'])

    def test_per_record_reference_limit(self):
        self.mutate('run', lambda v: v.update(events=[copy.deepcopy(v['events'][0]) for _ in range(64)]))
        self.expect('reference_count_limit')

    def test_large_blob_is_rejected_before_read(self):
        with (self.root / self.fixture['payload']['path']).open('wb') as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        self.expect('blob_size_limit')

    def test_aggregate_blob_budget_is_checked_before_hashing_next_file(self):
        with patch('validate.BLOB_TOTAL', 1):
            self.expect('blob_total_limit')

    def test_aggregate_json_budget_is_checked_before_next_record(self):
        with patch('validate.JSON_TOTAL', 1):
            self.expect('json_total_limit')

    def test_record_count_limit_on_acyclic_event_chain(self):
        previous = None
        for index in range(130):
            value = copy.deepcopy(self.fixture['records']['ready'])
            value.update(record_id='chain.' + str(index), previous=previous, sequence=index, event='gap', elapsed_ns=index)
            path = 'chain-' + str(index) + '.json'; data = encoded(value); (self.root/path).write_bytes(data)
            previous = {'ref_type':'record','path':path,'record_kind':'launch','schema_version':1,'digest':{'algorithm':'sha256','scope':'exact_utf8_file_bytes','value':hashlib.sha256(data).hexdigest()}}
        result = validate_bundle(self.root, path, context='fixture')
        self.assertEqual(result['outcome_codes'], ['record_count_limit'])

    def test_record_alias_is_rejected(self):
        # Two hard-link names cannot evade immutable record identity.
        import os
        original = self.root / self.fixture['paths']['profile']
        alias = self.root / 'alias.json'; os.link(original, alias)
        value = self.fixture['records']['request']; value['qualification'] = copy.deepcopy(self.fixture['refs']['profile']); value['qualification']['path'] = 'alias.json'
        (self.root / self.fixture['paths']['request']).write_bytes(encoded(value))
        self.expect('record_alias', 'request')


if __name__ == '__main__': unittest.main()
