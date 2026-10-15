"""V2 schema/eligibility tests. Synthetic candidate acceptance is evaluation only."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import validate as v1
import validate_v2 as v2
from fixture_factory import build_fixture, encoded, rewrite
from v2_fixture import build_v2_fixture, upgrade_fixture
from test_eligibility import synthetic_candidate


class V2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.fixture = upgrade_fixture(self.root, synthetic_candidate(self.root))
    def evaluate(self, purpose='qualification_run', name='request', policy=True, context='runtime'):
        return v2.validate_bundle(self.root, self.fixture['paths'][name], context=context, purpose=purpose,
                                  policy=self.fixture['policy'] if policy is True else policy or None)
    def mutate(self, name, fn): rewrite(self.root, self.fixture, name, fn)
    def denied(self, code=None, **kwargs):
        result=self.evaluate(**kwargs)
        self.assertFalse(result['eligible'],result)
        self.assertTrue(result['evaluation_only'])
        if code: self.assertIn(code,result['outcome_codes'],result)
        return result
    def test_first_qualification_run_without_previous_qualification(self):
        self.assertIsNone(self.fixture['records']['request']['qualification'])
        result=self.evaluate()
        self.assertTrue(result['record_valid'],result)
        self.assertTrue(result['eligible'],result)
        self.assertTrue(result['evaluation_only'])
        self.assertEqual(result['record_count'],4)
    def test_same_candidate_supported_launch_needs_qualification(self):
        self.mutate('request',lambda v:v.update(purpose='supported_launch'))
        self.denied('qualification_required',purpose='supported_launch')
    def test_supported_launch_with_matching_synthetic_qualification(self):
        value=copy.deepcopy(self.fixture['records']['request'])
        value.update(record_id='fixture.supported-request',run_id='fixture-supported',purpose='supported_launch',qualification=self.fixture['refs']['qualification'])
        self.fixture['paths']['supported']='records/supported.json'
        (self.root/self.fixture['paths']['supported']).write_bytes(encoded(value))
        result=self.evaluate('supported_launch','supported')
        self.assertTrue(result['eligible'],result)
        self.assertTrue(result['evaluation_only'])
    def test_supported_launch_mismatched_identity_refuses(self):
        value=copy.deepcopy(self.fixture['records']['request'])
        value.update(record_id='fixture.supported-request',run_id='fixture-supported',purpose='supported_launch',qualification=self.fixture['refs']['qualification'])
        value['configuration']['chip']='different-chip'
        self.fixture['paths']['supported']='records/supported.json'
        (self.root/self.fixture['paths']['supported']).write_bytes(encoded(value))
        self.denied('qualified_identity_mismatch',purpose='supported_launch',name='supported')
    def test_runtime_missing_host_requirement_refuses(self):
        self.mutate('lock',lambda v:v.update(host_requirements={'status':'unknown','value':None,'reason':'Not observed.'}))
        self.denied('host_requirements_unmet')
    def test_runtime_missing_signing_refuses(self):
        self.mutate('artifact',lambda v:v['signing'].update(status='unknown'))
        self.denied('signing_not_qualified')
    def test_runtime_missing_observer_requirement_refuses(self):
        self.mutate('request',lambda v:v.update(observer_required=False))
        self.denied('observer_required')
    def test_runtime_unknown_prefix_family_refuses(self):
        self.mutate('request',lambda v:v.update(prefix_family=None))
        self.denied('incompatible_family')
    def test_runtime_missing_owned_root_shape_refuses(self):
        self.mutate('request',lambda v:v['roots'].pop('prefix'))
        self.denied('schema_invalid')
    def test_runtime_aliased_mutable_root_refuses(self):
        self.mutate('request',lambda v:v['roots'].update(prefix='blobs'))
        self.denied('immutable_path_overlap')
    def test_runtime_without_independent_policy_refuses(self): self.denied('external_policy_required',policy=False)
    def test_runtime_without_independent_exact_identity_refuses(self):
        self.fixture['policy']['approved_record_digests']=[]
        self.denied('identity_not_trusted')
    def test_runtime_without_build_or_source_evidence_refuses(self):
        self.mutate('artifact',lambda v:v.update(build_evidence=[]))
        self.denied('missing_build_evidence')
        self.mutate('lock',lambda v:v.update(source_inventory_ref=None))
        self.denied('source_inventory_required')
    def test_fixture_and_research_cannot_promote_to_runtime(self):
        for context in ('fixture','research'):
            with self.subTest(context=context), tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve(); fixture=build_v2_fixture(root,context)
                rewrite(root,fixture,'request',lambda v:v.update(purpose='qualification_run'))
                result=v2.validate_bundle(root,'records/request.json',context=context,purpose='qualification_run',policy=fixture['policy'])
                self.assertFalse(result['eligible']);self.assertIn('runtime_context_required',result['outcome_codes'])
                relabeled=v2.validate_bundle(root,'records/request.json',context='runtime',purpose='qualification_run',policy=fixture['policy'])
                self.assertFalse(relabeled['record_valid']);self.assertIn('context_mismatch',relabeled['outcome_codes'])
    def test_fixture_targets_relabeled_runtime_still_refuse(self):
        self.mutate('artifact',lambda v:v['files'][0].update(format='fixture'))
        self.denied('fixture_not_runtime')
    def test_unknown_profile_inspection_and_launch_refusal(self):
        self.mutate('profile',lambda v:v.update(compatibility_family=None,renderer=None,save_paths=[],save_inventory_status={'status':'unknown','reason':'Not observed.'}))
        result=self.evaluate('inspect','profile')
        self.assertTrue(result['eligible'],result)
        self.denied()
    def test_unknown_save_inventory_cannot_declare_writable_mapping(self):
        self.mutate('profile',lambda v:v.update(save_inventory_status={'status':'unknown','reason':'No verified inventory.'}))
        self.denied('unknown_save_mapping',purpose='inspect',name='profile')
    def test_profile_metadata_is_closed(self):
        self.mutate('profile',lambda v:v['save_inventory_status'].update(authorize_write=True))
        self.denied('schema_invalid',purpose='inspect',name='profile')
    def test_path_observation_is_metadata_and_requires_evidence(self):
        observation={'kind':'settings','status':'observed','path':{'path_type':'windows_user_relative','path':'AppData/LocalLow/Fixture/settings.json'},'reason':'Synthetic test only.','evidence':[self.fixture['evidence']]}
        self.mutate('profile',lambda v:v['path_observations'].append(observation))
        self.assertTrue(self.evaluate('inspect','profile')['eligible'])
        self.mutate('profile',lambda v:v['path_observations'][0].update(evidence=[]))
        self.denied('missing_path_evidence',purpose='inspect',name='profile')
    def test_unknown_observed_path_cannot_have_a_guessed_value(self):
        self.mutate('profile',lambda v:v['path_observations'].append({'kind':'saves','status':'unknown','path':{'path_type':'windows_user_relative','path':'guessed.dat'},'reason':'Unknown.','evidence':[]}))
        self.denied('knowledge_inconsistent',purpose='inspect',name='profile')
    def test_observed_path_rejects_absolute_and_traversal(self):
        for path in ('C:/private/user/save','../save','/private/save','AppData/../save'):
            with self.subTest(path=path):
                self.mutate('profile',lambda v:v.update(path_observations=[{'kind':'saves','status':'observed','path':{'path_type':'windows_user_relative','path':path},'reason':'Synthetic.','evidence':[self.fixture['evidence']]}]))
                self.denied('invalid_observed_path',purpose='inspect',name='profile')
    def test_feature_pass_is_not_a_qualification(self):
        self.mutate('profile',lambda v:v['features'].append({'feature_id':'gameplay','status':'passed','evidence':[self.fixture['evidence']]}))
        self.mutate('request',lambda v:v.update(purpose='supported_launch'))
        self.denied('qualification_required',purpose='supported_launch')
    def test_feature_result_requires_evidence_and_unique_identity(self):
        self.mutate('profile',lambda v:v['features'].append({'feature_id':'gameplay','status':'passed','evidence':[]}))
        self.denied('missing_feature_evidence',purpose='inspect',name='profile')
        self.mutate('profile',lambda v:v['features'].append(copy.deepcopy(v['features'][0])))
        self.denied('duplicate_identity',purpose='inspect',name='profile')
    def test_provenance_validates_date_and_credential_free_primary_url(self):
        item={'url':'https://pear.invalid/source','review_date':'2026-10-08','scope':'fixture','detail':'Synthetic reference.'}
        self.mutate('profile',lambda v:v.update(provenance=[item]))
        self.assertTrue(self.evaluate('inspect','profile')['eligible'])
        self.mutate('profile',lambda v:v['provenance'][0].update(review_date='2026-02-30'))
        self.denied('invalid_review_date',purpose='inspect',name='profile')
        self.mutate('profile',lambda v:v['provenance'][0].update(review_date='2026-10-08',url='https://user:secret@pear.invalid/source'))
        result=self.denied('invalid_provenance_url',purpose='inspect',name='profile')
        self.assertNotIn('secret',json.dumps(result))
    def test_submitted_manager_environment_binding_refuses(self):
        self.mutate('profile',lambda v:v['environment'].append({'key':'WINEPREFIX','value':'state/prefix'}))
        self.denied('schema_invalid')
    def test_arbitrary_operation_refuses(self):
        self.mutate('profile',lambda v:v['operations'].append({'operation':'shell','root':'prefix','path':'script','key':'execute','value':True}))
        self.denied('schema_invalid')
    def test_mixed_record_and_reference_versions_refuse(self):
        self.mutate('profile',lambda v:v.update(schema_version=1))
        self.denied('unsupported_schema_version')
        self.mutate('profile',lambda v:v.update(schema_version=2))
        self.mutate('request',lambda v:v['profile'].update(schema_version=1))
        self.denied('schema_invalid')
    def test_unknown_version_refuses(self):
        self.mutate('request',lambda v:v.update(schema_version=3))
        self.denied('unsupported_schema_version')
    def test_v1_evaluation_is_unchanged_when_interleaved_with_v2(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();build_fixture(root)
            before=v1.validate_bundle(root,'records/request.json',context='fixture',purpose='fixture_launch')
            self.assertTrue(self.evaluate()['eligible'])
            self.assertEqual(before,v1.validate_bundle(root,'records/request.json',context='fixture',purpose='fixture_launch'))
            self.assertTrue(before['eligible'])
            rejected=v2.validate_bundle(root,'records/request.json',context='fixture',purpose='fixture_launch')
            self.assertEqual(rejected['outcome_codes'],['unsupported_schema_version'])
    def test_v2_preserves_raw_parser_rejection_and_privacy(self):
        path=self.root/self.fixture['paths']['request']
        for raw in (b'{"schema_version":2,"schema_version":2}',b'1.0',br'"\ud800"',b'\xff',b' '*262145):
            with self.subTest(raw=raw[:20]):
                path.write_bytes(raw)
                self.denied()
    def test_schema_registration_refuses_remote_resolution(self):
        with tempfile.TemporaryDirectory() as temp:
            schemas=Path(temp)
            for path in v2.SCHEMAS.glob('*.json'): shutil.copy2(path,schemas/path.name)
            path=schemas/'game-profile.schema.json';value=json.loads(path.read_bytes())
            value['properties']['renderer']={'$ref':'https://untrusted.invalid/schema'}
            path.write_bytes(encoded(value))
            with patch.object(v2,'SCHEMAS',schemas), self.assertRaises(v1.Rejected) as caught: v2.Schemas()
            self.assertEqual(caught.exception.code,'remote_schema_ref')
    def test_schema_registration_rejects_wrong_version(self):
        with tempfile.TemporaryDirectory() as temp:
            schemas=Path(temp)
            for path in v2.SCHEMAS.glob('*.json'): shutil.copy2(path,schemas/path.name)
            path=schemas/'contract-index.json';value=json.loads(path.read_bytes());value['records'][0]['schema_version']=1;path.write_bytes(encoded(value))
            with patch.object(v2,'SCHEMAS',schemas), self.assertRaises(v1.Rejected) as caught: v2.Schemas()
            self.assertEqual(caught.exception.code,'invalid_schema_registry')
    def test_v2_extended_blob_budget_and_v1_original_limit(self):
        path=self.root/'blobs/large';size=v1.BLOB_LIMIT+1
        with path.open('wb') as stream: stream.truncate(size)
        digest=hashlib.sha256()
        with path.open('rb') as stream:
            while data:=stream.read(65536): digest.update(data)
        ref={'ref_type':'blob','path':'blobs/large','digest':{'algorithm':'sha256','scope':'evidence_json_bytes','value':digest.hexdigest()}}
        self.mutate('profile',lambda v:v['features'].append({'feature_id':'large-evidence','status':'untested','evidence':[ref]}))
        self.assertTrue(self.evaluate('inspect','profile')['eligible'])
        root=v1.SafeRoot(self.root)
        try:
            with self.assertRaises(v1.Rejected) as caught: root.read('blobs/large',v1.BLOB_LIMIT)
            self.assertEqual(caught.exception.code,'blob_size_limit')
        finally: root.close()
    def test_v2_oversized_sparse_blob_refuses_before_read(self):
        path=self.root/'blobs/large'
        with path.open('wb') as stream: stream.truncate(v2.BLOB_LIMIT+1)
        ref={'ref_type':'blob','path':'blobs/large','digest':{'algorithm':'sha256','scope':'evidence_json_bytes','value':'0'*64}}
        self.mutate('profile',lambda v:v['features'].append({'feature_id':'large-evidence','status':'untested','evidence':[ref]}))
        self.denied('blob_size_limit',purpose='inspect',name='profile')
    def test_v2_aggregate_blob_budget_is_checked(self):
        schemas = v2.Schemas()
        with patch.object(v2,'BLOB_TOTAL',1), patch.object(v2,'Schemas',return_value=schemas):
            self.denied('blob_total_limit')

if __name__ == '__main__': unittest.main()
