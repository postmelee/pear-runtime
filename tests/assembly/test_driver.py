# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable CLI controls. Synthetic inputs/processes; never Apple signing."""
from contextlib import contextmanager
import copy
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.assembly import core, driver
import test_assembly as fixture_module

PACK_ROOT = fixture_module.PACK_ROOT


class RequestTests(unittest.TestCase):
    write_receipt = fixture_module.InputTests.write_receipt

    def setUp(self):
        fixture_module.InputTests.setUp(self)
        self.recipe_path = self.private/'recipe.json'
        self.bindings_path = self.private/'bindings.json'
        self.request_path = self.private/'request.json'
        build.write_json(self.recipe_path, {'roots':{'source':{'kind':'git','commit':'b'*40}}})
        build.write_json(self.bindings_path, {'roots':{'source':str(self.root)}})
        self.receipt['roots']['source']['path'] = str(self.root)
        self.receipt['recipe_sha256'] = build.fact(self.recipe_path)['sha256']
        build.write_json(self.products/'build.json', self.receipt)
        self.value = dict(schema_version=1, scope='development_candidate_assembly',
            inputs=dict(parent_ref=build.fact(self.parent/'runtime.json'),
                builds=[dict(ref=build.fact(self.products/'build.json'),
                    recipe_sha256=self.receipt['recipe_sha256'], source_commits={'source':'b'*40},
                    recipe_review=dict(mode='file_sha256',public_recipe_ref=build.fact(self.recipe_path),
                                       bindings_ref=build.fact(self.bindings_path),private_manifest_ref=None))],
                roles=['wine_native','fex_pe'], profile_ref=build.fact(self.private/'profile'),
                helper_root=str(PACK_ROOT), output_root=str(self.outputs), name='candidate', disk_floor_bytes=6*1024**3),
            expected_signing_recipe=[{'id':ident,'argv':['/usr/bin/arch','-arm64',*argv]}
                for ident,argv in self.helpers.signing_recipe(self.outputs/'candidate',self.old['native_images'],'f'*40)],
            limits={'whole_timeout_seconds':30,'worker_log_bytes':4096})
        self.request_data()

    def request_data(self):
        build.write_json(self.request_path, self.value)
        return driver.read_request(self.request_path)

    def update_receipt(self):
        build.write_json(self.products/'build.json', self.receipt)
        self.value['inputs']['builds'][0]['ref'] = build.fact(self.products/'build.json')

    def operation(self):
        return build.load(self.outputs/'candidate.assembly-operation/operation.json')

    @contextmanager
    def worker(self):
        with patch('os.getpgrp',return_value=os.getpid()),patch.object(driver,'GLOBAL_LOCK',self.root/'lease.lock'),\
             patch.object(core.shutil,'disk_usage',return_value=type('Disk',(),{'free':100*1024**3})()):
            yield

    def fake_assemble(self, inputs, *, interval, expected_signing_recipe, operation_binding):
        with interval('assembly-sign', self.outputs/'candidate'):
            out=self.outputs/'candidate';out.mkdir()
            build.write_json(out/'runtime.json',{'passed':True,'runtime_qualified':False,
                'diagnostic_only':True,'execution_authorized_by_this_record':False,'game_qualified':False,
                'development_assembly':{},'assembly_operation':operation_binding})
            return build.fact(out/'runtime.json')

    def test_plan_is_read_only_and_does_not_acquire_or_execute(self):
        with patch.object(driver,'lease',side_effect=AssertionError('no lease')),\
             patch.object(core,'assemble',side_effect=AssertionError('no execution')),\
             patch.object(os,'setpgid',side_effect=AssertionError('no group change')):
            plan,summary=driver.review(*self.request_data())
        self.assertEqual(list(self.outputs.iterdir()),[])
        self.assertFalse(summary['permission_admitted']);self.assertFalse(summary['current_authority_assessed'])
        self.assertGreater(summary['storage']['worker_additional_peak_bytes'],plan['storage']['additional_peak_bytes'])

    def test_real_inspect_cli_uses_synthetic_request_without_output(self):
        result=subprocess.run([sys.executable,'-B','-m','pear_runtime.assembly','inspect','--request',str(self.request_path)],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(json.loads(result.stdout)['signing_performed']);self.assertEqual(list(self.outputs.iterdir()),[])

    def test_callback_unknown_fields_and_bad_limits_are_rejected(self):
        for change,code in [('callback','assembly_request_signing_recipe'),('field','assembly_request_shape'),
                            ('limit','assembly_request_limits')]:
            original=copy.deepcopy(self.value)
            if change=='callback':self.value['expected_signing_recipe']='caller_callback'
            if change=='field':self.value['approval_callback']='approve'
            if change=='limit':self.value['limits']['whole_timeout_seconds']=True
            with self.subTest(change=change),self.assertRaisesRegex(Error,code):self.request_data()
            self.value=original

    def test_relative_or_aliased_request_ref_is_rejected(self):
        alias=self.private/'alias.json';alias.symlink_to(self.request_path)
        for path in (Path('request.json'),alias):
            with self.subTest(path=path),self.assertRaises((Error,FileNotFoundError)):driver.read_request(path)

    def test_static_signing_command_edit_is_rejected_before_output(self):
        self.value['expected_signing_recipe'][0]['argv'].append('--extra')
        with self.assertRaisesRegex(Error,'attach_sign_exact_recipe'):driver.review(*self.request_data())
        self.assertEqual(list(self.outputs.iterdir()),[])

    def test_current_request_or_bound_input_drift_fails(self):
        args=self.request_data();self.bindings_path.write_text('{}')
        with self.assertRaisesRegex(Error,'assembly_reference_changed'):driver.review(*args)
        self.assertEqual(list(self.outputs.iterdir()),[])

    def test_file_recipe_expected_hash_cannot_come_only_from_receipt(self):
        self.value['inputs']['builds'][0]['recipe_sha256']='c'*64
        self.receipt['recipe_sha256']='c'*64;self.update_receipt()
        with self.assertRaisesRegex(Error,'assembly_file_recipe_hash'):driver.review(*self.request_data())

    def test_root_binding_and_public_source_pins_match_independently(self):
        for field in ('path','commit'):
            receipt=copy.deepcopy(self.receipt)
            self.receipt['roots']['source'][field]='c'*40 if field=='commit' else '/different'
            if field=='commit':self.value['inputs']['builds'][0]['source_commits']={'source':'c'*40}
            self.update_receipt()
            code='assembly_public_source_pins' if field=='commit' else 'assembly_build_binding'
            with self.subTest(field=field),self.assertRaisesRegex(Error,code):driver.review(*self.request_data())
            self.receipt=receipt;self.value['inputs']['builds'][0]['source_commits']={'source':'b'*40}

    def expanded(self):
        private=self.private/'private-inputs.json';build.write_json(private,{'source':'synthetic private header identity'})
        request=self.value['inputs']['builds'][0]
        request['recipe_sha256']='d'*64
        request['recipe_review'].update(mode='expanded_dict_sha256',private_manifest_ref=build.fact(private))
        self.receipt.update(recipe_sha256='d'*64,public_recipe=build.fact(self.recipe_path),
                            private_manifest=build.fact(private),bindings_manifest=build.fact(self.bindings_path))
        self.update_receipt()
        return private

    def test_expanded_recipe_uses_explicit_expectation_and_both_source_refs(self):
        self.expanded();_,summary=driver.review(*self.request_data())
        self.assertEqual(len(summary['recipe_review_refs']),4)
        self.assertNotEqual(self.value['inputs']['builds'][0]['recipe_sha256'],build.fact(self.recipe_path)['sha256'])

    def test_expanded_receipt_cannot_set_its_own_expected_digest(self):
        self.expanded();self.receipt['recipe_sha256']='e'*64;self.update_receipt()
        with self.assertRaisesRegex(Error,'assembly_build_recipe'):driver.review(*self.request_data())

    def test_expanded_public_ref_requires_exact_absolute_identity(self):
        self.expanded();self.receipt['public_recipe']['path']='recipe.json';self.update_receipt()
        with self.assertRaisesRegex(Error,'assembly_expanded_recipe_provenance'):driver.review(*self.request_data())

    def test_expanded_private_manifest_must_match_receipt(self):
        self.expanded();self.receipt['private_manifest']['sha256']='e'*64;self.update_receipt()
        with self.assertRaisesRegex(Error,'assembly_expanded_recipe_provenance'):driver.review(*self.request_data())

    def test_worker_ownership_is_required_before_lock(self):
        with patch('os.getpgrp',return_value=0),self.assertRaisesRegex(Error,'signing_worker_group_required'):
            driver.execute(*self.request_data())
        self.assertEqual(list(self.outputs.iterdir()),[])

    def test_busy_lease_fails_without_new_outputs(self):
        path=self.root/'lease.lock'
        with path.open('wb') as handle,self.worker():
            fcntl.flock(handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(Error,'assembly_operation_busy'):driver.execute(*self.request_data())
        self.assertEqual(list(self.outputs.iterdir()),[])

    def test_success_retains_fresh_operation_and_live_interval(self):
        with self.worker(),patch.object(core,'assemble',side_effect=self.fake_assemble):
            result=driver.execute(*self.request_data())
        record=self.operation()
        self.assertEqual(core.completed_operation(result['runtime_ref'],build.load(result['runtime_ref']['path']),result['operation_ref']),result['operation_ref'])
        self.assertEqual(record['status'],'passed');self.assertTrue(record['lock']['released'])
        self.assertEqual(len(record['intervals']),1);self.assertFalse(result['runtime_execution_performed'])
        admission=record['phases'][0]
        self.assertEqual(admission['name'],'worker_input_admission')
        self.assertLessEqual(record['lock']['acquired']['monotonic_seconds'],admission['started']['monotonic_seconds'])
        self.assertLessEqual(admission['ended']['monotonic_seconds'],record['intervals'][0]['started']['monotonic_seconds'])
        self.assertEqual(set(record['logs']),{'stdout','stderr'})
        with self.assertRaisesRegex(Error,'assembly_output_exists'):driver.review(*self.request_data())

    def test_failed_execution_retains_original_error(self):
        with self.worker(),patch.object(core,'assemble',side_effect=OSError(13,'synthetic refusal')),self.assertRaises(OSError):
            driver.execute(*self.request_data())
        record=self.operation();self.assertEqual(record['status'],'failed');self.assertEqual(record['error']['errno'],13)
        self.assertTrue(record['lock']['released'])

    def test_aggregate_worker_output_limit_retains_exact_bound(self):
        self.value['limits']['worker_log_bytes']=256
        def noisy(*args,**kwargs):
            print('x'*100,file=sys.stdout);print('y'*300,file=sys.stderr)
        with self.worker(),patch.object(core,'assemble',side_effect=noisy),self.assertRaisesRegex(Error,'assembly_worker_log_limit'):
            driver.execute(*self.request_data())
        record=self.operation();self.assertEqual(sum(r['size_bytes'] for r in record['logs'].values()),256)
        self.assertEqual(record['error']['code'],'assembly_worker_log_limit')

    def test_whole_deadline_unwinds_owned_command_and_preserves_failure(self):
        self.value['limits']['whole_timeout_seconds']=1
        logs=self.outputs/'owned-command'
        code='import os,time;print(os.getpid(),flush=True);time.sleep(60)'
        def blocked(*args,**kwargs):
            logs.mkdir()
            return self.helpers.run_bounded([sys.executable,'-c',code],timeout=30,log_directory=logs)
        started=time.monotonic()
        with self.worker(),patch.object(core,'assemble',side_effect=blocked),self.assertRaisesRegex(Error,'assembly_worker_timeout'):
            driver.execute(*self.request_data())
        self.assertLess(time.monotonic()-started,8)
        record=self.operation();self.assertEqual(record['error']['code'],'assembly_worker_timeout')
        pid=int((logs/'stdout').read_text().strip())
        state=subprocess.run(['ps','-o','stat=','-p',str(pid)],capture_output=True,text=True).stdout.strip()
        self.assertTrue(not state or state.startswith('Z'),state)

    def test_capacity_refusal_occurs_before_operation_output(self):
        with self.worker(),patch.object(core.shutil,'disk_usage',return_value=type('Disk',(),{'free':1})()),\
             self.assertRaisesRegex(Error,'assembly_worker_storage'):
            driver.execute(*self.request_data())
        self.assertEqual(list(self.outputs.iterdir()),[])

    def test_mutating_review_input_during_execution_is_not_success(self):
        def drift(*args,**kwargs):
            self.bindings_path.write_text('{}')
            return {'path':'unused','sha256':'a'*64,'size_bytes':0}
        with self.worker(),patch.object(core,'assemble',side_effect=drift),self.assertRaisesRegex(Error,'assembly_reference_changed'):
            driver.execute(*self.request_data())
        self.assertEqual(self.operation()['status'],'failed')

    def test_successful_inner_receipt_is_not_admitted_after_outer_failure(self):
        def drift(*args,**kwargs):
            ref=self.fake_assemble(*args,**kwargs)
            self.bindings_path.write_text('{}')
            return ref
        with self.worker(),patch.object(core,'assemble',side_effect=drift),self.assertRaisesRegex(Error,'assembly_reference_changed'):
            driver.execute(*self.request_data())
        ref=build.fact(self.outputs/'candidate/runtime.json')
        self.assertTrue(build.load(ref['path'])['passed'])
        self.assertEqual(self.operation()['status'],'failed')
        with self.assertRaisesRegex(Error,'assembly_operation_not_complete'):
            core.verify_current_authority(ref,self.inputs.profile_ref,PACK_ROOT,self.outputs/'authority',
                                          operation_ref=build.fact(self.outputs/'candidate.assembly-operation/operation.json'))
        self.assertFalse((self.outputs/'authority').exists())

    def test_timeout_after_inner_success_is_not_admitted(self):
        self.value['limits']['whole_timeout_seconds']=1
        def late(*args,**kwargs):
            self.fake_assemble(*args,**kwargs)
            time.sleep(60)
        with self.worker(),patch.object(core,'assemble',side_effect=late),self.assertRaisesRegex(Error,'assembly_worker_timeout'):
            driver.execute(*self.request_data())
        ref=build.fact(self.outputs/'candidate/runtime.json')
        self.assertTrue(build.load(ref['path'])['passed'])
        self.assertEqual(self.operation()['status'],'failed')
        with self.assertRaisesRegex(Error,'assembly_operation_not_complete'):
            core.verify_current_authority(ref,self.inputs.profile_ref,PACK_ROOT,self.outputs/'authority',
                                          operation_ref=build.fact(self.outputs/'candidate.assembly-operation/operation.json'))
        self.assertFalse((self.outputs/'authority').exists())



class DeadlineTests(unittest.TestCase):
    def test_deadline_restores_signal_state_after_failure(self):
        import signal
        previous=signal.getsignal(signal.SIGALRM)
        with self.assertRaisesRegex(Error,'assembly_worker_timeout'):
            with driver.deadline(.01):time.sleep(.1)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL),(0.0,0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM),previous)
