# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Refuse unbound or altered CPU observation evidence without native execution."""
from pathlib import Path
import copy
import json
import tempfile
import unittest
from unittest.mock import patch
from pear_runtime.errors import Error
from pear_runtime.fixtures.controls import cpu_evidence as cpu
from pear_runtime.fixtures.inputs import fact,digest


class CPUObservationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.run=self.root/'run';self.run.mkdir();(self.run/'run').mkdir();self.runtime=self.root/'runtime';self.runtime.mkdir()
        binary=self.runtime/'cpu.exe';binary.write_bytes(b'fixed synthetic PE')
        self.fixture=dict(id='configured-memory',sha256=digest(binary.read_bytes()))
        packet=dict(fixtures={'configured-memory':dict(path='cpu.exe',sha256=self.fixture['sha256'])},
                    entrypoints={'bootstrap_helper':'bootstrap','loader':'loader'})
        (self.runtime/'runtime.json').write_text(json.dumps(packet));self.runtime_ref=fact(self.runtime/'runtime.json')
        identity=dict(pid=101,ppid=100,start_sec=42,start_usec=12)
        self.record=dict(runtime_ref=self.runtime_ref,runtime_sha256=self.runtime_ref['sha256'],outcome='exited',error=None,
            stream_error=None,cleanup_errors=[],cleanup=dict(complete=True,observation_gap=False,errors=[]),sentinel_survived=True,
            authorization_before_after_passed=True,processes={'loader':dict(identity=identity,exit_code=42,reaped=True)},
            events={'loader':[dict(event='loader_entry',translation_value=0,translation_error=0,cpu_type=16777228),
                              dict(event='image',cpu_type=16777228)]},logs=[],
            requested={**cpu.OPTIONS,'candidate':'d25-game','fixture':'configured-memory','budget':'standard120',
                       'log_budget':'standard2','samples':[],'observations':cpu.OBSERVATIONS},
            applied=dict(candidate='d25-game',deadline_seconds=120,stream_limit_bytes=cpu.STREAM_LIMIT,
                observation_environment=cpu.OBSERVATIONS,trace_environment=cpu.ENVIRONMENT['WINEDEBUG'],
                entry_environment={'PEAR_FEX_ENTRY_OBSERVE':'1'},link_environment={'PEAR_FEX_LINK_OBSERVE':'0'},
                query_environment={'PEAR_QUERY_OBSERVE':'0'},signal_environment={'PEAR_SIGNAL_RESUME_OBSERVE':'0'}))
        launches=[dict(role=role,argv=[],environment=dict(cpu.ENVIRONMENT)) for role in ('sentinel','server','loader')]
        launches[-1]['argv']=[str(self.runtime/'bootstrap'),'--exec-4k',str(self.runtime/'loader'),str(binary)]
        launches[-1]['environment'].update(PEAR_WINE_ABI_FIXTURE='1',WINEDLLOVERRIDES='d3d11,dxgi,d3d10core,winemetal=b;mscoree=')
        self.record['launches']=launches;self.record['applied']['launches']=launches
        self.bootstrap=dict(record_kind='pear_bootstrap_helper',version=1,cpu_type=16777228,translation_value=0,query_errno=0,**identity)
        self.logs()

    def logs(self):
        self.record['logs']=[]
        for role in ('loader','server','sentinel'):
            for channel in ('stdout','stderr')+ (('events',) if role=='loader' else ()):
                data=(json.dumps(self.bootstrap)+'\n').encode() if (role,channel)==('loader','stdout') else b''
                if channel=='events':data=b''.join((json.dumps(r)+'\n').encode() for r in self.record['events']['loader'])
                name=role+'.'+channel+'.log';(self.run/'run'/name).write_bytes(data)
                self.record['logs'].append(dict(role=role,channel=channel,path=name,bytes=len(data),observed_bytes=len(data),
                    sha256=digest(data),eof=True,write_error=None))
        (self.run/'case.json').write_text(json.dumps(self.record))

    def observe(self):return cpu.observed_row(self.run,self.record,self.fixture,self.runtime_ref)

    def test_original_bootstrap_host_cleanup_boundary_is_retained(self):
        row,evidence,_=self.observe();self.assertEqual(row['exit_code'],42);self.assertEqual(row['events'],[])
        self.assertFalse(evidence['late_load_coverage_complete']);self.assertTrue(evidence['diagnostic_only'])

    def test_changed_stdout_bytes_cannot_keep_passed_metadata(self):
        (self.run/'run/loader.stdout.log').write_bytes(b'{}\n')
        with self.assertRaisesRegex(Error,'cpu_log_changed'):self.observe()

    def test_bootstrap_must_match_exact_owned_identity(self):
        self.bootstrap['pid']=999;self.logs()
        with self.assertRaisesRegex(Error,'cpu_bootstrap_identity'):self.observe()

    def test_changed_environment_is_not_unobserved_cpu_configuration(self):
        self.record['launches'][-1]['environment']['PEAR_FEX_ABORT_OBSERVE']='0'
        with self.assertRaisesRegex(Error,'cpu_d36_launch_environment'):self.observe()

    def test_requested_policy_cannot_be_downgraded(self):
        self.record['requested']['observations']='off'
        with self.assertRaisesRegex(Error,'cpu_d36_requested_configuration'):self.observe()

    def test_non_arm64_observed_image_cannot_pass(self):
        self.record['events']['loader'][1]['cpu_type']=0x1000007;self.logs()
        with self.assertRaisesRegex(Error,'cpu_non_arm64_image'):self.observe()

    def test_event_summary_cannot_differ_from_captured_log(self):
        self.record['events']['loader'].append(dict(event='image',cpu_type=16777228))
        with self.assertRaisesRegex(Error,'cpu_log_coverage'):self.observe()

    def test_wrong_fixture_operand_is_rejected(self):
        self.record['launches'][-1]['argv'][-1]='/other.exe'
        with self.assertRaisesRegex(Error,'cpu_different_fixture_launched'):self.observe()

    def test_cleanup_gap_is_not_success(self):
        self.record['cleanup']['observation_gap']=True
        with self.assertRaisesRegex(Error,'cpu_owned_cleanup'):self.observe()

    def test_six_reused_rows_cannot_be_missing_or_duplicated(self):
        with self.assertRaisesRegex(Error,'cpu_overlap_complete'):
            cpu.compare_overlap({},[dict(id='tls-thread')]*6,{},provider=None)

    def test_unreleased_operation_is_rejected_before_case_read(self):
        operation=dict(scope='development_fixture_operation',status='passed',lock={'released':False},plan={})
        ref=dict(path=str(self.run.with_name(self.run.name+'.fixture-operation')/'operation.json'))
        with patch.object(cpu.core,'read_ref',return_value=operation):
            with self.assertRaisesRegex(Error,'cpu_reuse_operation'):
                cpu.observe_seven(self.run,self.fixture,ref,self.runtime_ref,source_roots={},checkpoint_pins={})


class AuthorityInterval(unittest.TestCase):
    def packet(self):
        return dict(intervals=[dict(name='current_authority_owned_execution_cleanup',
                    started={'monotonic_seconds':2},ended={'monotonic_seconds':7})],
                    lock=dict(acquired={'monotonic_seconds':1},release_observed={'monotonic_seconds':8}))

    def test_authority_checks_must_belong_to_the_owned_interval(self):
        before=dict(timing=dict(started={'monotonic_seconds':3.1},ended={'monotonic_seconds':4.1}))
        after=dict(timing=dict(started={'monotonic_seconds':5},ended={'monotonic_seconds':6}))
        with patch.object(cpu,'fact',return_value={}),patch.object(cpu.core,'read_ref',side_effect=[before,after]):cpu.authority_interval(Path('/run'),self.packet())
        after['timing']['ended']['monotonic_seconds']=9
        with patch.object(cpu,'fact',return_value={}),patch.object(cpu.core,'read_ref',side_effect=[before,after]):
            with self.assertRaisesRegex(Error,'cpu_authorization_interval_join'):
                cpu.authority_interval(Path('/run'),self.packet())

    def test_six_row_index_cannot_be_a_full19_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            index=dict(schema_version=1,scope='development_cpu_corpus_comparison',runtime_ref={},input_pack_ref={},
                source_provider=dict(root=str(root),commit='a'*40),case_operations=[{'id':x} for x in cpu.OVERLAP],
                ordering_operation_ref={},reuse_source_roots={})
            with patch.object(cpu.core,'read_ref',return_value=index),patch.object(cpu.corpus,'bind_provider'),\
                 patch.object(cpu,'admit_pack'):
                with self.assertRaisesRegex(Error,'cpu_comparison_complete_case_set'):cpu.compare_index({})
