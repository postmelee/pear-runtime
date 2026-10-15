# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable independent release controls; no host inspection or guest launch."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import release


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.run=self.root/'case';self.run.mkdir()
        self.op=self.root/'operation';self.op.mkdir()
        self.worker=90000
        self.identities=[dict(pid=self.worker+i,ppid=self.worker,start_sec=100+i,start_usec=i) for i in (1,2,3)]
        self.case={'processes':{role:dict(identity=row) for role,row in zip(('loader','server','sentinel'),self.identities)},
                   'registrations':[dict(identity=self.identities[0])],'runtime_ref':{'synthetic':'runtime'},
                   'diagnostic_fixture':{'name':'tls-thread'}}
        self.operation={'scope':'development_fixture_operation','status':'passed','lock':{'path':str(release.GLOBAL_LOCK),'released':True},
            'worker':{'pid':self.worker,'process_group':self.worker},
            'plan':{'output':str(self.run),'operation_output':str(self.op),'runtime_ref':self.case['runtime_ref'],'fixture':'tls-thread'}}
        self.freeze()
        self.empty=dict(processes={},groups={p:[] for p in self.plan['groups']},provider_ref={'synthetic':'provider'})
        self.handles=dict(handles=[],tool_ref={'synthetic':'lsof'})
        self.lock=dict(available=True,immediately_released=True)

    def freeze(self):
        build.write_json(self.run/'case.json',self.case);self.operation['case_ref']=build.fact(self.run/'case.json')
        build.write_json(self.op/'operation.json',self.operation)
        build.write_json(self.root/'request.json',dict(schema_version=1,scope='development_fixture_release',operations=[build.fact(self.op/'operation.json')]))
        self.ref=build.fact(self.root/'request.json');self.plan=release.inputs(self.ref)

    def verdict(self,observed=None,handles=None,lock=None):
        return release.verdict(self.plan,self.empty if observed is None else observed,self.handles if handles is None else handles,self.lock if lock is None else lock)

    def test_complete_absence_is_passed_and_failed_case_can_release(self):
        self.assertIs(self.verdict()['resource_release_passed'],True)
        self.operation['status']='failed';self.freeze()
        self.assertEqual(self.plan['operations'][0]['original_status'],'failed')
        self.assertEqual(self.verdict()['status'],'passed')

    def test_original_bsdinfo_layout_is_loaded_without_a_host_session(self):
        with patch.object(release.sys,'platform','darwin'),patch.object(release.ctypes,'CDLL',return_value=Mock()):
            probe=release.DarwinProbe()
        self.assertEqual(probe.source_ref['sha256'],'e6d79880e6fb46a20ed23f3966d3fa4139e2c78181a4ccf5e05f86e2ab87f688')
        self.assertIn('start_sec',dict(probe.Info._fields_))
        self.assertIn('pgid',dict(probe.Info._fields_))

    def test_same_birthtime_survivor_is_failed(self):
        seen=copy.deepcopy(self.empty);row={k:v for k,v in self.identities[0].items() if k!='ppid'}
        seen['processes'][row['pid']]=row
        result=self.verdict(seen);self.assertEqual(result['status'],'failed');self.assertEqual(result['original_identities_present'],[row])

    def test_reused_pid_is_not_an_original_survivor(self):
        seen=copy.deepcopy(self.empty);row={**self.identities[0],'start_sec':999}
        seen['processes'][row['pid']]=row
        result=self.verdict(seen);self.assertEqual(result['status'],'passed');self.assertEqual(result['original_identities_present'],[])
        self.assertEqual(len(result['reused_pids']),1)

    def test_worker_pid_without_birthtime_is_unknown(self):
        seen=copy.deepcopy(self.empty);seen['processes'][self.worker]={'pid':self.worker,'start_sec':999,'start_usec':0}
        self.assertEqual(self.verdict(seen)['status'],'unknown')

    def test_unregistered_group_member_is_unknown_and_registered_member_fails(self):
        seen=copy.deepcopy(self.empty);pid=self.identities[0]['pid']
        seen['groups'][pid]=[dict(pid=99999,start_sec=999,start_usec=0)]
        self.assertEqual(self.verdict(seen)['status'],'unknown')
        seen['groups'][pid]=[self.identities[0]]
        self.assertEqual(self.verdict(seen)['status'],'failed')

    def test_owned_handle_or_busy_lock_fails(self):
        self.assertEqual(self.verdict(handles={'handles':[{'pid':2,'path':str(self.run/'log')} ]})['status'],'failed')
        self.assertEqual(self.verdict(lock={'available':False,'immediately_released':False})['status'],'failed')

    def test_missing_case_and_incomplete_roles_are_not_released(self):
        self.operation.pop('case_ref');build.write_json(self.op/'operation.json',self.operation)
        with self.assertRaises(Error):release.inputs(self.ref)
        self.case['processes'].pop('server')
        with self.assertRaisesRegex(Error,'release_process_evidence_incomplete'):self.freeze()

    def test_wrong_case_runtime_and_worker_parent_refused(self):
        self.operation['plan']['runtime_ref']={'wrong':True}
        with self.assertRaisesRegex(Error,'release_case_binding'):self.freeze()
        self.operation['plan']['runtime_ref']=self.case['runtime_ref'];self.identities[0]['ppid']=777
        with self.assertRaisesRegex(Error,'release_worker_parent'):self.freeze()

    def test_unavailable_inspection_is_unknown_not_absent(self):
        with patch.object(release,'DarwinProbe',side_effect=OSError('unavailable')):
            result=release.inspect(self.ref)
        self.assertEqual(result['status'],'unknown');self.assertIs(result['resource_release_passed'],False)

    def test_second_observation_detects_late_survivor(self):
        second=copy.deepcopy(self.empty);second['processes'][self.identities[0]['pid']]=self.identities[0]
        probe=Mock();probe.observe.side_effect=[self.empty,second]
        with patch.object(release,'DarwinProbe',return_value=probe),patch.object(release,'handles',return_value=self.handles),patch.object(release,'lock_probe',return_value=self.lock):
            result=release.inspect(self.ref)
        self.assertEqual(result['status'],'failed');self.assertEqual(result['observation_count'],2)

    def test_mutated_evidence_after_observation_is_unknown(self):
        probe=Mock();probe.observe.return_value=self.empty
        def handle(_):
            (self.run/'case.json').write_text('{}');return self.handles
        with patch.object(release,'DarwinProbe',return_value=probe),patch.object(release,'handles',side_effect=handle),patch.object(release,'lock_probe',return_value=self.lock):
            result=release.inspect(self.ref)
        self.assertEqual(result['status'],'unknown');self.assertFalse(result['resource_release_passed'])

    def test_lsof_keeps_only_owned_descendants_and_deleted_handles(self):
        tool_ref={'synthetic':'tool'}
        raw=(b'p12\0\nf3\0n'+str(self.run/'log').encode()+b' (deleted)\0\np13\0\nf4\0n/unrelated/private\0\n')
        with patch.object(release.build,'fact',return_value=tool_ref),patch.object(release.subprocess,'run',return_value=SimpleNamespace(stdout=raw,stderr=b'',returncode=0)):
            result=release.handles([self.run])
        self.assertEqual(len(result['handles']),1);self.assertEqual(result['handles'][0]['pid'],12)

    def test_lsof_permission_error_and_missing_tool_are_unavailable(self):
        with patch.object(release.build,'fact',return_value={}),patch.object(release.subprocess,'run',return_value=SimpleNamespace(stdout=b'',stderr=b'permission denied',returncode=1)):
            with self.assertRaisesRegex(Error,'release_handles_unavailable'):release.handles([self.run])
        with patch.object(release.build,'fact',side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):release.handles([self.run])

    def test_lock_probe_preserves_bytes_and_does_not_create_missing_file(self):
        path=self.root/'lock';path.write_bytes(b'preserve lock metadata')
        with patch.object(release,'GLOBAL_LOCK',path):
            self.assertEqual(release.lock_probe(),{'available':True,'immediately_released':True})
            self.assertEqual(path.read_bytes(),b'preserve lock metadata')
        missing=self.root/'missing'
        with patch.object(release,'GLOBAL_LOCK',missing):
            with self.assertRaises(FileNotFoundError):release.lock_probe()
        self.assertFalse(missing.exists())


if __name__=='__main__':unittest.main()
