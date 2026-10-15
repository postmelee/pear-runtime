# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""Owned-log assessment assertions imported independently of COFF build checks."""
import unittest

class RunEvidence(unittest.TestCase):
    def setUp(self):
        import json,tempfile
        from pathlib import Path
        from pear_runtime.fixtures.inputs import fact
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        (self.root/'run').mkdir();module=self.root/'module';module.write_bytes(b'synthetic module')
        selection={k:fact(module) for k in ('after','source','fex')};(self.root/'prefix-ntdll.json').write_text(json.dumps(selection))
        identity=dict(pid=10,ppid=9,start_sec=1,start_usec=2)
        self.stdout=(json.dumps(dict(record_kind='pear_bootstrap_helper',cpu_type=16777228,translation_value=0,query_errno=0,**identity))+'\nPEAR_STRING_PASS checks=0000000000008242\n').encode()
        self.value=dict(logs=[],cleanup=dict(complete=True),sentinel_cleanup=dict(complete=True),sentinel_survived=True,cleanup_errors=[],stream_error=None,authorization_before_after_passed=True,fixtures_ref={},fixtures_unchanged=True,runtime_unchanged=True,outcome='exited',processes=dict(loader=dict(exit_code=0,identity=identity)),runtime_ref=dict(sha256='synthetic'),elapsed_ms=1,error=None)
    def record(self,stderr=b''):
        import json,hashlib
        self.value['logs']=[]
        for channel,raw in [('stdout',self.stdout),('stderr',stderr)]:
            name='loader.'+channel+'.log';(self.root/'run'/name).write_bytes(raw)
            self.value['logs'].append(dict(role='loader',channel=channel,path=name,bytes=len(raw),observed_bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),eof=True,write_error=None))
        (self.root/'case.json').write_text(json.dumps(self.value))
    def assess(self):
        from pear_runtime.fixtures.assessment.string import assess
        return assess(self.root)
    def test_complete_fixture(self):
        self.record();self.assertTrue(self.assess()['fixture_passed'])
    def test_success_marker_cannot_hide_exit_failure(self):
        self.value['processes']['loader']['exit_code']=1;self.record();self.assertFalse(self.assess()['fixture_passed'])
    def test_success_marker_cannot_hide_cleanup_failure(self):
        self.value['cleanup']['complete']=False;self.record();self.assertFalse(self.assess()['fixture_passed'])
    def test_mutated_log_refused(self):
        self.record();(self.root/'run/loader.stdout.log').write_bytes(b'changed')
        with self.assertRaisesRegex(Exception,'string_log_changed'):self.assess()
    def test_one_guard_line_counted_once(self):
        self.record(b'Pear FEX assertion: Pear source guard refused\n');v=self.assess();self.assertEqual(v['source_guard_count'],1);self.assertFalse(v['fixture_passed'])


if __name__=='__main__':unittest.main()
