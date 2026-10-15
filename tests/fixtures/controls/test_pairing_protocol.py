# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Original six pure pairing protocol tests; lifecycle tests remain with the supervisor."""
import unittest
from types import SimpleNamespace
from pear_runtime.errors import Error
from pear_runtime.fixtures.controls import pairing as runner

def protocol_rows():
    """Scalar source-protocol observations only, never executable fixtures."""
    leases = [0]*10 + [1,2,2,2,2,2,1,1,2,2,2,2,2,2,2,1,1,1,0,1,1,0,1,1,1,0,0,0,0]
    rows = []
    for index, (name, status) in enumerate(runner.CASES, 1):
        views = 0 if index < 14 else (1 if index < 30 else (2 if index < 33 else 3))
        proxies = int(index >= 20)
        rows.append({'record_kind':'pear_metal_pairing','version':1,'case_id':index,'case':name,
            'status':status,'expected_status':status,'facts':1,'lease_count':leases[index-1],
            'attachment_count':int(leases[index-1]>0),'main_thread':int(index>=14),'x18_mode':0,
            'delegate_state':int(index>=14),'created_views':views,'deallocated_views':views if index==39 else 0,
            'created_layers':views,'deallocated_layers':views if index==39 else 0,
            'created_proxies':proxies,'deallocated_proxies':proxies if index==39 else 0})
    return rows

def wire(rows):
    # Match the actual source-owned prefix rather than JSON's sorted key order.
    import json
    return b''.join(json.dumps(row,separators=(',',':')).encode()+b'\n' for row in rows)


class ProtocolControls(unittest.TestCase):
    def test_complete_protocol_keeps_diagnostic_review_separate(self):
        facts,diagnostics=runner.native_rows(wire(protocol_rows())+b'captured native warning\n')
        self.assertEqual(facts['case_count'],39)
        self.assertEqual(facts['physical_lifetime'],'observed_balanced')
        self.assertEqual(diagnostics,b'captured native warning\n')
        self.assertNotIn('rendering_qualified',facts)

    def test_unknown_unbalanced_or_early_physical_lifetime_refuses(self):
        for index,key,value in [(38,'deallocated_layers',2),(38,'deallocated_proxies',0),
                                (13,'deallocated_views',2),(30,'deallocated_layers',1),
                                (13,'delegate_state',2)]:
            with self.subTest(index=index,key=key):
                rows=protocol_rows();rows[index][key]=value
                with self.assertRaises(Error):runner.native_rows(wire(rows))

    def test_wrong_case_status_lease_main_thread_or_x18_refuses(self):
        for index,key,value in [(15,'facts',0),(21,'status',13),(27,'lease_count',0),
                                (13,'main_thread',0),(13,'x18_mode',1),(23,'case','unknown'),
                                (5,'status',2**32),(1,'expected_status',True)]:
            with self.subTest(index=index,key=key):
                rows=protocol_rows();rows[index][key]=value
                with self.assertRaises(Error):runner.native_rows(wire(rows))

    def test_duplicate_missing_reordered_and_unterminated_rows_refuse(self):
        rows=protocol_rows()
        for raw in [wire(rows[:-1]),wire(rows+[rows[-1]]),wire(rows[1:]+rows[:1]),wire(rows)[:-1]]:
            with self.assertRaises(Error):runner.native_rows(raw)

    def test_own_unknown_json_namespace_cannot_be_hidden_as_diagnostics(self):
        for extra in [b'{"record_kind":"pear_metal_pairing_extra"}\n',
                      b'{"version":1,"record_kind":"pear_metal_pairing"}\n',
                      b' {"record_kind": "pear_metal_pairing"}\n']:
            with self.assertRaises(Error):runner.native_rows(wire(protocol_rows())+extra)

    def test_pe_terminal_requires_primary_and_all_cleanup_success(self):
        helper=SimpleNamespace(base=SimpleNamespace(validate_helper=lambda *args:None))
        terminal={'record_kind':'pear_metal_pairing_pe','version':1,
                  **{key:0 for key in runner.PE_FIELDS},'cleanup_flags':7,'completed_phases':6}
        raw=lambda row:wire([{'record_kind':'pear_bootstrap_helper'},row])
        self.assertEqual(runner.pe_rows(raw(terminal),helper,None)['completed_phases'],6)
        for key,value in [('primary_error',5),('cleanup_error',1),('cleanup_flags',3),
                          ('completed_phases',5),('control_status',False),('primary_step',4)]:
            row=dict(terminal);row[key]=value
            with self.subTest(key=key):
                with self.assertRaises(Error):runner.pe_rows(raw(row),helper,None)
        with self.assertRaises(Error):runner.pe_rows(raw(terminal)+b'additional output\n',helper,None)
