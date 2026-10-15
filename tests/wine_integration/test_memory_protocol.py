# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact original assertions; historical finite transcript scope only."""
import unittest
from tests.fex.memory import protocol as WIRE

def original_response(**fields):
    value = dict.fromkeys(WIRE.RESPONSE_NAMES, 0)
    value.update(version=2, size=128)
    value.update(fields)
    return WIRE.RESPONSE.pack(*(value[name] for name in WIRE.RESPONSE_NAMES))


class MemoryProtocolTests(unittest.TestCase):
    def test_request_offsets_and_malformed_control_are_independently_encoded(self):
        raw = WIRE.request(opcode=2, owner_pid=17, executor_id=19,
                           allocation_id=23, generation=29, reserved2=31)
        self.assertEqual(len(raw), 128)
        self.assertEqual(int.from_bytes(raw[8:12], 'little'), 2)
        self.assertEqual(int.from_bytes(raw[16:24], 'little'), 17)
        self.assertEqual(int.from_bytes(raw[48:56], 'little'), 19)
        self.assertEqual(int.from_bytes(raw[120:128], 'little'), 31)
        with self.assertRaises(WIRE.ProtocolError):
            WIRE.request(owner_pid=True)
        with self.assertRaises(WIRE.ProtocolError):
            WIRE.request(operation_offset=1 << 64)

    def test_abi2_refuses_old_or_unknown_wire_versions(self):
        self.assertEqual(int.from_bytes(WIRE.request(opcode=14)[:4], "little"), 2)
        for version in (0, 1, 3):
            with self.subTest(version=version), self.assertRaises(WIRE.ProtocolError):
                WIRE.response(original_response(version=version))

    def test_original_signed_ntstatus_is_preserved_in_refusal(self):
        raw = original_response(status=7, native_error_domain=2,
                                native_error_code=-1073741675)
        value = WIRE.response(raw)
        self.assertEqual(value['native_error_code'], -1073741675)
        self.assertEqual(int.from_bytes(raw[20:24], 'little'), 0xc0000095)

    def test_refusal_cannot_expose_pointer_or_success_state(self):
        for field, number in [('private_write_base', 4096), ('owner_pid', 17),
                              ('capabilities', 15), ('lifecycle_state', 1),
                              ('flags', 1), ('allocation_id', 3)]:
            with self.subTest(field=field), self.assertRaises(WIRE.ProtocolError):
                WIRE.response(original_response(status=3, **{field: number}))

    def test_nonzero_errno_without_domain_is_not_accepted(self):
        with self.assertRaises(WIRE.ProtocolError):
            WIRE.response(original_response(status=7, native_error_code=13))
        with self.assertRaises(WIRE.ProtocolError):
            WIRE.response(original_response(status=0, native_error_domain=1,
                                            native_error_code=13))

    def test_record_truncation_and_unknown_fields_are_rejected(self):
        raw = original_response()
        for damaged in [raw[:-1], raw + b'\0']:
            with self.subTest(length=len(damaged)), self.assertRaises(WIRE.ProtocolError):
                WIRE.response(damaged)
        for fields in [{'status': 9}, {'flags': 6}, {'flags': 8},
                       {'reserved0': 1}, {'capabilities': 16},
                       {'effective_protection': 3}]:
            with self.subTest(fields=fields), self.assertRaises(WIRE.ProtocolError):
                WIRE.response(original_response(**fields))

    def test_write_address_requires_complete_writing_window(self):
        fields = dict(owner_pid=17, allocation_id=1, generation=1, extent_size=4096,
                      allocation_class=1, ec_role=2, lifecycle_state=2,
                      effective_protection=1, write_epoch=1, executor_id=1,
                      private_write_base=4096)
        self.assertEqual(WIRE.response(original_response(**fields))['private_write_base'], 4096)
        for field in ['write_epoch', 'generation', 'executor_id', 'extent_size']:
            damaged = dict(fields); damaged[field] = 0
            with self.subTest(field=field), self.assertRaises(WIRE.ProtocolError):
                WIRE.response(original_response(**damaged))

    def test_standalone_native_publication_does_not_claim_ec(self):
        facts = dict(state='published_rx', effective_protection='rx', pages_observed=2,
                     cache_primitive_performed=True, checked_ec=False, ec_registered=False,
                     writer_closed=True, raw_signal_handoff=False)
        self.assertEqual(WIRE.publication(facts, ec_required=False), facts)
        with self.assertRaises(WIRE.ProtocolError):
            WIRE.publication(facts, ec_required=True)
        facts['ec_registered'] = True
        with self.assertRaises(WIRE.ProtocolError):
            WIRE.publication(facts, ec_required=False)

    def test_unobserved_protection_or_cache_never_admits_owned_execution(self):
        facts = dict(state='published_rx', effective_protection='rx', pages_observed=1,
                     cache_primitive_performed=True, checked_ec=True, ec_registered=True,
                     writer_closed=True, raw_signal_handoff=False)
        for name, value in [('effective_protection', 'rw_nx'), ('pages_observed', 0),
                            ('cache_primitive_performed', False), ('writer_closed', False),
                            ('raw_signal_handoff', True), ('checked_ec', 1)]:
            damaged = dict(facts); damaged[name] = value
            with self.subTest(field=name), self.assertRaises(WIRE.ProtocolError):
                WIRE.publication(damaged, ec_required=True)
