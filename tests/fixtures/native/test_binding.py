# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
import struct
import unittest
from pear_runtime.errors import Error
from pear_runtime.fixtures.native.binding import pe_timestamps,compare_pe


def pe(machine=0xaa64):
    raw=bytearray(1024);raw[:2]=b'MZ';struct.pack_into('<I',raw,60,128);raw[128:132]=b'PE\0\0'
    magic=0x10b if machine==0x14c else 0x20b;size=224 if magic==0x10b else 240;dirs=96 if magic==0x10b else 112
    struct.pack_into('<HH',raw,132,machine,1);struct.pack_into('<H',raw,148,size)
    opt=152;struct.pack_into('<H',raw,opt,magic);struct.pack_into('<I',raw,opt+60,512)
    struct.pack_into('<I',raw,opt+dirs-4,16);struct.pack_into('<II',raw,opt+dirs+48,4096,28)
    section=opt+size;struct.pack_into('<4I',raw,section+8,512,4096,512,512)
    raw[600]=42;return bytes(raw)


class BindingTests(unittest.TestCase):
    def test_only_coff_and_debug_timestamps_allowed_both_pe_formats(self):
        for machine in (0xaa64,0x8664,0x14c):
            original=pe(machine);candidate=bytearray(original)
            for at in pe_timestamps(original)[1]:candidate[at:at+4]=b'1234'
            value=compare_pe(original,bytes(candidate),machine)
            self.assertTrue(value['whole_payload_equal_except_timestamps']);self.assertEqual(value['different_byte_count'],8)
    def test_executable_mutation_refused(self):
        original=pe();candidate=bytearray(original);candidate[600]^=1
        with self.assertRaisesRegex(Error,'native_pe_non_timestamp_changed'):compare_pe(original,bytes(candidate),0xaa64)
    def test_wrong_machine_refused(self):
        with self.assertRaisesRegex(Error,'native_pe_geometry'):compare_pe(pe(0x8664),pe(0x8664),0xaa64)
    def test_invalid_signature_refused(self):
        raw=bytearray(pe());struct.pack_into('<I',raw,152+112+48,100)
        raw[128:132]=b'nope'
        with self.assertRaisesRegex(Error,'native_pe_signature'):pe_timestamps(bytes(raw))
    def test_truncated_directory_refused(self):
        raw=bytearray(pe());struct.pack_into('<I',raw,152+112+48+4,27)
        with self.assertRaisesRegex(Error,'native_pe_debug_size'):pe_timestamps(bytes(raw))

if __name__=='__main__':unittest.main()
