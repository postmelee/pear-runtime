# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Original pure profile/code-origin controls against the captured helper package.

Synthetic certificates/devices never establish Apple authorization. The only
adaptation is binding original tests to the explicit source-pack namespace.
"""
import copy
from datetime import datetime, timedelta, timezone
import hashlib, os, plistlib, struct, tempfile, unittest
from pathlib import Path
from pear_runtime.assembly import _common as common
from pear_runtime.assembly.helpers import SourcePack, signing_helpers
PACK = SourcePack(Path(os.environ['PEAR_ASSEMBLY_SOURCE_PACK']))
helpers, signing = signing_helpers(PACK)
signing.PROFILE.DEFAULT_BUNDLE_ID = helpers.source_constant(
    PACK.capture()['host/probe/provisioned_probe.py'], 'DEFAULT_BUNDLE_ID')

NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)
CERT = b'owned synthetic certificate; never an Apple signing identity'
FINGERPRINT = hashlib.sha1(CERT).hexdigest().upper()
TEAM = 'TESTTEAMONLY'
PREFIX = 'TESTPREFIXONLY'
DEVICE = 'SYNTHETIC-DEVICE-ONLY'
IDENTITIES = '  1) ' + FINGERPRINT + ' "Apple Development: Synthetic Fixture (' + TEAM + ')"'


def profile_fixture():
    return {'ExpirationDate': NOW + timedelta(days=365), 'Platform': ['OSX'],
            'TeamIdentifier': [TEAM], 'ApplicationIdentifierPrefix': [PREFIX],
            'Entitlements': {signing.APP_ID: PREFIX + '.' + signing.BUNDLE_ID,
                             signing.TEAM_ID: TEAM, signing.CROSS_KEYS[0]: True,
                             'com.apple.security.get-task-allow': True},
            'ProvisionedDevices': [DEVICE], 'DeveloperCertificates': [CERT]}


def private_fixture():
    result = signing.profile_authorization(profile_fixture(), IDENTITIES, DEVICE, signing.BUNDLE_ID, NOW)
    data = b'owned synthetic CMS placeholder, not a profile'
    result.update(profile_bytes=data, profile_sha256=hashlib.sha256(data).hexdigest())
    return result


def metadata(flags='10000', team=TEAM, page_size=4096):
    return ('CodeDirectory v=20500 size=512 flags=0x' + flags + '(runtime) hashes=10+7\n'
            'Authority=Apple Development: Synthetic Fixture\nTeamIdentifier=' + team + '\nPage size=' + str(page_size) + '\n')


def macho(filetype=2, cpu=signing.MACH_ARM64):
    return struct.pack('<8I', 0xfeedfacf, cpu, 0, filetype, 0, 0, 0, 0) + b'owned fixture bytes'


def signed_macho(signature=b'old synthetic signature', include_command=True, flags=0):
    command_count = 3 if include_command else 2
    command_size = 160 if include_command else 144
    end = 768 + (len(signature) if include_command else 0)
    header = struct.pack('<8I', 0xfeedfacf, signing.MACH_ARM64, 0, 2,
                         command_count, command_size, flags, 0)
    text = struct.pack('<II16s4Q4I', 0x19, 72, b'__TEXT', 0x100000000, 4096, 0, 512, 5, 5, 0, 0)
    linkedit = struct.pack('<II16s4Q4I', 0x19, 72, b'__LINKEDIT', 0x100001000, 4096,
                           512, end - 512, 1, 1, 0, 0)
    command = struct.pack('<4I', 0x1d, 16, 768, len(signature)) if include_command else b''
    data = (header + text + linkedit + command).ljust(512, b'\0')
    data += b'owned executable and symbol bytes'.ljust(256, b'\0')
    return data + (signature if include_command else b'')


class CodeOriginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.before, self.after = root / 'unsigned', root / 'signed'
        self.before.write_bytes(signed_macho())
        self.after.write_bytes(signed_macho(b'a different, longer synthetic code signature'))

    def test_signature_replacement_and_linkedit_resize_are_accepted(self):
        signing.verify_code_origin(self.before, self.after)

    def test_added_signature_command_uses_only_existing_zero_padding(self):
        self.before.write_bytes(signed_macho(include_command=False))
        signing.verify_code_origin(self.before, self.after)
        data = bytearray(self.before.read_bytes())
        data[176] = 1
        self.before.write_bytes(data)
        with self.assertRaisesRegex(common.Error, 'signing_overwrote_load_padding'):
            signing.verify_code_origin(self.before, self.after)

    def test_instruction_data_header_and_other_load_command_changes_fail(self):
        for offset in (520, 24, 32 + 24):
            data = bytearray(signed_macho(b'a different, longer synthetic code signature'))
            data[offset] ^= 1
            self.after.write_bytes(data)
            with self.subTest(offset=offset), self.assertRaisesRegex(common.Error, 'signed_code_origin_mismatch'):
                signing.verify_code_origin(self.before, self.after)

    def test_signature_range_trailing_payload_and_segment_growth_fail(self):
        original = signed_macho(b'a different, longer synthetic code signature')
        for kind in ('trailing', 'range', 'vmsize'):
            data = bytearray(original)
            if kind == 'trailing': data += b'extra'
            if kind == 'range': struct.pack_into('<I', data, 184, 512)
            if kind == 'vmsize': struct.pack_into('<Q', data, 136, 1 << 30)
            self.after.write_bytes(data)
            with self.subTest(kind=kind), self.assertRaises(common.Error):
                signing.verify_code_origin(self.before, self.after)


class ProfileTests(unittest.TestCase):
    def test_exact_wine_profile_has_no_probe_jit_or_debug_claims(self):
        value = private_fixture()
        self.assertEqual(set(value['claims']), {signing.APP_ID, signing.TEAM_ID, signing.CROSS_KEYS[0]})
        self.assertNotIn(signing.PROFILE.BASELINE.ALLOW_JIT, value['claims'])
        self.assertNotIn('get-task-allow', str(value['claims']))
        self.assertNotIn(TEAM, str(value['checks']))
        self.assertTrue(all(value['checks'].values()))

    def test_probe_identity_is_not_transferred_to_wine(self):
        profile = profile_fixture()
        profile['Entitlements'][signing.APP_ID] = PREFIX + '.' + signing.PROFILE.DEFAULT_BUNDLE_ID
        with self.assertRaisesRegex(common.Error, 'profile_application_mismatch'):
            signing.profile_authorization(profile, IDENTITIES, DEVICE, signing.BUNDLE_ID, NOW)
        with self.assertRaisesRegex(common.Error, 'wine_application_identifier_mismatch'):
            signing.profile_authorization(profile, IDENTITIES, DEVICE, signing.PROFILE.DEFAULT_BUNDLE_ID, NOW)

    def test_expired_wrong_device_certificate_or_ambiguous_grant_fails(self):
        for kind in ('expired', 'device', 'certificate', 'grant', 'integer_grant', 'wildcard'):
            profile = profile_fixture()
            identities, device = IDENTITIES, DEVICE
            if kind == 'expired': profile['ExpirationDate'] = NOW
            if kind == 'device': device = 'OTHER'
            if kind == 'certificate': identities = ''
            if kind == 'grant': profile['Entitlements'][signing.CROSS_KEYS[1]] = True
            if kind == 'integer_grant': profile['Entitlements'][signing.CROSS_KEYS[0]] = 1
            if kind == 'wildcard': profile['Entitlements'][signing.APP_ID] = PREFIX + '.*'
            with self.subTest(kind=kind), self.assertRaises(common.Error):
                signing.profile_authorization(profile, identities, device, signing.BUNDLE_ID, NOW)

    def test_loader_public_claim_does_not_mutate_or_broaden_private_authorization(self):
        private = private_fixture()
        original = copy.deepcopy(private)
        expected = dict(private['claims'], **{signing.PROFILE.BASELINE.ALLOW_JIT: True})
        self.assertEqual(signing.loader_claims(private, 'page-wx'), expected)
        self.assertEqual(signing.loader_claims(private, 'none'), private['claims'])
        self.assertEqual(private, original)
        for key in ('com.apple.security.cs.disable-library-validation',
                    'com.apple.security.cs.allow-unsigned-executable-memory',
                    signing.PROFILE.BASELINE.ALLOW_JIT):
            changed = copy.deepcopy(private)
            changed['claims'][key] = True
            with self.subTest(key=key), self.assertRaisesRegex(common.Error, 'unexpected_authorized_claims'):
                signing.loader_claims(changed, 'page-wx')
        with self.assertRaisesRegex(common.Error, 'build_code_publication_policy'):
            signing.loader_claims(private, 'rwx')

    def test_only_actual_alternative_grant_is_selected(self):
        profile = profile_fixture()
        del profile['Entitlements'][signing.CROSS_KEYS[0]]
        profile['Entitlements'][signing.CROSS_KEYS[1]] = True
        value = signing.profile_authorization(profile, IDENTITIES, DEVICE, signing.BUNDLE_ID, NOW)
        self.assertIn(signing.CROSS_KEYS[1], value['claims'])
        self.assertNotIn(signing.CROSS_KEYS[0], value['claims'])

    def test_loader_code_signature_pages_match_four_kib_layout(self):
        claims = private_fixture()['claims']
        self.assertEqual(signing.signature_check(metadata(), plistlib.dumps(claims), claims, TEAM)
                         ['code_directory_page_size'], 4096)
        with self.assertRaisesRegex(common.Error, 'loader_signature_page_size_mismatch'):
            signing.signature_check(metadata(page_size=16384), plistlib.dumps(claims), claims, TEAM)
        self.assertEqual(signing.signature_check(metadata(page_size=16384), b'', {}, TEAM)
                         ['code_directory_page_size'], 16384)
        for meta in (metadata().replace('Page size=4096\n', ''), metadata() + 'Page size=4096\n',
                     metadata(page_size=0)):
            with self.subTest(meta=meta), self.assertRaises(common.Error):
                signing.signature_check(meta, plistlib.dumps(claims), claims, TEAM)

    def test_server_and_libraries_require_zero_entitlements(self):
        self.assertEqual(signing.signature_check(metadata(), b'', {}, TEAM)['claim_keys'], [])
        for key in (*signing.CROSS_KEYS, signing.PROFILE.BASELINE.ALLOW_JIT,
                    'com.apple.security.cs.disable-library-validation',
                    'com.apple.security.cs.allow-unsigned-executable-memory'):
            with self.subTest(key=key), self.assertRaisesRegex(common.Error, 'entitlements_unexpected'):
                signing.signature_check(metadata(), plistlib.dumps({key: True}), {}, TEAM)

    def test_malformed_effective_claims_are_stable_rejections(self):
        for value in (b'not a plist', b'<?xml version="1.0"?><plist><dict><key>bad</plist>'):
            with self.subTest(value=value), self.assertRaisesRegex(common.Error, 'entitlements_invalid'):
                signing.signature_check(metadata(), value, {}, TEAM)

    def test_hardened_real_signature_and_exact_claim_types_required(self):
        claims = private_fixture()['claims']
        self.assertTrue(signing.signature_check(metadata(), plistlib.dumps(claims), claims, TEAM)['same_team'])
        for meta in (metadata('2'), metadata('0'), metadata(team='OTHER'), metadata().replace('Apple Development:', 'Developer ID Application:')):
            with self.subTest(meta=meta), self.assertRaises(common.Error):
                signing.signature_check(meta, plistlib.dumps(claims), claims, TEAM)
        changed = dict(claims, **{signing.CROSS_KEYS[0]: 1})
        with self.assertRaisesRegex(common.Error, 'entitlements_unexpected'):
            signing.signature_check(metadata(), plistlib.dumps(changed), claims, TEAM)
