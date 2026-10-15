"""Inspect and prepare local development authorization for the actual Wine host.

The bundle layout is specific to the approved native bootstrap and PE/ABI fixtures. It
preserves the installed Wine tree and does not authorize its bin/wine wrapper.
Pure profile/signature checks are reused from Issue #2; its probe bundle and
execution helpers are deliberately not reused. No function here executes Wine.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import platform
import plistlib
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
from xml.parsers.expat import ExpatError

from common import Error, REPO, encoded, load_json, need, read_relative, record, relative, sha256
from build import code_publication_policy
from toolchain import MACH_ARM64, coff_machine, inspect_closure, inspect_macho

_SPEC = importlib.util.spec_from_file_location('pear_wine_profile_checks',
                                             REPO / 'host/probe/provisioned_probe.py')
PROFILE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(PROFILE)
APP_ID, TEAM_ID = PROFILE.APP_ID, PROFILE.TEAM_ID
CROSS_KEYS = PROFILE.CROSS_KEYS
BUNDLE_ID = 'io.github.postmelee.pear.wine-loader'
BUNDLE = 'PearWineLoader.app'
PAYLOAD = BUNDLE + '/Contents/Resources/runtime'
MAIN = BUNDLE + '/Contents/MacOS/wine'
NTDLL_ALIAS = BUNDLE + '/Contents/MacOS/ntdll.so'
LOADER = 'lib/wine/aarch64-unix/wine'
NTDLL = 'lib/wine/aarch64-unix/ntdll.so'
SERVER = 'bin/wineserver'
BOOTSTRAP_HELPER = 'libexec/pear-stage2/bootstrap-native'
SENTINEL = 'libexec/pear-stage2/sentinel'
API_LAUNCH = 'libexec/pear-stage3/api-launch'
API_GUESTS = {
    'api_pe': ('libexec/pear-stage3/api-arm64.exe', 0xAA64, True),
    'abi_pe': ('libexec/pear-stage3/abi-arm64.exe', 0xAA64, True),
    'x64_control': ('libexec/pear-stage3/api-x64.exe', 0x8664, False),
    'i386_control': ('libexec/pear-stage3/api-i386.exe', 0x14C, False),
}
PAGE_WX_GUESTS = {
    'lifetime_dll': ('libexec/pear-stage3/lifetime-arm64.dll', 0xAA64, True),
    'missing_name_dll': ('libexec/pear-stage3/missing-name-arm64.dll', 0xAA64, True),
    'missing_ordinal_dll': ('libexec/pear-stage3/missing-ordinal-arm64.dll', 0xAA64, True),
}


def guest_fixtures_for(built):
    guests = dict(API_GUESTS, **(PAGE_WX_GUESTS if code_publication_policy(built) == 'page-wx' else {}))
    if built.get('fixture_suite') in ('threads-memory-exceptions', 'mac-driver'):
        guests['stage4_pe'] = ('libexec/pear-stage4/stage4-arm64.exe', 0xAA64, True)
    if built.get('fixture_suite') == 'mac-driver':
        guests['window_pe'] = ('libexec/pear-stage5/window-arm64.exe', 0xAA64, True)
        guests['window_driver_pe'] = ('lib/wine/aarch64-windows/winemac.drv', 0xAA64, True)
    return guests


AUTHORIZATION_SCOPES = {'bootstrap': 'development_native_bootstrap_pre_pe',
                        'api-abi': 'development_windows_api_abi_fixtures',
                        'threads-memory-exceptions': 'development_windows_thread_memory_exception_fixtures',
                        'mac-driver': 'development_windows_mac_driver_fixtures'}
PROVENANCE = ('host/probe/provisioned_probe.py', 'host/probe/hardened_baseline.py')
LIMIT = 2 * 1024 * 1024


def owned(path):
    """Require a canonical task-local path without any symlink ancestor."""
    path = Path(path).absolute()
    root = REPO.resolve()
    need(path.is_relative_to(root / '.build/task4'), 'outside_task_root')
    current = root
    for part in relative(path.relative_to(root).as_posix()):
        current /= part
        need(not current.is_symlink(), 'symlink_task_path')
    return path


def _write(path, value):
    path = owned(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(encoded(value))


def _build(path):
    # Lazy import permits pure authorization tests without building Wine.
    import build
    path = owned(path)
    result = build.verify_build(path)
    record(result, 'wine_build')
    need(result.get('scope') == 'wine_component' and result.get('variant') == 'arm64',
         'unsupported_signing_build')
    result = dict(result)
    manifest = build.artifact_inventory(result, path)
    result['artifacts'] = manifest['files']
    result['symlinks'] = manifest['symlinks']
    return result


def _relative_target(root, path, target):
    need(isinstance(target, str) and target and not target.startswith('/') and
         not any(c in target for c in ('\\', ':', '%')) and
         all(ord(c) >= 32 and ord(c) != 127 for c in target), 'unsafe_payload_link')
    # Existing Wine installation aliases may contain '..', but must resolve
    # inside the copied tree to an ordinary file, never an external target.
    resolved = (path.parent / target).resolve()
    need(resolved.is_relative_to(root.resolve()) and resolved.is_file(), 'escaping_payload_link')
    return resolved


def inventory(root):
    """Hash the entire owned tree, including link identities and file modes."""
    root = Path(root)
    need(root.is_dir() and not root.is_symlink(), 'invalid_payload_root')
    rows, inodes = [], set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            rel = path.relative_to(root).as_posix()
            relative(rel)
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                _relative_target(root, path, target)
                rows.append({'path': rel, 'kind': 'symlink', 'target': target})
            elif stat.S_ISDIR(info.st_mode):
                need(stat.S_IMODE(info.st_mode) & 0o7000 == 0, 'unsafe_payload_mode')
                rows.append({'path': rel, 'kind': 'directory', 'mode': stat.S_IMODE(info.st_mode)})
            else:
                need(stat.S_ISREG(info.st_mode), 'special_payload_file')
                need(stat.S_IMODE(info.st_mode) & 0o7000 == 0, 'unsafe_payload_mode')
                identity = (info.st_dev, info.st_ino)
                need(identity not in inodes, 'payload_inode_alias')
                inodes.add(identity)
                rows.append({'path': rel, 'kind': 'file', 'mode': stat.S_IMODE(info.st_mode),
                             'size_bytes': info.st_size, 'sha256': sha256(path)})
            need(len(rows) <= 100000, 'payload_inventory_limit')
    return sorted(rows, key=lambda item: item['path'])


def requirement_map(build_root, built):
    """Map actual verified outputs to the approved finite fixture responsibilities."""
    suite = built.get('fixture_suite', 'bootstrap')
    need(suite in AUTHORIZATION_SCOPES, 'signing_fixture_suite')
    policy = code_publication_policy(built)
    capacity = built.get('arena_capacity')
    need((policy == 'none' and capacity is None) or
         (policy == 'page-wx' and isinstance(capacity, dict) and capacity.get('policy') == policy
          and capacity.get('wine_execution') is False), 'signing_arena_capacity_missing')
    install = owned(built['install_root'])
    artifacts = built.get('artifacts')
    need(isinstance(artifacts, list) and 0 < len(artifacts) <= 100000, 'build_artifacts_missing')
    native, seen = [], set()
    for item in artifacts:
        name = item['path']
        relative(name)
        need(name not in seen, 'duplicate_build_artifact')
        seen.add(name)
        if item.get('kind') != 'macho':
            continue
        path = install.joinpath(*relative(name))
        need(sha256(path) == item['sha256'], 'unsigned_artifact_changed')
        info = inspect_macho(path)
        need(info['architectures'] == [MACH_ARM64], 'native_artifact_not_arm64_only')
        need(info['filetype'] in (2, 6, 8), 'unexpected_native_artifact_type')
        role = ('wine-loader' if name == LOADER else 'wine-server' if name == SERVER else
                'wine-wrapper' if name == 'bin/wine' else
                'bootstrap-helper' if name == BOOTSTRAP_HELPER else
                'sentinel' if name == SENTINEL else
                'api-launch-helper' if name == API_LAUNCH else
                'native-helper' if info['filetype'] == 2 else 'native-library')
        restricted = role == 'wine-loader'
        need((role not in ('wine-loader', 'wine-server', 'wine-wrapper', 'bootstrap-helper', 'sentinel', 'api-launch-helper')) or info['filetype'] == 2,
             'process_role_not_executable')
        closure = inspect_closure(path, install)
        for image in closure:
            need(image['architectures'] == [MACH_ARM64], 'dependency_not_arm64_only')
        native.append({'source_path': name, 'unsigned_sha256': item['sha256'], 'role': role,
                       'macho': info, 'dependency_closure': closure,
                       'execution_in_stage2': role in ('wine-loader', 'wine-server', 'bootstrap-helper', 'sentinel'),
                       'required_user_page_size': 4096 if restricted else 16384 if info['filetype'] == 2 else None,
                       'required_code_signature_page_size': 4096 if restricted else None,
                       'cross_architecture_profile_required': restricted,
                       'cross_architecture_grant_alternatives': list(CROSS_KEYS) if restricted else [],
                       'allow_jit': restricted and policy == 'page-wx', 'hardened_runtime': True,
                       'library_validation': 'enabled',
                       'entitlement_policy': ('explicit_profile_app_team_one_cross_grant_and_public_allow_jit'
                            if policy == 'page-wx' else 'explicit_profile_app_team_and_one_cross_grant')
                            if restricted else 'none',
                       'signed_path': MAIN if restricted else PAYLOAD + '/' + name})
    by_path = {item['source_path']: item for item in native}
    need({LOADER, NTDLL, SERVER, BOOTSTRAP_HELPER, SENTINEL}.issubset(by_path), 'required_native_output_missing')
    need(by_path[NTDLL]['macho']['filetype'] in (6, 8), 'ntdll_not_library')
    entrypoints = {'loader': MAIN, 'server': PAYLOAD + '/' + SERVER,
                   'ntdll': PAYLOAD + '/' + NTDLL,
                   'bootstrap_helper': PAYLOAD + '/' + BOOTSTRAP_HELPER,
                   'sentinel': PAYLOAD + '/' + SENTINEL}
    guest_fixtures = {}
    if suite in ('api-abi', 'threads-memory-exceptions', 'mac-driver'):
        need(API_LAUNCH in by_path, 'api_launch_helper_missing')
        entrypoints['api_launch'] = PAYLOAD + '/' + API_LAUNCH
        artifact_map = {row['path']: row for row in artifacts}
        for role, (name, machine, executable) in guest_fixtures_for(built).items():
            item = artifact_map.get(name)
            need(item is not None and item['kind'] == 'pe' and item['machine'] == machine and
                 sha256(install / name) == item['sha256'] and coff_machine(install / name) == machine,
                 'signing_guest_fixture_mismatch')
            entrypoints[role] = PAYLOAD + '/' + name
            guest_fixtures[role] = {'machine': machine, 'execution_permitted': executable,
                                    'source_path': name, 'sha256': item['sha256']}
    return {'schema_version': 1, 'record_kind': 'wine_signing_requirements', 'scope': 'wine_component',
            'build_ref': {'path': str(owned(build_root) / 'build.json'),
                          'sha256': sha256(owned(build_root) / 'build.json')},
            'variant': 'arm64', 'install_root': str(install), 'native_images': native,
            'proposed_bundle_identifier': BUNDLE_ID,
            'bundle_layout': {'bundle': BUNDLE, 'payload': PAYLOAD, 'main': MAIN,
                              'ntdll_alias': NTDLL_ALIAS, 'loader_source': LOADER},
            'entrypoints': entrypoints, 'fixture_suite': suite, 'code_publication_policy': policy,
            'arena_capacity': capacity,
            'authorization_scope': AUTHORIZATION_SCOPES[suite],
            'guest_fixtures': guest_fixtures,
            'required_profile_checks': ['cms_decode', 'explicit_application_match', 'unexpired',
                'current_device', 'available_development_certificate', 'single_cross_architecture_grant'],
            'authorization': 'not_assessed', 'wine_execution': False,
            'runtime_qualified': False, 'distribution_qualified': False,
            'reuse': {name: sha256(REPO / name) for name in PROVENANCE},
            'profile_setup': 'Create a dedicated explicit macOS App ID matching the proposed identifier, '
                'enable Cross-architecture Compatibility Framework, and create a Mac development profile '
                'for this device and an available Apple Development certificate. Keep the profile local.'}


def inspect(build_root, output):
    value = requirement_map(build_root, _build(build_root))
    _write(output, value)
    return value


def _native(arguments, label, events, timeout=30):
    """Bound local Apple-tool output; never record arguments or private streams."""
    need(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'native_apple_silicon_required')
    need(arguments[0] in ('/usr/bin/security', '/usr/bin/codesign', '/usr/sbin/system_profiler'),
         'unexpected_signing_tool')
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'LANG': 'C'}
    event = {'operation': label}
    events.append(event)
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, start_new_session=True)
    buffers = [bytearray(), bytearray()]
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    failed = None
    try:
        for index, pipe in enumerate((process.stdout, process.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, index)
        while selector.get_map():
            if time.monotonic() >= deadline:
                failed = 'signing_tool_timeout'
                break
            for key, _ in selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                buffers[key.data].extend(data)
                if len(buffers[key.data]) > LIMIT:
                    failed = 'signing_tool_output_limit'
                    break
            if failed:
                break
        if not failed:
            try:
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                failed = 'signing_tool_timeout'
    except BaseException:
        failed = 'signing_tool_io_failure'
        raise
    finally:
        selector.close()
        for pipe in (process.stdout, process.stderr):
            pipe.close()
        cleanup_error = None
        if process.returncode is None:
            # This direct leader has not been polled/reaped, reserving its PID.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                cleanup_error = 'signing_tool_cleanup_failed'
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cleanup_error = 'signing_tool_cleanup_failed'
        event['cleanup_failure'] = cleanup_error
        event.update(exit_code=process.returncode, stdout_bytes=len(buffers[0]),
                     stderr_bytes=len(buffers[1]), failure=failed)
    need(cleanup_error is None, cleanup_error or 'signing_tool_cleanup_failed')
    need(failed is None, failed or 'signing_tool_failure')
    need(process.returncode == 0, 'signing_tool_failed')
    return bytes(buffers[0]), bytes(buffers[1])


def profile_authorization(profile, identities, device, bundle_id, now=None):
    """Reuse #2's actual profile match; omit its probe-only JIT entitlement."""
    need(bundle_id == BUNDLE_ID, 'wine_application_identifier_mismatch')
    try:
        result = PROFILE.validate_profile(profile, identities, device, bundle_id, now=now)
    except PROFILE.ControlError as error:
        raise Error(error.code) from None
    result['claims'].pop(PROFILE.BASELINE.ALLOW_JIT)
    need(set(result['claims']) == {APP_ID, TEAM_ID, result['granted_cross_architecture_key']},
         'unexpected_authorized_claims')
    return result


def loader_claims(private, policy):
    """Add the selected public JIT claim only after private profile matching."""
    need(policy in ('none', 'page-wx'), 'build_code_publication_policy')
    claims = dict(private['claims'])
    grant = private['granted_cross_architecture_key']
    need(grant in CROSS_KEYS and set(claims) == {APP_ID, TEAM_ID, grant}
         and claims[grant] is True, 'unexpected_authorized_claims')
    if policy == 'page-wx':
        claims[PROFILE.BASELINE.ALLOW_JIT] = True
    return claims


def _authorization(profile_path, bundle_id, events):
    profile_path = Path(profile_path)
    data = read_relative(profile_path.parent, profile_path.name, LIMIT)
    profile_hash = hashlib.sha256(data).hexdigest()
    decoded, _ = _native(['/usr/bin/security', 'cms', '-D', '-i', str(profile_path)], 'profile.decode', events)
    need(sha256(profile_path) == profile_hash, 'profile_changed')
    try:
        profile = plistlib.loads(decoded)
    except (ValueError, TypeError, ExpatError, plistlib.InvalidFileException):
        raise Error('profile_plist_invalid') from None
    identities, _ = _native(['/usr/bin/security', 'find-identity', '-v', '-p', 'codesigning'],
                             'profile.identity_match', events)
    hardware, _ = _native(['/usr/sbin/system_profiler', '-json', 'SPHardwareDataType'],
                           'profile.device_match', events)
    from common import decode_json
    try:
        info = decode_json(hardware)['SPHardwareDataType']
        need(isinstance(info, list) and len(info) == 1 and isinstance(info[0], dict),
             'provisioning_device_unavailable')
        devices = [value for key, value in info[0].items() if 'provision' in key.casefold()]
        need(len(devices) == 1 and isinstance(devices[0], str) and devices[0], 'provisioning_device_unavailable')
        private = profile_authorization(profile, identities.decode('utf-8'), devices[0], bundle_id)
    except (UnicodeError, KeyError, TypeError):
        raise Error('profile_observation_invalid') from None
    private['profile_sha256'] = profile_hash
    private['profile_bytes'] = data
    return private


def signature_check(metadata, entitlements, claims, team):
    """Check exact claims, including zero entitlements on ordinary host code."""
    matches = re.findall(r'^CodeDirectory\b[^\r\n]*?\bflags=0x([0-9a-fA-F]+)(?:\(|\s|$)', metadata, re.M)
    need(len(matches) == 1, 'signature_flags_missing')
    flags = int(matches[0], 16)
    need(bool(flags & 0x10000) and not flags & 2, 'signature_not_hardened_signed')
    need(re.search(r'^Authority=Apple Development: [^\r\n]+$', metadata, re.M) is not None,
         'signature_wrong_category')
    need(re.findall(r'^TeamIdentifier=([^\r\n]+)$', metadata, re.M) == [team], 'signature_team_mismatch')
    try:
        actual = plistlib.loads(entitlements) if entitlements.strip() else {}
    except (ValueError, TypeError, ExpatError, plistlib.InvalidFileException):
        raise Error('entitlements_invalid') from None
    need(isinstance(actual, dict) and actual == claims and
         all(type(actual[key]) is type(value) for key, value in claims.items()), 'entitlements_unexpected')
    pages = re.findall(r'^Page size=([0-9]+)$', metadata, re.M)
    need(len(pages) == 1 and int(pages[0]) in (4096, 16384), 'signature_page_size_missing_or_unsupported')
    page_size = int(pages[0])
    if any(claims.get(key) is True for key in CROSS_KEYS):
        need(page_size == 4096, 'loader_signature_page_size_mismatch')
    return {'hardened_runtime': True, 'ad_hoc': False, 'category': 'apple_development',
            'code_directory_page_size': page_size,
            'strict_verification': True, 'claim_keys': sorted(claims), 'same_team': True}


def _signature(path, claims, team, label, events):
    _native(['/usr/bin/codesign', '--verify', '--strict', str(path)], label + '.verify', events)
    _, metadata = _native(['/usr/bin/codesign', '--display', '--verbose=4', str(path)], label + '.metadata', events)
    entitlements, _ = _native(['/usr/bin/codesign', '--display', '--entitlements', ':-', str(path)],
                               label + '.claims', events)
    try:
        return signature_check(metadata.decode('utf-8'), entitlements, claims, team)
    except UnicodeError:
        raise Error('signature_metadata_invalid') from None


def _code_parts(path):
    """Describe only the Mach-O fields codesign is permitted to replace."""
    path = Path(path)
    need(path.stat().st_size <= 512 * 1024 * 1024, 'signed_code_size_limit')
    data = read_relative(path.parent, path.name, 512 * 1024 * 1024)
    need(len(data) >= 32, 'signed_code_truncated')
    header = struct.unpack_from('<8I', data)
    need(header[0] == 0xfeedfacf and header[1] == MACH_ARM64, 'signed_code_not_arm64')
    count, end = header[4], 32 + header[5]
    need(count <= 65536 and end <= len(data), 'signed_code_commands_invalid')
    commands, signature, linkedit = [], None, None
    at = 32
    for _ in range(count):
        need(at + 8 <= end, 'signed_code_commands_invalid')
        command, size = struct.unpack_from('<II', data, at)
        need(size >= 8 and size % 4 == 0 and at + size <= end, 'signed_code_commands_invalid')
        chunk = bytearray(data[at:at + size])
        if command == 0x1d:  # LC_CODE_SIGNATURE is replaced, never executable content.
            need(signature is None and size == 16, 'signed_code_signature_command_invalid')
            offset, length = struct.unpack_from('<II', data, at + 8)
            need(offset >= end and length > 0 and offset + length == len(data),
                 'signed_code_signature_range_invalid')
            signature = (offset, length)
        else:
            if command == 0x19 and chunk[8:24].rstrip(b'\0') == b'__LINKEDIT':
                need(size >= 72 and linkedit is None, 'signed_code_linkedit_invalid')
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<4Q', chunk, 24)
                need(fileoff + filesize <= len(data), 'signed_code_linkedit_invalid')
                linkedit = (vmsize, fileoff, filesize)
                # Codesign may resize the signature's containing file segment.
                struct.pack_into('<Q', chunk, 32, 0)
                struct.pack_into('<Q', chunk, 48, 0)
            commands.append(bytes(chunk))
        at += size
    need(at == end, 'signed_code_commands_invalid')
    return {'data': data, 'header': header[:4] + header[6:], 'commands': commands,
            'command_end': end, 'signature': signature, 'linkedit': linkedit}


def verify_code_origin(unsigned, signed):
    """Reject executable/data substitutions even when a receipt is rehashed."""
    before, after = _code_parts(unsigned), _code_parts(signed)
    need(before['header'] == after['header'] and before['commands'] == after['commands'],
         'signed_code_origin_mismatch')
    old, new = before['data'], after['data']
    start = max(before['command_end'], after['command_end'])
    if before['command_end'] < start:
        need(not any(old[before['command_end']:start]), 'signing_overwrote_load_padding')
    if after['command_end'] < start:
        need(not any(new[after['command_end']:start]), 'signing_removed_load_padding')
    old_end = before['signature'][0] if before['signature'] else len(old)
    new_end = after['signature'][0] if after['signature'] else len(new)
    old_body, new_body = old[start:old_end], new[start:new_end]
    need(new_body.startswith(old_body) and len(new_body) - len(old_body) < 16 and
         not any(new_body[len(old_body):]) and
         (before['signature'] is None or old_end == new_end), 'signed_code_origin_mismatch')
    if before['linkedit'] or after['linkedit']:
        need(before['linkedit'] is not None and after['linkedit'] is not None, 'signed_code_linkedit_changed')
        old_vm, old_off, old_size = before['linkedit']
        new_vm, new_off, new_size = after['linkedit']
        need(old_off == new_off and new_size - old_size == len(new) - len(old),
             'signed_code_linkedit_changed')
        allowed_vm = {old_vm, new_size, (new_size + 4095) & ~4095, (new_size + 16383) & ~16383}
        need(new_vm in allowed_vm and new_vm >= new_size, 'signed_code_linkedit_changed')


def verify_payload_origins(install, output, requirements):
    """Rebind copied content to the verified unsigned installation."""
    source = {row['path']: row for row in inventory(install)}
    native = {row['source_path']: row for row in requirements['native_images']}
    payload = output / PAYLOAD
    observed = set()
    for directory, dirs, files in os.walk(payload, followlinks=False):
        observed.update((Path(directory) / name).relative_to(payload).as_posix() for name in dirs + files)
    need(observed == set(source), 'signed_payload_inventory_changed')
    for name, row in source.items():
        path = payload.joinpath(*relative(name))
        if name == LOADER:
            need(path.is_symlink() and os.readlink(path) == os.path.relpath(output / MAIN, path.parent),
                 'signed_loader_alias_changed')
            path = output / MAIN
        if name in native:
            need(not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == row['mode'],
                 'signed_native_mode_changed')
            verify_code_origin(Path(install) / name, path)
        elif row['kind'] == 'file':
            need(not path.is_symlink() and sha256(path) == row['sha256'] and
                 stat.S_IMODE(path.stat().st_mode) == row['mode'], 'signed_data_origin_changed')
        elif row['kind'] == 'directory':
            need(path.is_dir() and not path.is_symlink() and
                 stat.S_IMODE(path.stat().st_mode) == row['mode'], 'signed_directory_changed')
        else:
            need(path.is_symlink() and os.readlink(path) == row['target'], 'signed_alias_changed')
    alias = output / NTDLL_ALIAS
    need(alias.is_symlink() and os.readlink(alias) == os.path.relpath(payload / NTDLL, alias.parent),
         'signed_ntdll_alias_changed')


def _copy_payload(install, output):
    before = inventory(install)
    payload = output / PAYLOAD
    payload.parent.mkdir(parents=True)
    shutil.copytree(install, payload, symlinks=True)
    need(inventory(payload) == before, 'payload_copy_mismatch')
    main = output / MAIN
    main.parent.mkdir(parents=True)
    shutil.move(payload / LOADER, main)
    (payload / LOADER).symlink_to(os.path.relpath(main, (payload / LOADER).parent))
    alias = output / NTDLL_ALIAS
    alias.symlink_to(os.path.relpath(payload / NTDLL, alias.parent))
    # The links are permitted only inside this new app, never into the build.
    _relative_target(output / BUNDLE, payload / LOADER, os.readlink(payload / LOADER))
    _relative_target(output / BUNDLE, alias, os.readlink(alias))
    need(inventory(install) == before, 'unsigned_install_changed')
    return before


def _local_input(path):
    path = owned(path)
    need(path.is_relative_to(REPO / '.build/task4/private'), 'local_signing_input_not_private')
    value = record(load_json(path), 'wine_local_signing')
    need(set(value) == {'schema_version', 'record_kind', 'scope', 'profile_path', 'bundle_identifier'} and
         value['scope'] == 'wine_component', 'local_signing_input_shape')
    profile = Path(value['profile_path'])
    need(profile.is_absolute() and not profile.is_symlink() and profile.is_file(), 'profile_reference_invalid')
    need(value['bundle_identifier'] == BUNDLE_ID, 'wine_application_identifier_mismatch')
    return value


def prepare(build_root, local_input, output, require_empty=True):
    need(require_empty, 'require_empty_needed')
    output = owned(output)
    need(not output.exists() and not output.is_symlink(), 'destination_exists')
    built = _build(build_root)
    requirements = requirement_map(build_root, built)
    local = _local_input(local_input)
    events = []
    private = _authorization(local['profile_path'], local['bundle_identifier'], events)
    claims = loader_claims(private, requirements['code_publication_policy'])
    # No task output or signing mutation exists until actual profile matching passes.
    output.mkdir(parents=True, mode=0o700)
    report = {'schema_version': 1, 'record_kind': 'wine_signed_runtime', 'scope': 'wine_component',
              'status': 'failed', 'authorization_scope': requirements['authorization_scope'],
              'code_publication_policy': requirements['code_publication_policy'],
              'arena_capacity': requirements['arena_capacity'],
              'build_ref': requirements['build_ref'], 'entrypoints': requirements['entrypoints'],
              'bundle': BUNDLE, 'profile_sha256': private['profile_sha256'],
              'profile_checks': private['checks'], 'commands': events, 'native_images': [],
              'runtime_qualified': False, 'distribution_qualified': False, 'wine_execution': False,
              'producer_sha256': {name: sha256(Path(__file__).parent / name)
                                  for name in ('signing.py', 'common.py')},
              'reuse': requirements['reuse']}
    try:
        _write(output / 'requirements.json', requirements)
        report['requirements_sha256'] = sha256(output / 'requirements.json')
        before = _copy_payload(Path(built['install_root']), output)
        contents = output / BUNDLE / 'Contents'
        (contents / 'embedded.provisionprofile').write_bytes(private['profile_bytes'])
        (contents / 'Info.plist').write_bytes(plistlib.dumps({
            'CFBundleIdentifier': BUNDLE_ID, 'CFBundleExecutable': 'wine',
            'CFBundleName': 'Pear Wine Loader', 'CFBundlePackageType': 'APPL',
            'CFBundleVersion': '1', 'CFBundleShortVersionString': '0.1',
            'LSMinimumSystemVersion': '26.5'}))
        claims_path = output / 'authorized-entitlements.plist'
        claims_path.write_bytes(plistlib.dumps(claims))
        ordinary = sorted((x for x in requirements['native_images'] if x['role'] != 'wine-loader'),
                          key=lambda x: (x['macho']['filetype'] == 2, x['source_path']))
        for index, item in enumerate(ordinary):
            path = output / item['signed_path']
            _native(['/usr/bin/codesign', '--force', '--sign', private['identity'], '--options', 'runtime',
                     '--timestamp=none', '--identifier', BUNDLE_ID + '.native.' + str(index), str(path)],
                    'native.' + str(index) + '.sign', events)
            observed = _signature(path, {}, private['claims'][TEAM_ID], 'native.' + str(index), events)
            report['native_images'].append({'path': item['signed_path'], 'source_path': item['source_path'],
                'role': item['role'], 'unsigned_sha256': item['unsigned_sha256'], 'sha256': sha256(path),
                'signature': observed})
        bundle = output / BUNDLE
        _native(['/usr/bin/codesign', '--force', '--sign', private['identity'], '--options', 'runtime',
                 '--timestamp=none', '--pagesize', '4096', '--entitlements', str(claims_path), '--identifier', BUNDLE_ID, str(bundle)],
                'loader.sign', events)
        main = output / MAIN
        main_signature = _signature(main, claims, private['claims'][TEAM_ID], 'loader', events)
        _signature(bundle, claims, private['claims'][TEAM_ID], 'bundle', events)
        original = next(x for x in requirements['native_images'] if x['role'] == 'wine-loader')
        report['native_images'].append({'path': MAIN, 'source_path': LOADER, 'role': 'wine-loader',
            'unsigned_sha256': original['unsigned_sha256'], 'sha256': sha256(main), 'signature': main_signature})
        need(sha256(contents / 'embedded.provisionprofile') == private['profile_sha256'], 'embedded_profile_changed')
        need(inventory(Path(built['install_root'])) == before, 'unsigned_install_changed')
        verify_payload_origins(Path(built['install_root']), output, requirements)
        _build(build_root)
        _write(output / 'signed-files.json', {'schema_version': 1, 'record_kind': 'wine_signed_files',
                                             'files': inventory(bundle)})
        report['files_manifest_sha256'] = sha256(output / 'signed-files.json')
        report['status'] = 'prepared'
    except (Error, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['error'] = getattr(error, 'code', 'signing_operation_failed')
        _write(output / 'signed.json', report)
        raise
    _write(output / 'signed.json', report)
    return validate_prepared(output)


def validate_prepared(runtime_root):
    """Recheck real profile, signatures and current bytes before a runner starts."""
    root = owned(runtime_root)
    report = record(load_json(root / 'signed.json'), 'wine_signed_runtime')
    need(report.get('scope') == 'wine_component' and report.get('status') == 'prepared' and
         report.get('authorization_scope') in AUTHORIZATION_SCOPES.values() and
         report.get('wine_execution') is False and report.get('runtime_qualified') is False and
         report.get('distribution_qualified') is False, 'signed_runtime_scope_invalid')
    need(report.get('producer_sha256') == {name: sha256(Path(__file__).parent / name)
          for name in ('signing.py', 'common.py')}, 'signing_producer_changed')
    ref = report['build_ref']
    build_path = owned(ref['path'])
    need(build_path.name == 'build.json' and sha256(build_path) == ref['sha256'], 'signed_build_changed')
    built = _build(build_path.parent)
    requirements = requirement_map(build_path.parent, built)
    need(sha256(root / 'requirements.json') == report['requirements_sha256'] and
         load_json(root / 'requirements.json') == requirements, 'signing_requirements_changed')
    need(report['authorization_scope'] == requirements['authorization_scope'], 'signed_fixture_scope_changed')
    need(report.get('code_publication_policy') == requirements['code_publication_policy'],
         'signed_code_publication_changed')
    need(report.get('arena_capacity') == requirements['arena_capacity'], 'signed_arena_capacity_changed')
    need(report['entrypoints'] == requirements['entrypoints'] and report['bundle'] == BUNDLE,
         'signed_entrypoint_changed')
    need(sha256(root / 'signed-files.json') == report['files_manifest_sha256'], 'signed_manifest_changed')
    files = record(load_json(root / 'signed-files.json'), 'wine_signed_files')
    need(set(files) == {'schema_version', 'record_kind', 'files'} and
         files['files'] == inventory(root / BUNDLE), 'signed_payload_changed')
    verify_payload_origins(Path(built['install_root']), root, requirements)
    events = []
    private = _authorization(root / BUNDLE / 'Contents/embedded.provisionprofile', BUNDLE_ID, events)
    need(private['profile_sha256'] == report['profile_sha256'], 'signed_profile_changed')
    expected_loader_claims = loader_claims(private, requirements['code_publication_policy'])
    info = plistlib.loads(read_relative(root, BUNDLE + '/Contents/Info.plist', LIMIT))
    need(info.get('CFBundleIdentifier') == BUNDLE_ID and info.get('CFBundleExecutable') == 'wine',
         'signed_bundle_identity_changed')
    rows = report['native_images']
    need(isinstance(rows, list) and len(rows) == len(requirements['native_images']), 'signed_native_coverage')
    by_path = {item['path']: item for item in rows}
    need(len(by_path) == len(rows), 'signed_native_duplicate')
    for index, expected in enumerate(requirements['native_images']):
        path = expected['signed_path']
        need(path in by_path, 'signed_native_coverage')
        item = by_path[path]
        need(item['role'] == expected['role'] and item['source_path'] == expected['source_path'] and
             item['unsigned_sha256'] == expected['unsigned_sha256'] and
             item['sha256'] == sha256(root / path), 'signed_native_identity_changed')
        info = inspect_macho(root / path)
        need(info == expected['macho'], 'signed_native_macho_changed')
        claims = expected_loader_claims if expected['role'] == 'wine-loader' else {}
        observed = _signature(root / path, claims, private['claims'][TEAM_ID], 'validate.' + str(index), events)
        need(observed == item['signature'], 'signed_claims_changed')
        inspect_closure(root / path, root / BUNDLE)
    _signature(root / BUNDLE, expected_loader_claims, private['claims'][TEAM_ID], 'validate.bundle', events)
    need(files['files'] == inventory(root / BUNDLE), 'signed_payload_changed')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    command = sub.add_parser('inspect')
    command.add_argument('--build', required=True)
    command.add_argument('--output', required=True)
    command = sub.add_parser('prepare')
    command.add_argument('--build', required=True)
    command.add_argument('--local-input', required=True)
    command.add_argument('--output', required=True)
    command.add_argument('--require-empty', action='store_true', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'inspect':
            inspect(args.build, args.output)
        else:
            prepare(args.build, args.local_input, args.output, args.require_empty)
        print(encoded({'schema_version': 1, 'record_kind': 'wine_signing_outcome',
                       'operation': args.command, 'status': 'completed', 'wine_execution': False}).decode(), end='')
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(encoded({'schema_version': 1, 'record_kind': 'wine_signing_outcome',
                       'operation': args.command, 'status': 'failed',
                       'error': getattr(error, 'code', 'signing_operation_failed'),
                       'wine_execution': False}).decode(), end='')
        return 1


if __name__ == '__main__':
    sys.exit(main())
