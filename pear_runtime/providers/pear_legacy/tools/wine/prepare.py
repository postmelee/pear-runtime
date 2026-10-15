#!/usr/bin/env python3
"""Materialize verified Wine source into fresh outputs without executing source.

The caller must own the fresh output and prevent concurrent mutation of inputs
or outputs. These checks do not create an atomic snapshot of hostile storage.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import unicodedata

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (Error, REPO, decode_json, encoded, load_json, need,
                    open_relative, read_relative, record, relative, sha256)

# Reuse the audited read-only Git cache and configuration checks, not its
# global source-readiness decision or any command recorded in source data.
_spec = importlib.util.spec_from_file_location('pear_source_audit', REPO / 'tools/sources/validate_inventory.py')
_audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_audit)
MAX_MEMBERS = 100000
MAX_ARCHIVE = 2 * 1024 * 1024 * 1024
MAX_CONTENT = 2 * 1024 * 1024 * 1024
MAX_MEMBER = 128 * 1024 * 1024
GIT_TIMEOUT = 120


def _git(git, repo, *args):
    try:
        return _audit.bounded_git(git, repo, args)
    except _audit.Invalid as error:
        raise Error(error.code) from None


def validate_inputs(value, repo_root=REPO):
    """Check the exact component record against its immutable audit bytes."""
    record(value, 'wine_build_inputs')
    need(set(value) == {'schema_version', 'record_kind', 'scope', 'audit_ref', 'components',
                       'dependencies', 'unresolved_ports'}, 'input_fields')
    need(value['scope'] == 'wine_component', 'input_scope')
    reference = value['audit_ref']
    need(isinstance(reference, dict) and set(reference) == {'path', 'sha256'}, 'audit_reference')
    relative(reference['path'])
    need(isinstance(reference['sha256'], str) and re.fullmatch('[a-f0-9]{64}', reference['sha256']),
         'audit_digest')
    raw = read_relative(repo_root, reference['path'])
    need(hashlib.sha256(raw).hexdigest() == reference['sha256'], 'audit_digest_mismatch')
    audit = record(decode_json(raw), 'source_audit')
    need(isinstance(audit.get('components'), list), 'audit_components')
    selected = value['components']
    need(isinstance(selected, list) and len(selected) == 1, 'wine_component_count')
    component = selected[0]
    need(isinstance(component, dict) and set(component) == {'id', 'audit_component_id', 'commit',
                'tree', 'cache_path', 'url'}, 'component_fields')
    need(component['id'] == 'wine' and isinstance(component['audit_component_id'], str), 'component_identity')
    for field in ('commit', 'tree'):
        need(isinstance(component[field], str) and re.fullmatch('[a-f0-9]{40}', component[field]), 'git_identity')
    relative(component['cache_path'])
    matches = [row for row in audit['components'] if isinstance(row, dict)
               and row.get('component_id') == component['audit_component_id']]
    need(len(matches) == 1, 'audit_component_identity')
    selected_audit = matches[0]
    source, acquisition = selected_audit.get('source', {}), selected_audit.get('acquisition', {})
    need(isinstance(source, dict) and isinstance(acquisition, dict), 'audit_source_shape')
    need(source.get('kind') == 'git' and source.get('object_format') == 'sha1'
         and acquisition.get('status') == 'acquired', 'audit_source_kind')
    need((component['commit'], component['tree'], component['url'], component['cache_path']) ==
         (source.get('commit_object_id'), source.get('tree_object_id'), source.get('url'), acquisition.get('cache_path')),
         'audit_source_mismatch')
    need(isinstance(component['url'], str) and component['url'].startswith('https://')
         and '@' not in component['url'] and '?' not in component['url'] and '#' not in component['url'], 'source_url')
    need(isinstance(selected_audit.get('content_digests'), list)
         and len(selected_audit['content_digests']) <= 256, 'audit_listing_digest')
    digests = [row for row in selected_audit['content_digests']
               if isinstance(row, dict) and row.get('scope') == 'git_tree_listing_bytes']
    need(len(digests) == 1, 'audit_listing_digest')
    listing = digests[0]
    need(listing.get('algorithm') == 'sha256' and isinstance(listing.get('value'), str)
         and re.fullmatch('[a-f0-9]{64}', listing['value']), 'audit_listing_digest')
    relative(listing.get('cache_path'))
    for name in ('dependencies', 'unresolved_ports'):
        need(isinstance(value[name], list) and len(value[name]) <= 256
             and all(isinstance(row, dict) for row in value[name]), 'input_requirement_list')
    return {'audit': audit, 'component': component, 'audit_component': selected_audit, 'listing': listing}


def _directory(root, value):
    fd = open_relative(root, value, directory=True)
    os.close(fd)
    return Path(root).joinpath(*relative(value))


def output_path(root, value):
    need(isinstance(value, str) and re.fullmatch(r'\.build/task4/[a-z0-9][a-z0-9_-]{0,95}', value),
         'output_scope')
    path = Path(root)
    for part in relative(value):
        path /= part
        need(not path.is_symlink(), 'symlink_output')
        need(not path.exists() or path.is_dir(), 'non_directory_output')
    need(not path.exists() or not any(path.iterdir()), 'output_not_empty')
    return path


def tree_entries(data):
    need(len(data) <= 128 * 1024 * 1024 and data.endswith(b'\0'), 'tree_listing_shape')
    entries, aliases = {}, {}
    for item in data[:-1].split(b'\0'):
        try:
            metadata, path_bytes = item.split(b'\t', 1)
            mode, kind, blob = metadata.decode('ascii').split(' ')
            path = path_bytes.decode('utf-8')
        except (ValueError, UnicodeError):
            raise Error('tree_listing_shape') from None
        relative(path)
        need(mode in ('100644', '100755') and kind == 'blob', 'unsupported_tree_entry')
        need(re.fullmatch('[a-f0-9]{40}', blob), 'git_blob_identity')
        need(path not in entries and len(entries) < MAX_MEMBERS, 'duplicate_or_excess_tree_entry')
        parts = relative(path)
        for index in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:index])
            key = unicodedata.normalize('NFD', prefix).casefold()
            need(key not in aliases or aliases[key] == prefix, 'tree_path_alias')
            aliases[key] = prefix
        entries[path] = {'mode': mode, 'git_blob': blob}
    for path in entries:
        need(not any('/'.join(relative(path)[:i]) in entries for i in range(1, len(relative(path)))),
             'tree_path_conflict')
    return entries


def archive_to_file(git, repository, commit, output):
    """Stream a bounded built-in Git archive; never invoke repository scripts."""
    env = {key: value for key, value in os.environ.items() if not key.startswith(('GIT_', 'DYLD_', 'LD_'))}
    env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null', GIT_CONFIG_NOSYSTEM='1',
               GIT_TERMINAL_PROMPT='0', GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1',
               GIT_OPTIONAL_LOCKS='0', GIT_ATTR_NOSYSTEM='1', LC_ALL='C')
    argv = [git, '--no-pager', '--no-optional-locks', '-C', str(repository),
            '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'protocol.allow=never',
            '-c', 'submodule.recurse=false', '-c', 'gc.auto=0', '-c', 'tar.umask=022',
            'archive', '--format=tar', commit]
    with Path(output).open('xb') as target:
        process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        deadline, size = time.monotonic() + GIT_TIMEOUT, 0
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    need(remaining > 0, 'git_archive_timeout')
                    for key, _ in selector.select(min(remaining, .25)):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(chunk)
                        need(size <= MAX_ARCHIVE, 'git_archive_size')
                        target.write(chunk)
                need(process.wait(timeout=max(.01, deadline - time.monotonic())) == 0, 'git_archive_failed')
        except BaseException:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (PermissionError, ProcessLookupError):
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                raise Error('git_archive_cleanup_unverified') from None
            raise
        finally:
            process.stdout.close()


def extract_verified(archive_path, destination, expected):
    """Extract regular files only, then bind each file to its original Git blob."""
    destination = Path(destination)
    destination.mkdir(mode=0o755)
    found, seen, rows, total = set(), set(), [], 0
    with tarfile.open(archive_path, mode='r:') as archive:
        for index, member in enumerate(archive):
            need(index < MAX_MEMBERS * 2, 'archive_member_limit')
            name = member.name.rstrip('/') if member.isdir() else member.name
            parts = relative(name)
            need(name not in seen, 'duplicate_archive_entry')
            seen.add(name)
            need(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE), 'unsupported_archive_entry')
            need(member.mode & ~0o777 == 0 and not member.mode & 0o022, 'unsafe_archive_mode')
            path = destination.joinpath(*parts)
            if member.isdir():
                need(any(p.startswith(name + '/') for p in expected), 'unexpected_archive_directory')
                path.mkdir(parents=True, exist_ok=True, mode=0o755)
                continue
            need(name in expected and name not in found, 'unexpected_archive_file')
            need(type(member.size) is int and 0 <= member.size <= MAX_MEMBER, 'archive_member_size')
            total += member.size
            need(total <= MAX_CONTENT, 'archive_content_limit')
            desired = expected[name]
            need(bool(member.mode & 0o111) == (desired['mode'] == '100755'), 'archive_mode_mismatch')
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            blob_hash = hashlib.sha1(f'blob {member.size}\0'.encode())
            content_hash = hashlib.sha256()
            stream = archive.extractfile(member)
            need(stream is not None, 'archive_content_missing')
            with stream, path.open('xb') as target:
                remaining = member.size
                while remaining:
                    block = stream.read(min(1024 * 1024, remaining))
                    need(bool(block), 'archive_content_truncated')
                    remaining -= len(block)
                    blob_hash.update(block)
                    content_hash.update(block)
                    target.write(block)
            need(blob_hash.hexdigest() == desired['git_blob'], 'archive_blob_mismatch')
            path.chmod(0o755 if desired['mode'] == '100755' else 0o644)
            found.add(name)
            rows.append({'path': name, 'mode': desired['mode'], 'size_bytes': member.size,
                         'sha256': content_hash.hexdigest(), 'git_blob': desired['git_blob']})
    need(found == set(expected), 'archive_missing_files')
    return sorted(rows, key=lambda row: row['path']), total


def _digest_value(value, length=64):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{' + str(length) + '}', value) is not None


def _manifest_tree(rows):
    """Reconstruct the original regular-file Git tree identity from manifest rows."""
    tree = {}
    for row in rows:
        parts = relative(row['path'])
        node = tree
        for part in parts[:-1]:
            need(part not in node or isinstance(node[part], dict), 'manifest_path_conflict')
            node = node.setdefault(part, {})
        need(parts[-1] not in node, 'manifest_path_conflict')
        node[parts[-1]] = (row['mode'], row['git_blob'])
    def digest(node):
        def order(item):
            return item[0].encode('utf-8') + (b'/' if isinstance(item[1], dict) else b'')
        entries = []
        for name, child in sorted(node.items(), key=order):
            mode, value = ('40000', digest(child)) if isinstance(child, dict) else child
            entries.append(mode.encode() + b' ' + name.encode('utf-8') + b'\0' + bytes.fromhex(value))
        raw = b''.join(entries)
        return hashlib.sha1(f'tree {len(raw)}\0'.encode() + raw).hexdigest()
    return digest(tree)


def _source_entries(root):
    """Enumerate through owned directory descriptors; links and special files fail."""
    files, directories, identities = {}, set(), set()
    visits = 0
    def walk(fd, prefix):
        nonlocal visits
        for name in os.listdir(fd):
            path = '/'.join((*prefix, name))
            relative(path)
            visits += 1
            need(visits <= MAX_MEMBERS * 2, 'source_entry_limit')
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            need(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'source_entry_unsupported')
            if stat.S_ISDIR(info.st_mode):
                directories.add(path)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    opened = os.fstat(child)
                    need((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino), 'source_changed')
                    walk(child, (*prefix, name))
                finally:
                    os.close(child)
            else:
                identity = (info.st_dev, info.st_ino)
                need(identity not in identities, 'source_inode_alias')
                identities.add(identity)
                files[path] = identity
    fd = open_relative(root, 'wine', directory=True)
    try:
        walk(fd, ())
    finally:
        os.close(fd)
    return files, directories


def verify_prepared(path, expected_inputs_sha256=None):
    """Read-only verification of a prepared directory and every materialized byte.

    The caller binds the input-record digest to its reviewed selection. This
    verifies source state, not build completeness, audit approval or permission.
    As with preparation, another writer must not mutate the tree concurrently.
    """
    root = Path(path).absolute()
    need('..' not in root.parts and root.parent.name == 'task4'
         and root.parent.parent.name == '.build'
         and re.fullmatch('[a-z0-9][a-z0-9_-]{0,95}', root.name), 'prepared_directory_scope')
    repository_root = root.parents[2]
    _directory(repository_root, '.build/task4/' + root.name)
    prepared_raw = read_relative(root, 'prepared.json')
    prepared = record(decode_json(prepared_raw), 'wine_prepared_sources')
    need(set(prepared) == {'schema_version', 'record_kind', 'scope', 'inputs_ref', 'audit_ref',
                          'preparation_only', 'runtime_qualified', 'components'}, 'prepared_fields')
    need(prepared['scope'] == 'wine_component' and prepared['preparation_only'] is True
         and prepared['runtime_qualified'] is False, 'prepared_scope')
    for field in ('inputs_ref', 'audit_ref'):
        reference = prepared[field]
        need(isinstance(reference, dict) and set(reference) == {'path', 'sha256'}, 'prepared_reference')
        relative(reference['path'])
        need(_digest_value(reference['sha256']), 'prepared_reference')
    if expected_inputs_sha256 is not None:
        need(_digest_value(expected_inputs_sha256), 'expected_inputs_digest')
        need(prepared['inputs_ref']['sha256'] == expected_inputs_sha256, 'prepared_inputs_mismatch')
    input_raw = read_relative(repository_root, prepared['inputs_ref']['path'])
    need(hashlib.sha256(input_raw).hexdigest() == prepared['inputs_ref']['sha256'], 'prepared_input_bytes')
    selected = validate_inputs(decode_json(input_raw), repository_root)
    need(prepared['audit_ref'] == decode_json(input_raw)['audit_ref'], 'prepared_audit_identity')
    need(isinstance(prepared['components'], list) and len(prepared['components']) == 1,
         'prepared_component_count')
    component = prepared['components'][0]
    need(isinstance(component, dict) and set(component) == {'id', 'commit', 'tree', 'source_path',
         'tree_listing_sha256', 'archive_sha256', 'files_manifest', 'file_count', 'total_bytes'}, 'prepared_component_fields')
    need(component['id'] == 'wine' and component['source_path'] == 'wine', 'prepared_component_identity')
    need((component['commit'], component['tree'], component['tree_listing_sha256'])
         == (selected['component']['commit'], selected['component']['tree'], selected['listing']['value']),
         'prepared_selected_source')
    need(all(_digest_value(component[key], 40) for key in ('commit', 'tree'))
         and all(_digest_value(component[key]) for key in ('tree_listing_sha256', 'archive_sha256')),
         'prepared_component_digest')
    need(type(component['file_count']) is int and 0 < component['file_count'] <= MAX_MEMBERS
         and type(component['total_bytes']) is int and 0 <= component['total_bytes'] <= MAX_CONTENT,
         'prepared_content_count')
    reference = component['files_manifest']
    need(isinstance(reference, dict) and set(reference) == {'path', 'sha256'}
         and reference['path'] == 'wine-files.json' and _digest_value(reference['sha256']), 'prepared_manifest_reference')
    manifest_raw = read_relative(root, reference['path'])
    need(hashlib.sha256(manifest_raw).hexdigest() == reference['sha256'], 'prepared_manifest_digest')
    manifest = record(decode_json(manifest_raw), 'wine_source_files')
    need(set(manifest) == {'schema_version', 'record_kind', 'files'} and isinstance(manifest['files'], list)
         and len(manifest['files']) == component['file_count'], 'prepared_manifest_fields')
    rows = manifest['files']
    expected, expected_directories, total = {}, set(), 0
    for row in rows:
        need(isinstance(row, dict) and set(row) == {'path', 'mode', 'size_bytes', 'sha256', 'git_blob'},
             'prepared_file_fields')
        parts = relative(row['path'])
        need(row['path'] not in expected and row['mode'] in ('100644', '100755')
             and type(row['size_bytes']) is int and 0 <= row['size_bytes'] <= MAX_MEMBER
             and _digest_value(row['sha256']) and _digest_value(row['git_blob'], 40), 'prepared_file_identity')
        expected[row['path']] = row
        expected_directories.update('/'.join(parts[:i]) for i in range(1, len(parts)))
        total += row['size_bytes']
    need(list(expected) == sorted(expected) and total == component['total_bytes'], 'prepared_manifest_accounting')
    need(_manifest_tree(rows) == component['tree'], 'prepared_tree_identity')
    listing = b''.join((row['mode'] + ' blob ' + row['git_blob'] + '\t' + row['path']).encode('utf-8') + b'\0' for row in rows)
    need(hashlib.sha256(listing).hexdigest() == component['tree_listing_sha256'], 'prepared_listing_identity')
    actual, directories = _source_entries(root)
    need(set(actual) == set(expected) and directories == expected_directories, 'prepared_source_inventory')
    for name, row in expected.items():
        with os.fdopen(open_relative(root, 'wine/' + name), 'rb') as source:
            before = os.fstat(source.fileno())
            need((before.st_dev, before.st_ino) == actual[name], 'source_changed')
            need(stat.S_IMODE(before.st_mode) == (0o755 if row['mode'] == '100755' else 0o644),
                 'prepared_source_mode')
            need(before.st_size == row['size_bytes'], 'prepared_source_size')
            content = hashlib.sha256()
            blob = hashlib.sha1(f'blob {row["size_bytes"]}\0'.encode())
            remaining = row['size_bytes']
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                need(bool(chunk), 'prepared_source_size')
                remaining -= len(chunk)
                content.update(chunk)
                blob.update(chunk)
            need(not source.read(1), 'prepared_source_size')
            after = os.fstat(source.fileno())
            need((before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                 == (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                 'source_changed')
            need(content.hexdigest() == row['sha256'] and blob.hexdigest() == row['git_blob'],
                 'prepared_source_digest')
    need(read_relative(repository_root, prepared['inputs_ref']['path']) == input_raw, 'prepared_inputs_changed')
    need(hashlib.sha256(read_relative(repository_root, prepared['audit_ref']['path'])).hexdigest()
         == prepared['audit_ref']['sha256'], 'prepared_audit_changed')
    need(read_relative(root, 'prepared.json') == prepared_raw and read_relative(root, reference['path']) == manifest_raw,
         'prepared_metadata_changed')
    final_files, final_directories = _source_entries(root)
    need(final_files == actual and final_directories == directories, 'source_changed')
    return prepared


def prepare(inputs_path, source_cache, output_value, repo_root=REPO):
    root = Path(repo_root)
    relative(inputs_path)
    raw = read_relative(root, inputs_path)
    value = decode_json(raw)
    context = validate_inputs(value, root)
    cache = _directory(root, source_cache)
    output = output_path(root, output_value)
    need(not cache.is_relative_to(output) and not output.is_relative_to(cache), 'input_output_alias')
    git = shutil.which('git')
    need(git is not None, 'git_unavailable')
    audit = _audit.Audit(context['audit'], root, cache)
    try:
        repository = audit.validate_repo(context['component']['cache_path'])
    except (_audit.Invalid, configparser.Error, UnicodeError) as error:
        raise Error(error.code if isinstance(error, _audit.Invalid) else 'unsafe_git_config') from None
    component = context['component']
    need(_git(git, repository, 'rev-parse', '--show-object-format').strip() == b'sha1', 'git_object_format')
    need(_git(git, repository, 'cat-file', '-t', component['commit']).strip() == b'commit', 'git_commit_type')
    need(_git(git, repository, 'rev-parse', component['commit'] + '^{tree}').strip().decode() == component['tree'],
         'git_tree_mismatch')
    listing = _git(git, repository, 'ls-tree', '-r', '-z', '--full-tree', component['commit'])
    need(hashlib.sha256(listing).hexdigest() == context['listing']['value'], 'tree_listing_digest_mismatch')
    need(read_relative(cache, context['listing']['cache_path'], 128 * 1024 * 1024) == listing, 'cached_listing_mismatch')
    expected = tree_entries(listing)
    # No checkout/reset/worktree operation touches the original audit cache.
    output.mkdir(parents=True, exist_ok=True)
    archive = output / 'wine-source.tar'
    archive_to_file(git, repository, component['commit'], archive)
    rows, total = extract_verified(archive, output / 'wine', expected)
    manifest = {'schema_version': 1, 'record_kind': 'wine_source_files', 'files': rows}
    manifest_path = output / 'wine-files.json'
    with manifest_path.open('xb') as stream:
        stream.write(encoded(manifest))
    prepared = {'schema_version': 1, 'record_kind': 'wine_prepared_sources', 'scope': 'wine_component',
                'inputs_ref': {'path': inputs_path, 'sha256': hashlib.sha256(raw).hexdigest()},
                'audit_ref': value['audit_ref'], 'preparation_only': True, 'runtime_qualified': False,
                'components': [{'id': 'wine', 'commit': component['commit'], 'tree': component['tree'],
                'source_path': 'wine', 'tree_listing_sha256': hashlib.sha256(listing).hexdigest(),
                'archive_sha256': sha256(archive), 'files_manifest': {'path': 'wine-files.json', 'sha256': sha256(manifest_path)},
                'file_count': len(rows), 'total_bytes': total}]}
    # Detect changed input/audit bytes before publishing a successful preparation.
    need(read_relative(root, inputs_path) == raw, 'inputs_changed')
    need(hashlib.sha256(read_relative(root, value['audit_ref']['path'])).hexdigest() == value['audit_ref']['sha256'],
         'audit_changed')
    with (output / 'prepared.json').open('xb') as stream:
        stream.write(encoded(prepared))
    return prepared


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--source-cache', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--require-empty', required=True, action='store_true')
    args = parser.parse_args()
    try:
        result = prepare(args.inputs, args.source_cache, args.output)
        print(json.dumps({'prepared': True, 'file_count': result['components'][0]['file_count'],
                          'preparation_only': True, 'runtime_qualified': False}))
        return 0
    except (Error, OSError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(json.dumps({'prepared': False, 'error': error.code if isinstance(error, Error) else 'preparation_failed',
                          'preparation_only': True, 'runtime_qualified': False}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
