#!/usr/bin/env python3
"""Bounded, read-only v1 contract oracle. This program never launches a runtime."""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata
from datetime import datetime, timezone, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

REPO = Path(__file__).resolve().parents[2]
SCHEMAS = REPO / 'runtime/contracts/v1'
KINDS = ('runtime_lock', 'runtime_artifact', 'game_profile', 'launch', 'failure', 'run', 'qualification')
CONTEXTS = ('research', 'fixture', 'runtime')
PURPOSES = ('inspect', 'fixture_launch', 'qualification_run', 'supported_launch', 'qualify')
BASE = 'https://pear.invalid/contracts/v1/'
JSON_LIMIT = 256 * 1024
JSON_TOTAL = 4 * 1024 * 1024
BLOB_LIMIT = 64 * 1024 * 1024
BLOB_TOTAL = 256 * 1024 * 1024
ID = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$')
SHA = re.compile(r'^[0-9a-f]{64}$')


class Rejected(Exception):
    def __init__(self, code):
        self.code = code


def require(condition, code):
    if not condition:
        raise Rejected(code)


def strict_json(data):
    require(len(data) <= JSON_LIMIT, 'json_size_limit')
    try:
        text = data.decode('utf-8', errors='strict')
    except UnicodeError:
        raise Rejected('invalid_utf8') from None
    require(not text.startswith('\ufeff'), 'invalid_json')
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            require(depth <= 32, 'json_depth_limit')
        elif char in ']}':
            depth -= 1
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_key')
            result[key] = value
        return result
    def number(value):
        raise Rejected('unsupported_number')
    def integer(value):
        require(len(value) <= 17, 'unsupported_number')
        result = int(value)
        require(abs(result) <= 9007199254740991, 'unsupported_number')
        return result
    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=number, parse_float=number, parse_int=integer)
    except (ValueError, RecursionError):
        raise Rejected('invalid_json') from None
    count = 0
    def walk(node):
        nonlocal count
        count += 1
        require(count <= 8192, 'json_node_limit')
        if isinstance(node, str):
            require(len(node) <= 2048 and not any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in node), 'invalid_string')
        elif isinstance(node, dict):
            for key, item in node.items():
                require(len(key) <= 96, 'invalid_key')
                walk(key)
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)
    walk(value)
    return value


def relative_parts(path):
    require(isinstance(path, str) and 0 < len(path) <= 512, 'invalid_path')
    require(not any(c in path for c in ('\\', ':', '\x00', '%')) and not path.startswith(('~', '/')), 'invalid_path')
    parts = path.split('/')
    require(all(part not in ('', '.', '..') and not any(ord(c) < 32 for c in part) for part in parts), 'invalid_path')
    return parts


class SafeRoot:
    """Descriptor-relative traversal forbids symlinks, including inside the root."""
    def __init__(self, root):
        self.fd = None
        try:
            path = os.path.abspath(os.fspath(root))
            require('\x00' not in path, 'invalid_path')
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                for part in Path(path).parts[1:]:
                    nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    os.close(fd)
                    fd = nxt
                self.fd = fd
            except BaseException:
                os.close(fd)
                raise
        except (OSError, TypeError, ValueError):
            raise Rejected('unsafe_bundle_root') from None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def open_file(self, path):
        parts = relative_parts(path)
        parent = os.dup(self.fd)
        try:
            for part in parts[:-1]:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                os.close(parent)
                parent = nxt
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode), 'not_regular_file')
                return fd, info
            except BaseException:
                os.close(fd)
                raise
        except OSError:
            raise Rejected('unsafe_or_missing_path') from None
        finally:
            os.close(parent)

    def check_directory(self, path):
        # Missing future state directories are allowed; existing parts must be directories.
        parts = relative_parts(path)
        fd = os.dup(self.fd)
        try:
            for part in parts:
                try:
                    nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                except FileNotFoundError:
                    break
                os.close(fd)
                fd = nxt
        except OSError:
            raise Rejected('unsafe_or_missing_path') from None
        finally:
            os.close(fd)

    def check_mutable(self, path, immutable_inodes):
        """Bounded metadata-only scan; immutable hard-link aliases cannot be writable state."""
        fd = os.dup(self.fd)
        try:
            for part in relative_parts(path):
                try:
                    nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                except FileNotFoundError:
                    return
                os.close(fd)
                fd = nxt
            count = 0
            def inspect(directory, depth):
                nonlocal count
                require(depth <= 32, 'state_scan_limit')
                with os.scandir(directory) as entries:
                    for entry in entries:
                        count += 1
                        require(count <= 4096, 'state_scan_limit')
                        info = entry.stat(follow_symlinks=False)
                        require(not stat.S_ISLNK(info.st_mode), 'unsafe_or_missing_path')
                        require((info.st_dev, info.st_ino) not in immutable_inodes, 'immutable_path_overlap')
                        if stat.S_ISDIR(info.st_mode):
                            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                            try: inspect(child, depth + 1)
                            finally: os.close(child)
                        else:
                            require(stat.S_ISREG(info.st_mode), 'not_regular_file')
            inspect(fd, 0)
        except OSError:
            raise Rejected('unsafe_or_missing_path') from None
        finally:
            os.close(fd)

    def read(self, path, limit, total_remaining=None):
        fd, before = self.open_file(path)
        try:
            require(before.st_size <= limit, 'json_size_limit' if limit == JSON_LIMIT else 'blob_size_limit')
            if total_remaining is not None: require(before.st_size <= total_remaining, 'json_total_limit' if limit == JSON_LIMIT else 'blob_total_limit')
            digest = hashlib.sha256()
            chunks, size = [], 0
            while True:
                data = os.read(fd, min(65536, limit + 1 - size))
                if not data:
                    break
                size += len(data)
                require(size <= limit, 'json_size_limit' if limit == JSON_LIMIT else 'blob_size_limit')
                digest.update(data)
                if limit == JSON_LIMIT:
                    chunks.append(data)
            after = os.fstat(fd)
            require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and size == before.st_size, 'file_changed')
            return b''.join(chunks), digest.hexdigest(), size, (before.st_dev, before.st_ino)
        finally:
            os.close(fd)


def all_refs(node):
    if isinstance(node, dict):
        if node.get('ref_type') in ('record', 'blob'):
            yield node
        else:
            for value in node.values():
                yield from all_refs(value)
    elif isinstance(node, list):
        for value in node:
            yield from all_refs(value)


def reject_remote(uri):
    raise NoSuchResource(ref=uri)


class Schemas:
    def __init__(self):
        index = strict_json((SCHEMAS.parent / 'contract-index.json').read_bytes())
        require(index.get('registry_format_version') == 1 and index.get('contract_set') == 'pear-runtime' and index.get('status') == 'experimental' and index.get('schema_dialect') == 'https://json-schema.org/draft/2020-12/schema' and index.get('schema_implementation') == 'implemented' and index.get('validator_implementation') == 'bounded_python_oracle' and index.get('schema_path_base') == 'runtime/contracts' and index.get('schema_resolution') == 'registered_local_paths_only', 'invalid_schema_registry')
        require(index.get('reference_digest') == {'algorithm':'sha256','scope':'exact_utf8_file_bytes','self_reference':'forbidden'}, 'invalid_schema_registry')
        entries = index.get('records')
        require(type(entries) is list and len(entries) == len(KINDS) and all(type(item) is dict for item in entries), 'invalid_schema_registry')
        require({item.get('record_kind') for item in entries} == set(KINDS), 'invalid_schema_registry')
        for item in entries:
            require(type(item.get('schema_version')) is int and item['schema_version'] == 1 and item.get('schema_path') == 'v1/' + item['record_kind'].replace('_','-') + '.schema.json' and item.get('status') == 'implemented', 'invalid_schema_registry')
        require(index.get('shared_definitions') == {'schema_path':'v1/common.schema.json','status':'implemented'}, 'invalid_schema_registry')
        documents = {}
        for name in ('common',) + tuple(k.replace('_', '-') for k in KINDS):
            value = strict_json((SCHEMAS / (name + '.schema.json')).read_bytes())
            require(value.get('$id') == BASE + name + '.schema.json' and value.get('$schema') == 'https://json-schema.org/draft/2020-12/schema', 'invalid_schema_registry')
            documents[value['$id']] = value
        def inspect(node):
            if isinstance(node, dict):
                if '$ref' in node:
                    require(node['$ref'].split('#', 1)[0] in documents or node['$ref'].startswith('#'), 'remote_schema_ref')
                for value in node.values(): inspect(value)
            elif isinstance(node, list):
                for value in node: inspect(value)
        registry = Registry(retrieve=reject_remote).with_resources((uri, Resource.from_contents(value)) for uri, value in documents.items())
        resolver = registry.resolver()
        def resolve_refs(node):
            if isinstance(node, dict):
                if '$ref' in node:
                    try: resolver.lookup(node['$ref'])
                    except Exception: raise Rejected('unresolved_schema_ref') from None
                for value in node.values(): resolve_refs(value)
            elif isinstance(node, list):
                for value in node: resolve_refs(value)
        self.validators = {}
        for uri, value in documents.items():
            inspect(value)
            resolve_refs(value)
            try: Draft202012Validator.check_schema(value)
            except SchemaError: raise Rejected('invalid_schema_registry') from None
            self.validators[uri] = Draft202012Validator(value, registry=registry)

    def check(self, record):
        require(isinstance(record, dict) and record.get('record_kind') in KINDS, 'unknown_record_kind')
        require(type(record.get('schema_version')) is int and record['schema_version'] == 1, 'unsupported_schema_version')
        validator = self.validators[BASE + record['record_kind'].replace('_', '-') + '.schema.json']
        require(next(validator.iter_errors(record), None) is None, 'schema_invalid')


def unique(values, code='duplicate_identity'):
    require(len(values) == len(set(values)), code)


def timestamp(value):
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise Rejected('invalid_timestamp') from None


def scope(ref, expected):
    require(ref is None or ref['digest']['scope'] in expected, 'digest_scope_mismatch')


class Bundle:
    def __init__(self, root, schemas):
        self.root, self.schemas = root, schemas
        self.records, self.hashes, self.inodes, self.blobs = {}, {}, {}, {}
        self.blob_inodes = {}
        self.record_bytes, self.blob_bytes = 0, 0
        self.visiting = set()

    def load(self, path):
        relative_parts(path)
        require(path not in self.visiting, 'reference_cycle')
        if path in self.records:
            return
        require(len(self.records) + len(self.visiting) < 128, 'record_count_limit')
        self.visiting.add(path)
        data, digest, size, inode = self.root.read(path, JSON_LIMIT, JSON_TOTAL - self.record_bytes)
        self.record_bytes += size
        require(self.record_bytes <= JSON_TOTAL, 'json_total_limit')
        record = strict_json(data)
        self.schemas.check(record)
        refs = list(all_refs(record))
        require(len(refs) <= 64, 'reference_count_limit')
        for ref in refs:
            if ref['ref_type'] == 'record':
                self.load(ref['path'])
        self.records[path], self.hashes[path], self.inodes[path] = record, digest, inode
        self.visiting.remove(path)

    def target(self, ref, kind, variant=None):
        require(ref is not None and ref['record_kind'] == kind, 'reference_kind_mismatch')
        value = self.records[ref['path']]
        require(value['record_kind'] == kind and (variant is None or value.get('variant') == variant), 'reference_kind_mismatch')
        return value

    def verify(self, context):
        unique(list(self.inodes.values()), 'record_alias')
        unique([record['record_id'] for record in self.records.values()])
        for record in self.records.values():
            require(record['record_context'] == context, 'context_mismatch')
            for ref in all_refs(record):
                if ref['ref_type'] == 'record':
                    value = self.records[ref['path']]
                    require(value['record_kind'] == ref['record_kind'] and value['schema_version'] == ref['schema_version'], 'reference_kind_mismatch')
                    require(self.hashes[ref['path']] == ref['digest']['value'], 'digest_mismatch')
                else:
                    path = ref['path']
                    if path not in self.blobs:
                        _, digest, size, inode = self.root.read(path, BLOB_LIMIT, BLOB_TOTAL - self.blob_bytes)
                        self.blob_bytes += size
                        require(self.blob_bytes <= BLOB_TOTAL, 'blob_total_limit')
                        require(inode not in self.inodes.values(), 'record_as_blob')
                        self.blobs[path] = digest
                        self.blob_inodes[path] = inode
                    require(self.blobs[path] == ref['digest']['value'], 'digest_mismatch')
        for record in self.records.values():
            self.semantic(record)

    def semantic(self, record):
        kind = record['record_kind']
        disclosure = record['disclosure']
        unique(disclosure['withheld'])
        require(disclosure['mode'] != 'full' or not disclosure['withheld'], 'disclosure_inconsistent')
        require(disclosure['mode'] != 'public_partial' or (disclosure['withheld'] and disclosure['origin_token'] is not None), 'disclosure_inconsistent')
        if kind == 'runtime_lock':
            scope(record['source_inventory_ref'], ['source_inventory_json_bytes'])
            components = record['components']
            ids = {c['component_id'] for c in components}
            unique([c['component_id'] for c in components])
            toolchains = {t['toolchain_id'] for t in record['toolchains']}
            unique([t['toolchain_id'] for t in record['toolchains']])
            for field in ('compatibility_family', 'host_requirements', 'signing_requirements'):
                require((record[field]['status'] == 'known') == (record[field]['value'] is not None), 'knowledge_inconsistent')
            require(not record['component_coverage']['complete'] or record['component_coverage']['status'] == 'known', 'knowledge_inconsistent')
            edges = {}
            for component in components:
                source = component['source']
                require(source['status'] != 'known' or all(source[k] is not None for k in ('url', 'immutable_ref', 'content')), 'knowledge_inconsistent')
                for field in ('source', 'dependencies', 'patches', 'build_context', 'terms'):
                    require(component[field]['status'] != 'unknown' or bool(component[field]['reason']), 'knowledge_inconsistent')
                for immutable in [source['immutable_ref']] + [p['base_ref'] for p in component['patches']['items']]:
                    if immutable:
                        if immutable['kind'] == 'git_commit':
                            length = {'sha1': 40, 'sha256': 64}.get(immutable['object_format'])
                            require(length is not None and isinstance(immutable['value'], str) and len(immutable['value']) == length, 'immutable_ref_invalid')
                        else:
                            require(immutable['object_format'] is None and immutable['value'] is None, 'immutable_ref_invalid')
                if source['content']:
                    scope(source['content'], ['git_tree_listing_bytes'] if source['immutable_ref'] and source['immutable_ref']['kind'] == 'git_commit' else ['source_archive_bytes'])
                for target in component['build_context']['targets']:
                    require((target['role'] in ('host', 'build') and target['format'] in ('mach_o', 'fixture') and target['architecture'] in ('arm64', 'x86_64')) or (target['role'] == 'guest' and target['format'] in ('pe', 'fixture') and target['architecture'] in ('x86_64', 'i386', 'arm64ec')), 'target_inconsistent')
                scope(component['build_context']['configuration'], ['build_configuration_bytes'])
                for patch in component['patches']['items']: scope(patch['content'], ['patch_file_bytes'])
                deps = component['dependencies']['component_ids']
                unique(deps)
                require(set(deps) <= ids, 'unknown_component')
                require(set(component['build_context']['toolchain_ids']) <= toolchains, 'unknown_toolchain')
                edges[component['component_id']] = deps
            def visit(node, active, done):
                require(node not in active, 'component_cycle')
                if node in done: return
                for child in edges[node]: visit(child, active | {node}, done)
                done.add(node)
            done = set()
            for node in edges: visit(node, set(), done)
        elif kind == 'runtime_artifact':
            lock = self.target(record['lock'], 'runtime_lock')
            unique([f['file_id'] for f in record['files']])
            unique([f['content']['path'] for f in record['files']])
            require(record['translator_component'] in {c['component_id'] for c in lock['components']}, 'unknown_component')
            require(lock['compatibility_family']['value'] in (None, record['compatibility_family']), 'incompatible_family')
            for file in record['files']:
                scope(file['content'], ['file_bytes'])
                require((file['role'] == 'host' and file['format'] in ('mach_o', 'fixture') and file['architecture'] in ('arm64', 'x86_64', 'unknown')) or (file['role'] == 'guest' and file['format'] in ('pe', 'fixture') and file['architecture'] in ('x86_64', 'i386', 'arm64ec')) or (file['role'] == 'data' and file['format'] == 'data' and file['architecture'] == 'none'), 'target_inconsistent')
            signing = record['signing']
            scope(signing['evidence'], ['evidence_json_bytes'])
            unique(signing['payload_digests'])
            require(signing['status'] != 'passed' or (set(signing['payload_digests']) == {f['content']['digest']['value'] for f in record['files']} and signing['evidence'] is not None), 'signing_payload_mismatch')
        elif kind == 'game_profile':
            relative_parts(record['executable']['path'])
            unique([v['key'] for v in record['environment']])
            unique(record['required_checks'])
            unique(record['required_processes'])
            for operation in record['operations']:
                relative_parts(operation['path'])
                require((operation['key'] == 'fixture_flag' and type(operation['value']) is bool) or (operation['key'] == 'dxmt_log_level' and type(operation['value']) is int and 0 <= operation['value'] <= 5), 'invalid_operation')
            for save in record['save_paths']: relative_parts(save['path'])
            if disclosure['mode'] == 'public_partial':
                require(not record['arguments'] and not record['environment'] and not record['save_paths'], 'private_fields_in_public')
        elif kind == 'launch' and record['variant'] == 'request':
            paths = [tuple(relative_parts(path)) for path in record['roots'].values()]
            for index, left in enumerate(paths):
                for right in paths[index + 1:]:
                    require(left[:len(right)] != right and right[:len(left)] != left, 'overlapping_roots')
            for path in record['roots'].values(): self.root.check_directory(path)
            immutable = set(self.records) | set(self.blobs)
            def folded(path): return tuple(unicodedata.normalize('NFC', part).casefold() for part in relative_parts(path))
            for name, path in record['roots'].items():
                if name == 'runtime': continue
                candidate = folded(path)
                for item in immutable:
                    other = folded(item)
                    require(candidate[:len(other)] != other and other[:len(candidate)] != candidate, 'immutable_path_overlap')
                self.root.check_mutable(path, set(self.inodes.values()) | set(self.blob_inodes.values()))
            for field, kind2 in (('lock', 'runtime_lock'), ('artifact', 'runtime_artifact'), ('profile', 'game_profile'), ('qualification', 'qualification')):
                if record[field]: self.target(record[field], kind2)
            if all(record[k] for k in ('lock', 'artifact', 'profile')):
                lock, artifact, profile = [self.records[record[k]['path']] for k in ('lock', 'artifact', 'profile')]
                require(artifact['lock']['digest'] == record['lock']['digest'], 'lock_mismatch')
                family = artifact['compatibility_family']
                require(profile['compatibility_family'] == family and record['prefix_family'] in (None, family), 'incompatible_family')
                cache = record['cache_identity']
                require(all(cache[k + '_digest'] == record[k]['digest']['value'] for k in ('lock', 'artifact', 'profile')) and cache['abi'] == artifact['abi'] and cache['translator_component'] == artifact['translator_component'], 'cache_identity_mismatch')
                require(set(cache['cpu_features']) == set(record['configuration']['host']['capabilities']), 'cache_identity_mismatch')
                require(record['entry_file_id'] in {f['file_id'] for f in artifact['files'] if f['role'] == 'host'}, 'invalid_entry_file')
                require(record['configuration']['renderer'] == profile['renderer'] and record['configuration']['translator'] == artifact['translator_component'] and record['configuration']['game_build'] == profile['game_build'], 'configuration_mismatch')
        elif kind == 'launch':
            request = self.target(record['request'], 'launch', 'request')
            require(record['run_id'] == request['run_id'], 'run_identity_mismatch')
            require((record['producer'] == 'observer' and record['event'] in ('observer_ready', 'observer_complete', 'gap') and record['process'] is None) or (record['producer'] == 'supervisor' and record['event'] in ('spawned', 'exited', 'gap') and (record['event'] == 'gap' or record['process'] is not None)), 'event_ownership')
            if record['ready_ack']:
                ready = self.target(record['ready_ack'], 'launch', 'event')
                require(record['event'] == 'spawned' and ready['event'] == 'observer_ready' and ready['request']['digest'] == record['request']['digest'], 'invalid_ready_ack')
            for ref in record['completed_exits']:
                exited = self.target(ref, 'launch', 'event')
                require(record['event'] == 'observer_complete' and exited['event'] == 'exited' and exited['request']['digest'] == record['request']['digest'], 'invalid_completion_basis')
            unique([r['path'] for r in record['completed_exits']])
            if record['previous']:
                previous = self.target(record['previous'], 'launch', 'event')
                require(previous['producer'] == record['producer'] and previous['request']['digest'] == record['request']['digest'] and previous['sequence'] + 1 == record['sequence'] and previous['clock_id'] == record['clock_id'] and previous['elapsed_ns'] <= record['elapsed_ns'], 'event_sequence')
            else:
                require(record['sequence'] == 0, 'event_sequence')
        elif kind == 'failure':
            if record['request']:
                request = self.target(record['request'], 'launch', 'request')
                require(record['run_id'] == request['run_id'], 'run_identity_mismatch')
        elif kind == 'run':
            timestamp(record['started_at'])
            if record['request']:
                request = self.target(record['request'], 'launch', 'request')
                require(record['run_id'] == request['run_id'] and record['configuration'] == request['configuration'], 'run_identity_mismatch')
            else:
                require(disclosure['mode'] == 'public_partial' and 'private_launch' in disclosure['withheld'], 'missing_request')
            unique([p['identity']['token'] for p in record['processes']])
            unique([(p['identity']['pid'], p['identity']['generation']) for p in record['processes']])
            for process in record['processes']:
                unique([m['module_id'] for m in process['modules']])
                for module in process['modules']:
                    for evidence in module['evidence']: scope(evidence, ['evidence_json_bytes'])
                    if module['source'] == 'artifact':
                        require(module['artifact_file_id'] is not None, 'module_identity_mismatch')
                    else:
                        require(module['artifact_file_id'] is None and module['content'] is None and ((module['source'] == 'system' and module['kind'] == 'host') or (module['source'] == 'game' and module['kind'] == 'guest')), 'module_identity_mismatch')
            unique([c['check_id'] for c in record['checks']])
            unique(record['coverage']['required_processes'])
            unique([r['path'] for r in record['events']])
            for ref in record['events']:
                event = self.target(ref, 'launch', 'event')
                require(record['request'] is not None and event['request']['digest'] == record['request']['digest'], 'run_identity_mismatch')
            for ref in record['failures']:
                failure = self.target(ref, 'failure')
                require(failure['run_id'] == record['run_id'] and failure['request'] == record['request'], 'run_identity_mismatch')
            result = record['exit']
            require((result['kind'] == 'exited' and result['code'] is not None and result['signal'] is None) or (result['kind'] == 'signaled' and result['code'] is None and result['signal'] is not None) or (result['kind'] in ('timeout', 'unknown') and result['code'] is None and result['signal'] is None), 'exit_inconsistent')
        elif kind == 'qualification':
            timestamp(record['reviewed_at'])
            unique([r['path'] for r in record['runs']])
            unique(record['required_checks'])
            for ref in record['runs']:
                run = self.target(ref, 'run')
                require(run['configuration'] == record['configuration'], 'configuration_mismatch')

    def complete_lock(self, lock):
        return (lock['component_coverage']['complete'] and all(lock[f]['status'] == 'known' for f in ('compatibility_family', 'host_requirements', 'signing_requirements')) and bool(lock['toolchains']) and all(all(c[f]['status'] == 'known' for f in ('source', 'dependencies', 'patches', 'build_context', 'terms')) and c['build_context']['targets'] and all(t['triple'] is not None for t in c['build_context']['targets']) and c['build_context']['configuration'] is not None and c['build_context']['toolchain_ids'] and c['terms']['references'] and c['evidence'] for c in lock['components']))

    def request_codes(self, request, policy, runtime):
        codes = set()
        if any(request[k] is None for k in ('lock', 'artifact', 'profile')):
            return {'incomplete_identity'}
        lock, artifact, profile = [self.records[request[k]['path']] for k in ('lock', 'artifact', 'profile')]
        if not self.complete_lock(lock): codes.add('incomplete_identity')
        if not request['observer_required']: codes.add('observer_required')
        if request['prefix_family'] != artifact['compatibility_family']: codes.add('incompatible_family')
        if request['signing_scope'] != lock['signing_requirements']['value'] or request['signing_scope'] != artifact['signing']['scope'] or artifact['signing']['status'] != 'passed': codes.add('signing_not_qualified')
        if not artifact['build_evidence']: codes.add('missing_build_evidence')
        host = request['configuration']['host']
        expected = lock['host_requirements']['value']
        if expected is None or host['architecture'] != 'arm64' or host['os'] != expected['os'] or host['architecture'] != expected['architecture'] or host['version'] < expected['version'] or not set(expected['capabilities']) <= set(host['capabilities']): codes.add('host_requirements_unmet')
        if runtime:
            if any(t['format'] == 'fixture' for c in lock['components'] for t in c['build_context']['targets']): codes.add('fixture_not_runtime')
            if lock['source_inventory_ref'] is None: codes.add('source_inventory_required')
            if profile['store'] != 'steam' or any(f['format'] == 'fixture' for f in artifact['files']) or profile['environment'] or any(o['key'] == 'fixture_flag' for o in profile['operations']): codes.add('fixture_not_runtime')
            if any(f['role'] == 'host' and f['architecture'] != 'arm64' for f in artifact['files']): codes.add('host_not_native')
            if request['configuration']['game_build'] is None or request['configuration']['steam_build'] is None: codes.add('incomplete_identity')
            if policy is None:
                codes.add('external_policy_required')
            else:
                if any(request[k]['digest']['value'] not in policy['approved_record_digests'] for k in ('lock', 'artifact', 'profile')): codes.add('identity_not_trusted')
                if host != policy['host']: codes.add('policy_host_mismatch')
                if request['signing_scope'] not in policy['allowed_signing_scopes']: codes.add('policy_signing_mismatch')
        return codes

    def run_codes(self, run, policy, qualification):
        codes = set()
        if run['request'] is None: return {'incomplete_observation'}
        request = self.records[run['request']['path']]
        codes |= self.request_codes(request, policy, True)
        if request['purpose'] != 'qualification_run': codes.add('wrong_run_purpose')
        if request['profile'] is None: return codes | {'incomplete_identity'}
        profile = self.records[request['profile']['path']]
        needed_checks = set(profile['required_checks']) | set(policy['required_checks']) | set(qualification['required_checks'])
        checks = {c['check_id']: c for c in run['checks']}
        if any(check not in checks or checks[check]['status'] != 'passed' or not checks[check]['evidence'] for check in needed_checks): codes.add('required_check_not_passed')
        needed_processes = set(profile['required_processes']) | set(policy['required_processes']) | set(run['coverage']['required_processes'])
        coverage = run['coverage']
        if coverage['status'] != 'passed' or coverage['missing_processes'] or coverage['missing_modules'] or coverage['dropped_events'] or not needed_processes <= set(coverage['required_processes']): codes.add('incomplete_observation')
        artifact = self.records[request['artifact']['path']] if request['artifact'] else None
        artifact_files = {file['file_id']: file for file in artifact['files']} if artifact else {}
        expected_modules = {m['module_id']: m for m in policy['module_expectations']}
        processes = run['processes']
        if not needed_processes <= {p['purpose'] for p in processes if p['required'] and p['observed']}: codes.add('incomplete_observation')
        for process in processes:
            if not process['observed'] or process['translated'] is not False or process['host_architecture'] != 'arm64': codes.add('host_not_native')
            modules = process['modules']
            if not modules or any(not m['observed'] or m['observed_sha256'] is None or not m['evidence'] or (m['kind'] == 'host' and m['architecture'] != 'arm64') or (m['kind'] == 'guest' and m['architecture'] not in ('x86_64', 'i386', 'arm64ec')) for m in modules): codes.add('incomplete_module_observation')
            for module in modules:
                if module['source'] == 'artifact':
                    file = artifact_files.get(module['artifact_file_id'])
                    if file is None or module['content'] is None or module['observed_sha256'] != file['content']['digest']['value'] or module['content']['digest'] != file['content']['digest'] or module['kind'] != file['role'] or module['architecture'] != file['architecture']: codes.add('module_identity_mismatch')
                if module['module_id'] in expected_modules:
                    expectation = expected_modules[module['module_id']]
                    if any(module[field] != expectation[field] for field in ('kind', 'source', 'observed_sha256')): codes.add('module_policy_mismatch')
        for kind in ('host', 'guest'):
            present = {m['module_id'] for p in processes for m in p['modules'] if m['kind'] == kind and m['observed']}
            required_modules = set(policy['required_' + kind + '_modules'])
            if not required_modules <= present: codes.add('incomplete_module_observation')
            if not required_modules <= set(expected_modules): codes.add('module_policy_incomplete')
            if any(expected_modules[mid]['kind'] != kind for mid in required_modules & set(expected_modules)): codes.add('module_policy_mismatch')
        if run['exit'] != {'kind': 'exited', 'code': 0, 'signal': None, 'cleanup': 'passed'} or run['failures']: codes.add('run_not_passed')
        events = [self.records[r['path']] for r in run['events']]
        event_hashes = {r['digest']['value'] for r in run['events']}
        if any(e['previous'] is not None and e['previous']['digest']['value'] not in event_hashes for e in events): codes.add('event_gap')
        if len({(e['producer'], e['sequence']) for e in events}) != len(events): codes.add('event_gap')
        ready = [e for e in events if e['event'] == 'observer_ready' and e['status'] == 'passed']
        complete = [e for e in events if e['event'] == 'observer_complete' and e['status'] == 'passed']
        spawned = [e for e in events if e['event'] == 'spawned']
        exited = [e for e in events if e['event'] == 'exited']
        tokens = {p['identity']['token'] for p in processes}
        if len(ready) != 1 or len(complete) != 1 or not spawned or not exited or len({e['clock_id'] for e in events}) != 1 or any(e['event'] == 'gap' or e['status'] != 'passed' for e in events):
            codes.add('observer_lifecycle_incomplete')
        elif ready[0]['elapsed_ns'] >= min(e['elapsed_ns'] for e in spawned) or complete[0]['elapsed_ns'] <= max(e['elapsed_ns'] for e in exited) or set(complete[0]['covers']) != tokens:
            codes.add('observer_lifecycle_incomplete')
        for event in spawned:
            if event['ready_ack'] is None or event['ready_ack']['digest']['value'] not in event_hashes or len(ready) != 1 or self.records[event['ready_ack']['path']] != ready[0]: codes.add('readiness_ack_missing')
        if len(complete) == 1 and {r['digest']['value'] for r in complete[0]['completed_exits']} != {r['digest']['value'] for r in run['events'] if self.records[r['path']]['event'] == 'exited'}: codes.add('completion_basis_incomplete')
        for process in processes:
            starts = [e for e in spawned if e['process'] == process['identity']]
            stops = [e for e in exited if e['process'] == process['identity']]
            if len(starts) != 1 or len(stops) != 1 or starts[0]['elapsed_ns'] >= stops[0]['elapsed_ns']: codes.add('process_lifecycle_incomplete')
        if len(spawned) != len(processes) or len(exited) != len(processes): codes.add('process_lifecycle_incomplete')
        if timestamp(run['started_at']) > timestamp(qualification['reviewed_at']): codes.add('invalid_review_order')
        return codes

    def qualification_codes(self, qualification, policy):
        if policy is None: return {'external_policy_required'}
        codes = set()
        if qualification['decision'] != 'supported': codes.add('qualification_not_supported')
        if qualification['reviewer'] not in policy['trusted_reviewers']: codes.add('reviewer_not_trusted')
        if qualification['scope'] not in policy['allowed_signing_scopes']: codes.add('policy_signing_mismatch')
        reviewed = timestamp(qualification['reviewed_at'])
        now = datetime.now(timezone.utc)
        if reviewed > now or now - reviewed > timedelta(days=policy['max_age_days']): codes.add('qualification_expired')
        identities = set()
        for ref in qualification['runs']:
            run = self.records[ref['path']]
            if ref['digest']['value'] not in policy['approved_record_digests']: codes.add('identity_not_trusted')
            codes |= self.run_codes(run, policy, qualification)
            if run['request']:
                request = self.records[run['request']['path']]
                identities.add(tuple(request[k]['digest']['value'] if request[k] else None for k in ('lock', 'artifact', 'profile')) + (request['entry_file_id'],))
                if request['signing_scope'] != qualification['scope']: codes.add('policy_signing_mismatch')
            if now - timestamp(run['started_at']) > timedelta(days=policy['max_age_days']): codes.add('qualification_expired')
        if len(identities) != 1: codes.add('qualified_identity_mismatch')
        return codes

    def eligibility(self, entry, purpose, context, policy):
        if purpose == 'inspect': return set()
        record = self.records[entry]
        codes = set()
        if any(r['disclosure']['mode'] != 'full' for r in self.records.values()): codes.add('partial_bundle')
        if purpose == 'fixture_launch':
            if context != 'fixture': codes.add('fixture_context_required')
        elif context != 'runtime': codes.add('runtime_context_required')
        if purpose == 'qualify':
            if record['record_kind'] != 'qualification': return codes | {'wrong_entry_kind'}
            if policy is not None and self.hashes[entry] not in policy['approved_record_digests']: codes.add('identity_not_trusted')
            return codes | self.qualification_codes(record, policy)
        if record['record_kind'] != 'launch' or record.get('variant') != 'request': return codes | {'wrong_entry_kind'}
        if record['purpose'] != purpose: codes.add('purpose_mismatch')
        codes |= self.request_codes(record, policy, purpose != 'fixture_launch')
        if purpose == 'supported_launch':
            if record['qualification'] is None: return codes | {'qualification_required'}
            qualification = self.records[record['qualification']['path']]
            codes |= self.qualification_codes(qualification, policy)
            if policy is not None and record['qualification']['digest']['value'] not in policy['approved_record_digests']: codes.add('identity_not_trusted')
            if qualification['configuration'] != record['configuration'] or qualification['scope'] != record['signing_scope']: codes.add('qualified_identity_mismatch')
            for ref in qualification['runs']:
                run = self.records[ref['path']]
                old = self.records[run['request']['path']] if run['request'] else None
                if old is None or old['entry_file_id'] != record['entry_file_id'] or any(old[k] is None or record[k] is None or old[k]['digest'] != record[k]['digest'] for k in ('lock', 'artifact', 'profile')): codes.add('qualified_identity_mismatch')
        return codes


def valid_policy(policy):
    if policy is None: return
    fields = {'policy_version', 'approved_record_digests', 'trusted_reviewers', 'required_checks', 'required_processes', 'required_host_modules', 'required_guest_modules', 'module_expectations', 'host', 'allowed_signing_scopes', 'max_age_days'}
    require(type(policy) is dict and set(policy) == fields and type(policy['policy_version']) is int and policy['policy_version'] == 1, 'invalid_policy')
    require(type(policy['max_age_days']) is int and 0 <= policy['max_age_days'] <= 3650, 'invalid_policy')
    for field in fields - {'policy_version', 'host', 'max_age_days', 'module_expectations'}:
        values = policy[field]
        require(type(values) is list and len(values) <= 128 and all(type(v) is str for v in values), 'invalid_policy')
        require(len(values) == len(set(values)), 'invalid_policy')
        pattern = SHA if field == 'approved_record_digests' else ID
        require(all(pattern.fullmatch(v) for v in values), 'invalid_policy')
    require(set(policy['allowed_signing_scopes']) <= {'development', 'distribution'}, 'invalid_policy')
    expectations = policy['module_expectations']
    require(type(expectations) is list and len(expectations) <= 64, 'invalid_policy')
    for item in expectations:
        require(type(item) is dict and set(item) == {'module_id','kind','source','observed_sha256'}, 'invalid_policy')
        require(type(item['module_id']) is str and ID.fullmatch(item['module_id']) and item['kind'] in ('host','guest') and item['source'] in ('artifact','system','game') and type(item['observed_sha256']) is str and SHA.fullmatch(item['observed_sha256']), 'invalid_policy')
    unique([item['module_id'] for item in expectations], 'invalid_policy')
    host = policy['host']
    require(type(host) is dict and set(host) == {'os', 'architecture', 'version', 'capabilities'} and host['os'] == 'macos' and host['architecture'] == 'arm64', 'invalid_policy')
    require(type(host['version']) is list and len(host['version']) == 3 and all(type(v) is int and 0 <= v <= 999 for v in host['version']), 'invalid_policy')
    require(type(host['capabilities']) is list and len(host['capabilities']) <= 64 and all(type(v) is str and ID.fullmatch(v) for v in host['capabilities']), 'invalid_policy')
    unique(host['capabilities'], 'invalid_policy')


def report(valid, codes=(), count=0):
    return {'record_valid': valid, 'eligible': valid and not codes, 'outcome_codes': sorted(set(codes))[:32], 'record_count': count, 'evaluation_only': True}


def validate_bundle(bundle_root, entry, *, context='research', purpose='inspect', policy=None):
    root, bundle = None, None
    try:
        require(context in CONTEXTS and purpose in PURPOSES, 'invalid_request')
        valid_policy(policy)
        root = SafeRoot(bundle_root)
        bundle = Bundle(root, Schemas())
        bundle.load(entry)
        bundle.verify(context)
        codes = bundle.eligibility(entry, purpose, context, policy)
        return report(True, codes, len(bundle.records))
    except Rejected as error:
        return report(False, [error.code], len(bundle.records) if bundle else 0)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        # Never include exception text, paths, schema errors, arguments or private records.
        return report(False, ['validation_error'], len(bundle.records) if bundle else 0)
    finally:
        if root: root.close()


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps(report(False, ['cli_usage'])))
        raise SystemExit(2)


def main():
    parser = Arguments(description=__doc__)
    parser.add_argument('--bundle-root')
    parser.add_argument('--entry')
    parser.add_argument('--context', choices=CONTEXTS, default='research')
    parser.add_argument('--purpose', choices=PURPOSES, default='inspect')
    parser.add_argument('--policy')
    parser.add_argument('--check-schemas', action='store_true')
    parser.add_argument('--check-examples', action='store_true')
    args = parser.parse_args()
    try:
        if args.check_schemas or args.check_examples:
            if any((args.bundle_root, args.entry, args.policy)) or args.context != 'research' or args.purpose != 'inspect': parser.error('incompatible')
            Schemas()
            if args.check_examples:
                results = [validate_bundle(REPO / 'runtime/contracts/examples', 'research-lock.json'), validate_bundle(REPO / 'runtime/contracts/examples/fixture', 'records/request.json', context='fixture', purpose='fixture_launch'), validate_bundle(REPO / 'runtime/contracts/examples/fixture', 'records/qualification.json', context='fixture')]
                require(all(r['record_valid'] and r['eligible'] for r in results), 'example_invalid')
            result = report(True)
        else:
            if not args.bundle_root or not args.entry: parser.error('missing')
            policy = None
            if args.policy:
                policy_path = Path(args.policy).absolute()
                bundle_path = Path(args.bundle_root).resolve()
                require(not policy_path.resolve().is_relative_to(bundle_path), 'policy_inside_bundle')
                policy_root = SafeRoot(policy_path.parent)
                try:
                    policy = strict_json(policy_root.read(policy_path.name, JSON_LIMIT)[0])
                finally:
                    policy_root.close()
            result = validate_bundle(args.bundle_root, args.entry, context=args.context, purpose=args.purpose, policy=policy)
    except Rejected as error:
        result = report(False, [error.code])
    except (OSError, ValueError, TypeError):
        result = report(False, ['validation_error'])
    print(json.dumps(result, sort_keys=True))
    return 0 if result['eligible'] else 3 if result['record_valid'] else 1


if __name__ == '__main__':
    sys.exit(main())
