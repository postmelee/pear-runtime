#!/usr/bin/env python3
"""Read-only v2 adapter over the preserved #3 v1 oracle; never authorizes execution.

Reuse strict parsing, SafeRoot, graph loading, all original semantic/purpose and
policy rules. The local schema registration and blob-budget loop below are narrow
version-specific adaptations of #3 validate.py, not a second validation framework.
"""
import json
import sys
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit
import validate as v1
from validate import (REPO, KINDS, CONTEXTS, PURPOSES, JSON_LIMIT, SafeRoot,
                      Rejected, require, strict_json, all_refs, unique, scope,
                      reject_remote, valid_policy, report, Arguments,
                      Draft202012Validator, SchemaError, Registry, Resource)

SCHEMAS = REPO / 'runtime/contracts/v2'
BASE = 'https://pear.invalid/contracts/v2/'
BLOB_LIMIT = 8 * 1024 ** 3
BLOB_TOTAL = 64 * 1024 ** 3

class Schemas:
    def __init__(self):
        index = strict_json((SCHEMAS / 'contract-index.json').read_bytes())
        require(index.get('registry_format_version') == 1 and index.get('contract_set') == 'pear-runtime' and index.get('status') == 'experimental' and index.get('schema_dialect') == 'https://json-schema.org/draft/2020-12/schema' and index.get('schema_implementation') == 'implemented' and index.get('validator_implementation') == 'bounded_python_oracle' and index.get('schema_path_base') == 'runtime/contracts/v2' and index.get('schema_resolution') == 'registered_local_paths_only', 'invalid_schema_registry')
        require(index.get('reference_digest') == {'algorithm':'sha256','scope':'exact_utf8_file_bytes','self_reference':'forbidden'}, 'invalid_schema_registry')
        entries = index.get('records')
        require(type(entries) is list and len(entries) == len(KINDS) and all(type(item) is dict for item in entries), 'invalid_schema_registry')
        require({item.get('record_kind') for item in entries} == set(KINDS), 'invalid_schema_registry')
        for item in entries:
            require(type(item.get('schema_version')) is int and item['schema_version'] == 2 and item.get('schema_path') == item['record_kind'].replace('_','-') + '.schema.json' and item.get('status') == 'implemented', 'invalid_schema_registry')
        require(index.get('shared_definitions') == {'schema_path':'common.schema.json','status':'implemented'}, 'invalid_schema_registry')
        require(index.get('limits') == {'json_bytes': JSON_LIMIT, 'json_total_bytes': v1.JSON_TOTAL, 'blob_bytes': BLOB_LIMIT, 'blob_total_bytes': BLOB_TOTAL}, 'invalid_schema_registry')
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
        require(type(record.get('schema_version')) is int and record['schema_version'] == 2, 'unsupported_schema_version')
        validator = self.validators[BASE + record['record_kind'].replace('_', '-') + '.schema.json']
        require(next(validator.iter_errors(record), None) is None, 'schema_invalid')


class SafeRoot(v1.SafeRoot):
    def read(self, path, limit, total_remaining=None):
        if limit != BLOB_LIMIT or total_remaining is None or total_remaining >= limit:
            return super().read(path, limit, total_remaining)
        # Constrain actual streaming too, including growth after the first fstat.
        require(total_remaining >= 0, 'blob_total_limit')
        try:
            return super().read(path, total_remaining, total_remaining)
        except Rejected as error:
            if error.code in ('json_size_limit', 'blob_size_limit', 'json_total_limit'):
                raise Rejected('blob_total_limit') from None
            raise


class Bundle(v1.Bundle):
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
        super().semantic(record)
        if record['record_kind'] != 'game_profile': return
        inventory = record['save_inventory_status']
        require(inventory['status'] != 'unknown' or not record['save_paths'], 'unknown_save_mapping')
        unique([item['feature_id'] for item in record['features']])
        for item in record['features']:
            require(item['status'] not in ('passed', 'failed') or bool(item['evidence']), 'missing_feature_evidence')
            for ref in item['evidence']: scope(ref, ['evidence_json_bytes'])
        for item in record['path_observations']:
            require((item['status'] == 'observed') == (item['path'] is not None), 'knowledge_inconsistent')
            if item['path'] is not None:
                # Canonical Windows-user-relative metadata; never resolved against a host root.
                path = item['path']['path']
                require(not any(c in path for c in ('\\', ':', '%', '~')) and
                        all(part not in ('', '.', '..') for part in path.split('/')), 'invalid_observed_path')
                require(bool(item['evidence']), 'missing_path_evidence')
            for ref in item['evidence']: scope(ref, ['evidence_json_bytes'])
        for item in record['provenance']:
            url = urlsplit(item['url'])
            require(url.scheme == 'https' and bool(url.hostname) and not url.username and
                    not url.password and not url.query and not url.fragment, 'invalid_provenance_url')
            try: date.fromisoformat(item['review_date'])
            except ValueError: raise Rejected('invalid_review_date') from None

    def request_codes(self, request, policy, runtime):
        codes = super().request_codes(request, policy, runtime)
        if request['profile']:
            profile = self.records[request['profile']['path']]
            if profile['compatibility_family'] is None or profile['renderer'] is None:
                codes.add('incomplete_profile')
        return codes

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
                results = [validate_bundle(SCHEMAS / 'examples', 'research-lock.json'), validate_bundle(SCHEMAS / 'examples/fixture', 'records/request.json', context='fixture', purpose='fixture_launch'), validate_bundle(SCHEMAS / 'examples/fixture', 'records/qualification.json', context='fixture')]
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
