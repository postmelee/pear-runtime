"""Adapt the original fixture producer; all bytes and observations remain synthetic."""
import json
from fixture_factory import build_fixture, encoded, rewrite
from validate import all_refs


def upgrade_fixture(root, fixture):
    for path in fixture['paths'].values():
        value = json.loads((root / path).read_bytes())
        value['schema_version'] = 2
        for ref in all_refs(value):
            if ref['ref_type'] == 'record': ref['schema_version'] = 2
        if value['record_kind'] == 'game_profile':
            value.update(save_inventory_status={'status':'known', 'reason':'Self-owned fixture inventory only.'},
                         path_observations=[], provenance=[], features=[])
        (root / path).write_bytes(encoded(value))
    for ref in fixture['refs'].values(): ref['schema_version'] = 2
    rewrite(root, fixture, 'profile', lambda value: None)
    return fixture


def build_v2_fixture(root, context='fixture'):
    return upgrade_fixture(root, build_fixture(root, context))
