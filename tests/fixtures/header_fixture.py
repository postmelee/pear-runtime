# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Finite metadata/header/depfile evidence; no compiler or native runner."""
import copy
import hashlib
import json
from pathlib import Path

from pear_runtime import build


class SelectedFixture:
    def __init__(self, base, catalog):
        self.base = Path(base)
        self.catalog = copy.deepcopy(catalog)
        self.roots = {name: self.base / name for name in ('fex', 'wine', 'runtime', 'private')}
        self.output, self.metadata = self.base / 'output', self.base / 'metadata'
        for path in (*self.roots.values(), self.output, self.metadata):
            path.mkdir()
        self.wire = self.write(self.roots['wine'] / 'include/wine/pear_fex_memory.h', b'synthetic wire')
        self.abort = self.write(self.roots['runtime'] / 'include/PearAbortObservation.h', b'synthetic abort')
        self.phase = self.write(self.roots['private'] / 'PearPhaseSelection.h', b'synthetic phase')
        self.export = self.write(self.output / 'exports/wire/wine/pear_fex_memory.h', self.wire.read_bytes())
        self.role_paths = dict(wire=self.export, abort=self.abort, phase=self.phase)
        self.policy = dict(core=('wire', 'abort'), module=('wire', 'abort', 'phase'), memory=('wire', 'abort'))
        units = []
        for name, row in zip(('core', 'module', 'memory'), self.catalog['compile_units']):
            source = self.write(self.roots['fex'] / row['path'], ('synthetic ' + name).encode())
            ref = build.fact(source)
            row.update(sha256=ref['sha256'], size_bytes=ref['size_bytes'])
            units.append(dict(id=name, path=row['path'], sha256=ref['sha256'], size_bytes=ref['size_bytes'],
                              depfile=name + '.d', object=name + '.obj'))
        definitions = dict(fex=dict(kind='git', commit=self.catalog['source_commit']),
                           wine=dict(kind='git', commit='1' * 40), runtime=dict(kind='input'),
                           private=dict(kind='private'))
        wr, ar, pr = map(build.fact, (self.wire, self.abort, self.phase))
        self.recipe = dict(schema_version=1, name='synthetic-selected', roots=definitions, compile_units=units,
            shared_headers=[dict(owner='pear-wine', path='include/wine/pear_fex_memory.h', sha256=wr['sha256']),
                            dict(owner='pear-runtime', path='include/PearAbortObservation.h', sha256=ar['sha256'])],
            source_exports=[dict(root='wine', path='include/wine/pear_fex_memory.h',
                                 output='exports/wire/wine/pear_fex_memory.h', sha256=wr['sha256'])],
            inputs=[dict(root='runtime', path='include/PearAbortObservation.h',
                         sha256=ar['sha256'], size_bytes=ar['size_bytes'])],
            required_private_input=dict(name='PearPhaseSelection.h', required_for_original_diagnostic_configuration=True))
        self.bindings = dict(roots={name: str(path) for name, path in self.roots.items()})
        self.private = dict(schema_version=1, root=str(self.roots['private']),
                            files=[dict(path='PearPhaseSelection.h', sha256=pr['sha256'], size_bytes=pr['size_bytes'])])
        self.built = dict(scope='development_component_build', status='passed', runtime_eligible=False,
            game_qualified=False, roots={name: dict(path=str(self.roots[name]), **definition)
                                        for name, definition in definitions.items()}, commands=[], dependencies=[],
            artifacts=dict(fex_pe=build.fact(self.write(self.output / 'deployment.dll', b'synthetic unexecuted artifact'))))
        for unit, row in zip(units, self.catalog['compile_units']):
            source = self.roots['fex'] / unit['path']
            refs = [build.fact(source), *(build.fact(self.role_paths[role]) for role in self.policy[unit['id']])]
            dep = self.output / unit['depfile']
            self.write_depfile(dep, [ref['path'] for ref in refs])
            log = self.write(self.output / (unit['id'] + '.log'), b'synthetic compile observation')
            self.built['commands'].append(dict(id=unit['id'], cwd=str(self.output),
                argv=['/synthetic/compiler', *row['required_defines'], '-c', str(source), '-MF', str(dep)],
                exit_code=0, error=None, logs=dict(stdout=build.fact(log), stderr=build.fact(log))))
            self.built['dependencies'].append(dict(depfile=build.fact(dep), files=refs))
        self.refresh_metadata()
        self.bind_review()

    @staticmethod
    def write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    @staticmethod
    def write_depfile(path, paths):
        tokens = [p.replace('$', '$$').replace('\\', '\\\\').replace(' ', '\\ ') for p in paths]
        path.write_text('synthetic.obj: ' + ' '.join(tokens) + '\n')

    def json_ref(self, name, value):
        path = self.metadata / name
        build.write_json(path, value)
        return build.fact(path)

    def refresh_metadata(self):
        self.built['public_recipe'] = self.json_ref('recipe.json', self.recipe)
        self.built['bindings_manifest'] = self.json_ref('bindings.json', self.bindings)
        self.built['private_manifest'] = self.json_ref('private.json', self.private)
        self.catalog['public_recipe_sha256'] = self.built['public_recipe']['sha256']
        expanded = copy.deepcopy(self.recipe)
        expanded['inputs'].append(dict(root='private', **self.private['files'][0]))
        self.built['recipe_sha256'] = hashlib.sha256(json.dumps(expanded, sort_keys=True).encode()).hexdigest()
        self.catalog_ref = self.json_ref('catalog.json', self.catalog)

    def bind_review(self):
        build.write_json(self.output / 'build.json', self.built)
        self.build_ref = build.fact(self.output / 'build.json')
        self.entry = dict(ref=self.build_ref, recipe_sha256=self.built['recipe_sha256'],
            source_commits={name: row['commit'] for name, row in self.recipe['roots'].items() if row['kind'] == 'git'},
            recipe_review=dict(mode='expanded_dict_sha256', public_recipe_ref=self.built['public_recipe'],
                               bindings_ref=self.built['bindings_manifest'], private_manifest_ref=self.built['private_manifest']))
        self.request = dict(schema_version=1, scope='development_candidate_assembly', inputs=dict(builds=[self.entry]))
        self.runtime = dict(development_assembly=dict(builds=[self.build_ref], artifacts=self.built['artifacts'],
                                                     review_refs=[]))
        self.refresh_request()
        self.capabilities_ref = self.json_ref('capabilities.json', dict(schema_version=1,
            scope='compiled_runtime_capabilities', catalog_ref=self.catalog_ref, fex_build_ref=self.build_ref))

    def refresh_request(self):
        ref = self.json_ref('request.json', self.request)
        self.runtime['development_assembly']['review_refs'] = [ref, self.built['public_recipe'],
            self.built['bindings_manifest'], self.built['private_manifest']]
