# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Original D36 parser order/ownership and game-only canonical FEX source closure."""
from pathlib import Path
import tempfile
import importlib
import sys
import unittest
from unittest.mock import Mock,patch
from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import game_operation,producers

ROOT=Path(__file__).resolve().parents[2]


class IsolatedObservationImport:
    def setUp(self):
        super().setUp()
        before=dict(sys.modules)
        package=sys.modules['pear_runtime.fixtures']
        prior=getattr(package,'game_observations',None)
        def restore():
            for name in tuple(sys.modules):
                if name not in before and (name=='Pear' or name.startswith('Pear.') or name=='pear_runtime.fixtures.game_observations'):
                    del sys.modules[name]
            if prior is None:package.__dict__.pop('game_observations',None)
            else:package.game_observations=prior
        self.addCleanup(restore)
        self.subject=importlib.import_module('pear_runtime.fixtures.game_observations')
        self.fex=Path(self.subject.attach_observation.__file__).resolve().parents[2]


class ObservationTests(IsolatedObservationImport,unittest.TestCase):
    def setUp(self):
        super().setUp()
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        (self.root/'run').mkdir();(self.root/'run/loader.stderr.log').write_bytes(b'synthetic diagnostic log')
        build.write_json(self.root/'case.json',dict(outcome='image_refused',error=None,
            processes={'loader':{'identity':{'pid':12}},'server':{'identity':{'pid':13}}},
            registrations=[{'identity':{'pid':14}}],play_handoff=None))

    def test_original_three_assessors_receive_same_owned_identity_set_in_order(self):
        order=[]
        def check(name):
            def assess(raw,owned):
                self.assertEqual(raw,b'synthetic diagnostic log');self.assertEqual(owned,{12,13,14});order.append(name);return {'records':0}
            return assess
        with patch.object(self.subject.attach_observation,'assess',side_effect=check('attach')),\
             patch.object(self.subject.binding_census_observation,'assess',side_effect=check('binding')),\
             patch.object(self.subject.slot_lifetime_observation,'assess',side_effect=check('slot')):
            result=self.subject.observe(self.root)
        self.assertEqual(order,['attach','binding','slot']);self.assertEqual(result['status'],'assessed')
        self.assertEqual(result['owner_outcome'],'image_refused');self.assertFalse(result['game_qualified'])

    def test_original_parser_error_is_retained_without_running_later_oracles(self):
        with patch.object(self.subject.attach_observation,'assess',side_effect=Error('attach_invalid')),\
             patch.object(self.subject.binding_census_observation,'assess') as binding:
            result=self.subject.observe(self.root)
        self.assertEqual(result['status'],'failed');self.assertEqual(result['attach_assessment_error']['message'],'attach_invalid')
        binding.assert_not_called()

    def test_log_or_case_unavailable_never_becomes_a_pass(self):
        (self.root/'run/loader.stderr.log').unlink();self.assertEqual(self.subject.observe(self.root)['status'],'unavailable')
        (self.root/'case.json').unlink();self.assertEqual(self.subject.observe(self.root)['status'],'unavailable')

    def test_original_final_assessment_and_four_play_receipts_remain_linked(self):
        (self.root/'play').mkdir()
        names=('handoff-request.json','handoff-ack.json','companion-result.json','hud-result.json')
        for name in names:build.write_json(self.root/'play'/name,{'synthetic':name})
        build.write_json(self.root/'assessment.json',{'synthetic':'assessment'})
        (self.root/'run/loader.stderr.log').unlink()
        value=self.subject.observe(self.root)
        self.assertEqual(value['status'],'unavailable')
        self.assertEqual(value['assessment_ref'],build.fact(self.root/'assessment.json'))
        self.assertEqual(value['play_receipts'],{name:build.fact(self.root/'play'/name) for name in names})

    def test_log_change_during_assessment_is_refused(self):
        def mutate(*args):
            (self.root/'run/loader.stderr.log').write_bytes(b'changed');return {}
        with patch.object(self.subject.attach_observation,'assess',return_value={}),\
             patch.object(self.subject.binding_census_observation,'assess',return_value={}),\
             patch.object(self.subject.slot_lifetime_observation,'assess',side_effect=mutate):
            with self.assertRaisesRegex(Error,'assembly_reference_changed'):self.subject.observe(self.root)


class ClosureTests(IsolatedObservationImport,unittest.TestCase):
    def test_generic_fixture_graph_requires_neither_pear_nor_fex(self):
        value=producers.manifest_for_roots({'runtime':str(ROOT)})
        self.assertEqual(set(value['roots']),{'runtime'})
        self.assertNotIn('pear_runtime/fixtures/game_observations.py',{r['path'] for r in value['files']})

    def test_game_graph_pins_selector_policy_and_only_canonical_readers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();game=root/'tools/development/game';game.mkdir(parents=True)
            for name in ('context','feedback','witness'):(game/(name+'.py')).write_text('VALUE=1\n')
            (root/'tools/development/runtime_candidate.py').write_text('VALUE=1\n')
            (game/'import-provenance.json').write_text('{}')
            value=producers.manifest_for_roots({'runtime':str(ROOT),'fex':str(self.fex),'pear':str(root)},
                entry_modules=game_operation.GAME_ENTRY_MODULES,dynamic_paths=game_operation.GAME_DYNAMIC_PATHS,scope=game_operation.SCOPE)
        rows={(r['root'],r['path']) for r in value['files']}
        self.assertIn(('pear','tools/development/runtime_candidate.py'),rows)
        self.assertIn(('pear','tools/development/game/import-provenance.json'),rows)
        for name in ('attach_observation','binding_census_observation','slot_lifetime_observation','thread_create_observation','validation'):
            self.assertIn(('fex','Pear/Diagnostics/'+name+'.py'),rows)
        self.assertIn(('runtime','pear_runtime/fixtures/game_observations.py'),rows)


if __name__=='__main__':unittest.main()
