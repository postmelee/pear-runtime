# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""New fixture admission rejects ambient/game routes before any side effect."""
from contextlib import ExitStack, contextmanager
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import direct
from pear_runtime.fixtures.context import FixtureContext, NAMES
from pear_runtime.fixtures.types import Selection


class DirectScope(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.output = self.root / 'new-fixture'
        self.candidate = Selection('d25-game', self.root / 'runtime')
        # Exact type is needed to exercise the public gate. No descriptor is
        # bypassed for execution: every case stops before context.begin.
        self.context = object.__new__(FixtureContext)
        self.context.selected = {'abort_observer': True}
        self.stack = self.enterContext(ExitStack())
        self.boundaries = {}
        for owner, name in ((FixtureContext, 'current_authority'),
                            (FixtureContext, 'fresh_output'),
                            (FixtureContext, 'begin'),
                            (direct, 'stage_modules'),
                            (direct.subprocess, 'run'),
                            (direct.shutil, 'copyfile'),
                            (direct.supervisor, 'supervision')):
            self.boundaries[name] = self.stack.enter_context(
                patch.object(owner, name, side_effect=AssertionError('unexpected '+name)))

    def refused(self, expected='direct_fixture_context_scope', **changes):
        args = dict(inputs=None, candidate=self.candidate, output=self.output,
                    fixture='tls-thread', fixture_context=self.context)
        args.update(changes)
        with self.assertRaisesRegex(Error, '^'+expected+'$'):
            direct.run(**args)
        for boundary in self.boundaries.values():
            boundary.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_missing_context_rejected_before_authority_copy_or_launch(self):
        self.refused(fixture_context=None)

    def test_lookalike_and_subclass_contexts_are_not_authority(self):
        class DerivedContext(FixtureContext):
            pass
        for context in (SimpleNamespace(selected={'abort_observer': True}),
                        object.__new__(DerivedContext)):
            with self.subTest(context_type=type(context).__name__):
                self.refused(fixture_context=context)

    def test_historical_candidate_routes_do_not_admit_runtime_execution(self):
        for name in direct.CANDIDATES:
            if name != 'd25-game':
                with self.subTest(candidate=name):
                    self.refused(candidate=Selection(name, self.candidate.runtime))

    def test_candidate_requires_the_canonical_selection_type(self):
        class DerivedSelection(Selection):
            pass
        for candidate in (SimpleNamespace(name='d25-game', runtime=self.candidate.runtime),
                          DerivedSelection('d25-game', self.candidate.runtime)):
            with self.subTest(candidate_type=type(candidate).__name__):
                self.refused(candidate=candidate)

    def test_owned_game_inputs_and_play_adapter_are_outside_fixture_scope(self):
        self.refused(inputs=self.root / 'owned-game-inputs')
        factory = Mock(side_effect=AssertionError('play adapter must not be constructed'))
        self.refused(play_adapter_factory=factory)
        factory.assert_not_called()

    def test_absent_or_external_fixture_is_rejected(self):
        for fixture in (None, 'phase-guest', 'platform-prepare-native',
                        'presentation-original', 'unlisted-fixture'):
            with self.subTest(fixture=fixture):
                self.refused(fixture=fixture)

    def test_nonfixture_sampling_and_extended_budget_are_refused(self):
        for changes, code in (({'samples': ('source-wait',)}, 'direct_event_sample_scope'),
                              ({'samples': ('source-wait-short',)}, 'direct_event_sample_scope'),
                              ({'samples': (15, 60, 90)}, 'direct_fixture_scope'),
                              ({'budget': 'd18-game300'}, 'direct_extended_budget_scope')):
            with self.subTest(changes=changes):
                self.refused(code, **changes)

    def test_invalid_observation_or_trace_is_rejected_before_staging(self):
        for changes, code in (({'observations': True}, 'direct_observations'),
                              ({'abort_observation': 'historical'}, 'abort_observation_option'),
                              ({'trace': 'platform'}, 'direct_platform_scope')):
            with self.subTest(changes=changes):
                self.refused(code, **changes)

    def test_abort_opt_in_requires_compiled_capability(self):
        for selected in ({}, {'abort_observer': False}, {'abort_observer': 1}):
            self.context.selected = selected
            with self.subTest(selected=selected):
                self.refused('abort_selected_runtime', abort_observation='on')

    def test_exact_seven_ids_reach_context_admission_without_launch(self):
        self.boundaries['fresh_output'].side_effect = None
        self.boundaries['fresh_output'].return_value = self.output
        self.boundaries['begin'].side_effect = Error('test_admission_boundary')
        for fixture in NAMES:
            with self.subTest(fixture=fixture), self.assertRaisesRegex(Error, '^test_admission_boundary$'):
                direct.run(None, self.candidate, self.output,
                           fixture=fixture, fixture_context=self.context)
        self.assertEqual(self.boundaries['begin'].call_count, 7)
        for name, boundary in self.boundaries.items():
            if name not in ('fresh_output', 'begin'):
                boundary.assert_not_called()
        self.assertFalse(self.output.exists())


class OwnedRunFailure(unittest.TestCase):
    def test_deadline_unwinds_cleanup_and_preserves_error_before_after_authority(self):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root=Path(temporary).resolve();runtime=root/'runtime';seed=root/'seed'
            output=root/'fixture';runtime.mkdir();(seed/'run/prefix').mkdir(parents=True)
            build.write_json(runtime/'runtime.json',{})
            build.write_json(seed/'case.json',{})
            inf=runtime/direct.signing.PAYLOAD/'share/wine/wine.inf'
            inf.parent.mkdir(parents=True);inf.write_text('synthetic')
            (seed/'run/prefix/.update-timestamp').write_text(str(int(inf.stat().st_mtime)))
            native=runtime/direct.preparation.NATIVE
            native.parent.mkdir(parents=True);native.write_bytes(b'synthetic native identity only')
            context=object.__new__(FixtureContext)
            context.selected={};context.value={'seed_root':str(seed),'provider_root':str(root/'provider')}
            context.ref={'synthetic':True};context.fresh_output=Mock(return_value=output)
            context.begin=Mock(return_value=(runtime,{'entrypoints':{}}))
            context.mark=Mock();context.storage_admission=Mock(return_value={})
            context.baseline=Mock();context.finish=Mock()
            events=[]
            def authority(*args):events.append(Path(args[2]).name)
            context.current_authority=Mock(side_effect=authority)
            def preserve(path):
                build.write_json(path/'producers.json',[])
                return []
            context.preserve_sources=Mock(side_effect=preserve)
            @contextmanager
            def interval(path):
                self.assertEqual(path,output);events.append('interval-enter')
                try:yield
                finally:events.append('interval-release')
            context.execution_interval=interval
            failure=Error('assembly_worker_timeout')
            def timed_out():events.append('owned-timeout');raise failure
            session=SimpleNamespace(failure=None,events={},children={},
                observer=SimpleNamespace(registrations={},signal_observations=[]))
            helpers=SimpleNamespace(base=SimpleNamespace(STREAM_LIMIT=None),
                api=SimpleNamespace(APISession=Mock(return_value=session),
                                    graphical_session=Mock(side_effect=timed_out)))
            def cleanup(*args):
                events.append('cleanup')
                return {},{'complete':True},{'complete':True},{},True,[]
            life=SimpleNamespace(cleanup_session=Mock(side_effect=cleanup))
            @contextmanager
            def supervision(root):yield life,helpers
            stack.enter_context(patch.object(direct.supervisor,'supervision',side_effect=supervision))
            stack.enter_context(patch.object(direct.supervisor,'assessment_packet',return_value={}))
            stack.enter_context(patch.object(direct.supervisor,'environment',return_value={}))
            stack.enter_context(patch.object(direct,'prefix_inventory',return_value=[]))
            copy=stack.enter_context(patch.object(direct.subprocess,'run'))
            stack.enter_context(patch.object(direct,'stage_modules',return_value=[]))
            assess=stack.enter_context(patch.object(direct,'assess',side_effect=AssertionError('late assessment')))
            with self.assertRaises(Error) as caught:
                direct.run(None,Selection('d25-game',runtime),output,
                           fixture='tls-thread',fixture_context=context)
            self.assertIs(caught.exception,failure)
            life.cleanup_session.assert_called_once_with(session,None,None,output/'run')
            self.assertEqual(events,['interval-enter','before','owned-timeout','cleanup','interval-release'])
            context.current_authority.assert_called_once()
            context.finish.assert_not_called();assess.assert_not_called()
            helpers.api.APISession.assert_called_once();copy.assert_called_once()
            saved=build.load(output/'case.json')
            self.assertEqual(saved['outcome'],'error')
            self.assertEqual(saved['error']['code'],'assembly_worker_timeout')
            self.assertEqual(saved['error']['phase'],'owned-run')
            self.assertTrue(saved['cleanup']['complete'])
            self.assertTrue(saved['sentinel_survived'])
            self.assertNotIn('authorization_before_after_passed',saved)
            self.assertFalse((output/'assessment.json').exists())


if __name__ == '__main__':
    unittest.main()
