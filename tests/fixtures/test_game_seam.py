# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable source, companion and copied-game binding refusals; no native execution."""
import ast
from contextlib import ExitStack
import copy
from pathlib import Path
import sys
import tempfile
from types import CodeType,SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.fixtures import supervision,producers,game_types,game_operation
from pear_runtime.fixtures.context import FixtureContext

ROOT=Path(__file__).resolve().parents[2]
PROVIDER=ROOT/'pear_runtime/providers/pear_legacy'


class CompanionTests(unittest.TestCase):
    def test_private_namespaces_keep_original_classes_and_independent_budgets(self):
        with ExitStack() as stack:
            for target in ('subprocess.Popen','subprocess.run','ctypes.CDLL','os.killpg','socket.socket'):
                stack.enter_context(patch(target,side_effect=AssertionError('no native operation')))
            with supervision.supervision(PROVIDER) as (life,helpers):
                aliases=dict(sys.modules);paths=list(sys.path);helpers.base.STREAM_LIMIT=64*1024**2
                first=life.companion_factory();second=life.companion_factory()
                first.STREAM_LIMIT=4*1024**2
                self.assertEqual(helpers.base.STREAM_LIMIT,64*1024**2)
                self.assertEqual(second.STREAM_LIMIT,256*1024)
                self.assertIsNot(first.Session,second.Session)
                self.assertEqual(first.Session.__init__.__code__,helpers.base.Session.__init__.__code__)
                self.assertEqual(first.DarwinObserver.__init__.__code__,helpers.base.DarwinObserver.__init__.__code__)
                self.assertEqual(dict(sys.modules),aliases);self.assertEqual(sys.path,paths)
                factory=life.companion_factory
            with self.assertRaisesRegex(Error,'game_companion_provider_inactive'):factory()

    def test_child_provider_requires_exact_original_source_and_provenance(self):
        refs=supervision.source_refs(PROVIDER);proof=supervision.provenance_ref()
        with supervision.companion_provider(PROVIDER,provider_ref=proof,source_refs=refs) as base:
            self.assertTrue(callable(base.DarwinObserver));self.assertTrue(callable(base.Session))
        bad=copy.deepcopy(refs);bad.pop(next(iter(bad)))
        with patch.object(supervision,'_companion_namespace',side_effect=AssertionError('not admitted')) as load:
            with self.assertRaisesRegex(Error,'game_companion_provider_binding'):
                with supervision.companion_provider(PROVIDER,provider_ref=proof,source_refs=bad):pass
        load.assert_not_called()

    def test_child_provider_does_not_mask_primary_with_late_input_failure(self):
        refs=supervision.source_refs(PROVIDER);proof=supervision.provenance_ref()
        with patch.object(supervision,'_recheck',side_effect=Error('fixture_provider_changed')):
            with self.assertRaisesRegex(RuntimeError,'primary') as raised:
                with supervision.companion_provider(PROVIDER,provider_ref=proof,source_refs=refs):raise RuntimeError('primary')
        self.assertIn('fixture_provider_changed',raised.exception.__notes__[0])


class PreparedTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.output=self.root/'output';game=self.output/'game';game.mkdir(parents=True)
        executable=game/'Megabonk.exe';executable.write_bytes(b'synthetic executable')
        target=game/'GameAssembly.dll';target.write_bytes(b'synthetic target')
        snapshot=self.root/'snapshot.json';snapshot.write_bytes(b'{}')
        self.refs=[]
        for i in range(69):
            path=self.root/f'source-{i}';path.write_bytes(str(i).encode());self.refs.append(build.fact(path))
        self.value={'game_files':[dict(relative=f'file-{i}',ref=ref) for i,ref in enumerate(self.refs)],
                    'snapshot_ref':build.fact(snapshot)}
        info=target.stat();self.prepared=game_types.PreparedGame(game,build.fact(executable),
            dict(dev=info.st_dev,ino=info.st_ino,bytes=info.st_size,sha256=build.fact(target)['sha256']),
            copy.deepcopy(self.refs),self.value['snapshot_ref'])

    def test_flat_original_refs_join_all_ordered_descriptor_rows(self):
        executable,target=game_types.validate_prepared(self.prepared,self.value,self.output)
        self.assertEqual(executable,self.output/'game/Megabonk.exe');self.assertEqual(target,self.prepared.target)

    def test_shallow_frozen_value_cannot_hide_source_order_or_identity_change(self):
        for change in ('reverse','drop','change'):
            refs=copy.deepcopy(self.refs)
            if change=='reverse':refs.reverse()
            elif change=='drop':refs.pop()
            else:refs[0]['sha256']='0'*64
            value=game_types.PreparedGame(self.prepared.game_root,self.prepared.executable_ref,
                self.prepared.target,refs,self.prepared.snapshot_ref)
            with self.subTest(change=change),self.assertRaisesRegex(Error,'game_prepared_sources'):
                game_types.validate_prepared(value,self.value,self.output)

    def test_changed_executable_target_and_alias_are_refused(self):
        exe=self.output/'game/Megabonk.exe';original=exe.read_bytes();exe.write_bytes(b'changed')
        with self.assertRaisesRegex(Error,'game_prepared_executable'):game_types.validate_prepared(self.prepared,self.value,self.output)
        exe.write_bytes(original);target=self.output/'game/GameAssembly.dll';target.write_bytes(b'changed')
        with self.assertRaisesRegex(Error,'game_prepared_target'):game_types.validate_prepared(self.prepared,self.value,self.output)
        target.unlink();target.symlink_to(self.root/'source-0')
        with self.assertRaisesRegex(Error,'game_prepared_alias'):game_types.validate_prepared(self.prepared,self.value,self.output)

    def test_structural_substitute_and_foreign_output_are_refused(self):
        with self.assertRaisesRegex(Error,'game_prepared_type'):
            game_types.validate_prepared(SimpleNamespace(**self.prepared.__dict__),self.value,self.output)
        with self.assertRaisesRegex(Error,'game_prepared_root'):
            game_types.validate_prepared(self.prepared,self.value,self.root/'other')


class ProducerScopeTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.pear=self.root/'pear';self.pear.mkdir()

    def test_fixture_scope_refuses_pear_root_and_game_entrypoints(self):
        with self.assertRaisesRegex(Error,'fixture_producer_roots'):
            producers._root_map({'runtime':str(ROOT),'pear':str(self.pear)})
        with self.assertRaisesRegex(Error,'fixture_producer_entrypoints'):
            producers.closure_options(game_operation.GAME_ENTRY_MODULES,(), 'fixture_producer_sources')

    def test_game_scope_requires_exact_entrypoints_and_one_named_policy_manifest(self):
        for entries in (game_operation.GAME_ENTRY_MODULES[:-1],game_operation.GAME_ENTRY_MODULES+('tools.other',)):
            with self.assertRaises(Error):producers.closure_options(entries,(),game_operation.SCOPE)
        for path in ('pear:tools/other.json','pear:../private.json'):
            with self.assertRaisesRegex(Error,'game_producer_dynamic_scope'):
                producers.closure_options(game_operation.GAME_ENTRY_MODULES,(path,),game_operation.SCOPE)
        producers.closure_options(game_operation.GAME_ENTRY_MODULES,
            ('pear:tools/development/game/import-provenance.json',),game_operation.SCOPE)

    def test_game_module_resolution_never_admits_other_tools(self):
        package=self.pear/'tools/development/game';package.mkdir(parents=True)
        (package/'context.py').write_text('VALUE=1\n')
        self.assertEqual(producers._module_location('tools.development.game.context',{'pear':self.pear}),
                         ('pear','tools/development/game/context.py'))
        with self.assertRaisesRegex(Error,'game_producer_module_scope'):
            producers._module_location('tools.steam.old_policy',{'pear':self.pear})
        with self.assertRaisesRegex(Error,'fixture_producer_module_missing'):
            producers._module_location('tools.development.game.missing',{'pear':self.pear})

    def test_loaded_policy_from_other_root_is_refused(self):
        source=self.pear/'policy.py';source.write_text('VALUE=1\n')
        other=self.root/'other.py';other.write_text('VALUE=1\n')
        with patch.dict(sys.modules,{'tools.development.game.context':SimpleNamespace(__file__=str(other))}):
            refs={('pear','policy.py'):build.fact(source)}
            with self.assertRaisesRegex(Error,'fixture_producer_loaded_source'):producers._loaded_sources(refs)


class ContextInspectTests(unittest.TestCase):
    def test_full_read_only_inspect_does_not_activate_or_execute(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();output=root/'fresh';descriptor=root/'descriptor.json';descriptor.write_text('{}')
            ctx=object.__new__(FixtureContext);ctx._active=False;ctx._completed=False
            ctx.ref=build.fact(descriptor);ctx.value={'runtime_ref':{},'operation_ref':{},'producer_manifest_ref':{}}
            ctx._producers=Mock(refs={});ctx.fresh_output=Mock(return_value=output)
            ctx._admit=Mock(return_value=(root,{}));ctx.storage_admission=Mock(return_value={'required_free_bytes':1})
            with patch('subprocess.run',side_effect=AssertionError('inspect cannot execute')):
                result=ctx.inspect(output)
            ctx._admit.assert_called_once_with();ctx._producers.recheck.assert_called_once_with()
            self.assertFalse(ctx._active);self.assertFalse(ctx._completed);self.assertFalse(output.exists())
            for key in ('current_authority_assessed','runtime_execution_performed','game_qualified'):self.assertIs(result[key],False)
            ctx._active=True
            with self.assertRaisesRegex(Error,'fixture_inspect_state'):ctx.inspect(output)


if __name__=='__main__':unittest.main()
