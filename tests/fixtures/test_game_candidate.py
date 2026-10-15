# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Candidate source/copy roots and resealed synthetic-prefix admission failures."""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch

from pear_runtime import build
from pear_runtime.errors import Error
from pear_runtime.assembly.helpers import PAYLOAD
from pear_runtime.fixtures import game_operation as subject
from pear_runtime.fixtures.supervision import prefix_inventory


class CandidateTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name).resolve()
        self.runtime=self.root/'runtime';self.seed=self.root/'seed';self.provider=self.root/'provider';self.output=self.root/'outputs'
        for p in (self.runtime,self.seed,self.provider,self.output):p.mkdir()
        self.template=self.seed/'run/prefix';self.template.mkdir(parents=True)
        inf=self.runtime/PAYLOAD/'share/wine/wine.inf';inf.parent.mkdir(parents=True);inf.write_text('synthetic')
        (self.template/'.update-timestamp').write_text(str(int(inf.stat().st_mtime)))
        modules={}
        for name in ('ntdll.dll','xtajit64.dll'):
            source=self.runtime/PAYLOAD/'lib/wine/aarch64-windows'/name;source.parent.mkdir(parents=True,exist_ok=True);source.write_bytes(b'new-'+name.encode())
            target=self.template/'drive_c/windows/system32'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b'old-'+name.encode())
            modules[name]=dict(seed_sha256=build.fact(target)['sha256'],selected_ref=build.fact(source))
        self.seedref=self.write(self.seed/'case.json',dict(scope='translated_graphics',fixture_id='device',outcome='exited',error=None,
            cleanup={'complete':True},sentinel_survived=True,cleanup_errors=[]))
        self.profile=self.write(self.root/'profile/meta.json',{})
        self.inputroot=self.root/'immutable-pack';self.inputroot.mkdir()
        built=self.write(self.root/'build/build.json',dict(schema_version=1,scope='development_component_build',status='passed',
            roots={'inputs':{'kind':'input','path':str(self.inputroot)}}))
        runtime=dict(passed=True,diagnostic_only=True,runtime_qualified=False,runtime_eligible=False,game_qualified=False,
            execution_authorized_by_this_record=False,development_assembly={'profile_ref':self.profile,'builds':[built],'review_refs':[]})
        self.runtime_ref=self.write(self.runtime/'runtime.json',runtime);self.opref=self.write(self.root/'operation.json',{})
        self.capref=self.write(self.root/'capabilities.json',{})
        self.m=dict(runtime_ref=self.runtime_ref,operation_ref=self.opref,profile_ref=self.profile,capabilities_ref=self.capref,
            seed_ref=self.seedref,seed_root=str(self.seed),provider_root=str(self.provider),output_root=str(self.output),
            seed_inventory=prefix_inventory(self.template),modules=modules)
        self.stack=self.enterContext(ExitStack())
        self.stack.enter_context(patch.object(subject.core,'completed_operation'))
        self.stack.enter_context(patch.object(subject,'SourcePack'))
        self.stack.enter_context(patch.object(subject,'signing_helpers',return_value=(None,None)))
        self.stack.enter_context(patch.object(subject.core,'verify_closure'))
        self.stack.enter_context(patch.object(subject,'capability_binding',return_value={'attach_observer':True}))
        self.stack.enter_context(patch('subprocess.run',side_effect=AssertionError('candidate inspection cannot launch')))

    def write(self,path,value):path.parent.mkdir(parents=True,exist_ok=True);build.write_json(path,value);return build.fact(path)

    def test_explicit_candidate_and_seed_admit_without_commands(self):
        runtime,value,selected=subject.admit_candidate(self.m)
        self.assertEqual(runtime,self.runtime);self.assertEqual(selected,{'attach_observer':True})

    def test_resealed_seed_with_wrong_update_timestamp_is_still_refused(self):
        (self.template/'.update-timestamp').write_text('0')
        self.m['seed_inventory']=prefix_inventory(self.template)
        with self.assertRaisesRegex(Error,'game_prefix_update'):subject.admit_candidate(self.m)

    def test_output_inside_component_immutable_input_root_is_refused(self):
        output=self.inputroot/'output';output.mkdir();self.m['output_root']=str(output)
        with self.assertRaisesRegex(Error,'game_output_build_input_overlap'):subject.admit_candidate(self.m)

    def test_equal_bytes_from_other_selected_module_path_are_not_admitted(self):
        original=Path(self.m['modules']['ntdll.dll']['selected_ref']['path'])
        other=self.root/'same-bytes.dll';other.write_bytes(original.read_bytes())
        self.m['modules']['ntdll.dll']['selected_ref']=build.fact(other)
        with self.assertRaisesRegex(Error,'game_module_binding'):subject.admit_candidate(self.m)


if __name__=='__main__':unittest.main()
