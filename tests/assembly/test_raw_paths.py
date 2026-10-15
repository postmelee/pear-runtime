# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Raw load-path admission with selected Wine compatibility; no host loading."""
import struct,tempfile,unittest
from pathlib import Path
from pear_runtime.errors import Error
from pear_runtime.assembly._byte_readers import (inspect_closure as inspect_closure_policy,
    _raw_path_parts as raw_parts)
from pear_runtime.assembly import _byte_readers as current

def macho(dependency=None,rpaths=()):
 commands=[]
 for kind,value in ((0xc,dependency),*((0x8000001c,item) for item in rpaths)):
  if value is None:continue
  raw=value.encode()+b'\0';length=(12+len(raw)+3)&~3
  commands.append(struct.pack('<III',kind,length,12)+raw+b'\0'*(length-12-len(raw)))
 command=b''.join(commands)
 return struct.pack('<8I',0xfeedfacf,current.MACH_ARM64,0,6,len(commands),len(command),0,0)+command

class PolicyCases(unittest.TestCase):
 def setUp(self):
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name).resolve();self.bundle=self.root/'bundle';self.install=self.bundle/'lib/wine/aarch64-unix';self.install.mkdir(parents=True)
  self.image=self.install/'a.so';self.image.write_bytes(macho());self.leaf=self.install/'leaf.dylib';self.leaf.write_bytes(macho())
 def scan(self,dep=None,rpaths=()):self.image.write_bytes(macho(dep,rpaths));return inspect_closure_policy(self.image,self.bundle)
 def test_canonical_system_paths_external(self):
  for dep in ('/usr/lib/libSystem.B.dylib','/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit'):
   self.assertEqual(self.scan(dep)[0]['resolved_dependencies'][0]['kind'],'macos_system_dependency')
 def test_noncanonical_system_paths_refused(self):
  for dep in ('/usr/lib/../../x.dylib','/System/Library/./x.dylib','/usr/lib//x.dylib','//usr/lib/x.dylib','/usr/lib/x\ny','/usr/lib/x\\y'):
   with self.subTest(dep=dep),self.assertRaises(Error):self.scan(dep)
 def test_selected_trailing_and_bounded_parent_rpaths_allowed(self):
  for path in ('@loader_path','@loader_path/','@loader_path/../../','@executable_path/../../'):
   self.assertEqual(len(self.scan(rpaths=(path,))),1)
  for path in ('@loader_path','@loader_path/'):
   rows=self.scan('@rpath/leaf.dylib',(path,));self.assertEqual(len(rows),2)
   self.assertEqual(rows[0]['resolved_dependencies'][0]['path'],str(self.leaf))
 def test_malformed_unused_rpaths_refused(self):
  for path in ('@loader_path/.','@loader_path//','@executable_path/.','@executable_path//','/usr/lib/.','/usr/lib//','//usr/lib','@rpath','relative/path','@loader_path_extra','x/@loader_path','@loader_path/@executable_path','@loader_path/\n'):
   for dependency in (None,'@rpath/leaf.dylib'):
    with self.subTest(path=path,dependency=dependency),self.assertRaises(Error):self.scan(dependency,(path,))
 def test_parent_compatibility_is_bounded_not_blanket_dotdot_ban(self):
  # Old raw policy refused this; new explicit rule allows it within the bundle.
  rows=self.scan('@rpath/leaf.dylib',('@loader_path/../aarch64-unix',));self.assertEqual(len(rows),2)
  with self.assertRaisesRegex(Error,'macho_path_outside_bundle'):self.scan(rpaths=('@loader_path/../../../../',))
 def test_absolute_rpath_in_bundle_only(self):
  self.assertEqual(len(self.scan('@rpath/leaf.dylib',(str(self.install),))),2)
  outside=self.root/'outside';outside.mkdir()
  with self.assertRaisesRegex(Error,'macho_path_outside_bundle'):self.scan(rpaths=(str(outside),))
 def test_rpath_and_library_aliases_inside_only(self):
  inside=self.bundle/'alias';inside.symlink_to(self.install,target_is_directory=True)
  self.assertEqual(len(self.scan('@rpath/leaf.dylib',(str(inside),))),2)
  alias=self.install/'alias.dylib';alias.symlink_to('leaf.dylib');self.assertEqual(len(self.scan('@loader_path/alias.dylib')),2)
  outside=self.root/'outside';outside.mkdir();(outside/'leaf.dylib').write_bytes(macho())
  external=self.bundle/'external';external.symlink_to(outside,target_is_directory=True)
  with self.assertRaisesRegex(Error,'macho_path_outside_bundle'):self.scan(rpaths=(str(external),))
 def test_inherited_rpaths_do_not_skip_own_raw_validation(self):
  (self.install/'b.dylib').write_bytes(macho('@rpath/leaf.dylib',('@loader_path//',)))
  with self.assertRaises(Error):self.scan('@rpath/b.dylib',('@loader_path',))
 def test_bundle_load_suffixes_and_anchor_boundaries(self):
  for dep in ('@rpath/./leaf.dylib','@rpath//leaf.dylib','@rpath/../leaf.dylib','@loader_path_extra/leaf.dylib','relative/leaf.dylib','@loader_path/@rpath/leaf.dylib'):
   with self.subTest(dep=dep),self.assertRaises(Error):self.scan(dep,('@loader_path',))
  self.assertEqual(len(self.scan(str(self.leaf))),2)
 def test_raw_control_characters_refused_before_filesystem_resolution(self):
  for control in ('\0','\n','\x7f','\x85'):
   with self.subTest(control=repr(control)),self.assertRaises(Error):raw_parts('/usr/lib/a'+control+'.dylib')
   with self.subTest(control=repr(control)),self.assertRaises(Error):raw_parts('@loader_path/a'+control,rpath=True)
 def test_broken_or_external_library_alias_cannot_hide_behind_valid_rpath(self):
  alternate=self.install/'alternate';alternate.mkdir()
  outside=self.root/'outside.dylib';outside.write_bytes(macho())
  alias=alternate/'leaf.dylib'
  for target in (self.root/'missing.dylib',outside):
   with self.subTest(target=target.name):
    alias.symlink_to(target)
    try:
     with self.assertRaises(Error):self.scan('@rpath/leaf.dylib',('@loader_path/alternate','@loader_path'))
    finally:alias.unlink()
 def test_broken_or_external_directory_alias_cannot_hide_behind_valid_rpath(self):
  outside=self.root/'outside-dir';outside.mkdir();alias=self.bundle/'alias-dir'
  for target in (self.root/'missing-dir',outside):
   with self.subTest(target=target.name):
    alias.symlink_to(target,target_is_directory=True)
    try:
     with self.assertRaises(Error):self.scan('@rpath/leaf.dylib',(str(alias),'@loader_path'))
    finally:alias.unlink()
 def test_broken_or_external_intermediate_alias_cannot_hide_behind_valid_rpath(self):
  alternate=self.install/'alternate';alternate.mkdir()
  valid=self.install/'nested';valid.mkdir();(valid/'leaf.dylib').write_bytes(macho())
  outside=self.root/'outside-tree';outside.mkdir();(outside/'leaf.dylib').write_bytes(macho())
  alias=alternate/'nested'
  for target in (self.root/'missing-tree',outside):
   with self.subTest(target=target.name):
    alias.symlink_to(target,target_is_directory=True)
    try:
     with self.assertRaises(Error):self.scan('@rpath/nested/leaf.dylib',('@loader_path/alternate','@loader_path'))
    finally:alias.unlink()
