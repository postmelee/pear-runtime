# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reject changed recipe inputs before writing generated fixture sources."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from pear_runtime.errors import Error
from pear_runtime.assembly._common import encoded
from pear_runtime.recipes import cpu_sources


class SourceInputs(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve();self.output=self.root/'generated'
        self.fex=Path(cpu_sources.asm_generator.__file__).resolve().parents[3]
        self.runtime=Path(cpu_sources.__file__).resolve().parents[2]
        self.recipe=self.root/'recipe.json'
        self.generate=self.enterContext(patch.object(cpu_sources.asm_generator,'generate',
                          side_effect=AssertionError('generator reached before refusal')))

    def test_changed_source_refused_before_output(self):
        self.recipe.write_bytes(encoded(dict(schema_version=1,scope='cpu_fixture_source_recipe',
            inputs=[dict(root='fex',path='Pear/Tests/CPU/runner.c',sha256='0'*64,size_bytes=1)])))
        with self.assertRaisesRegex(Error,'cpu_source_input_changed'):
            cpu_sources.prepare(self.fex,self.runtime,self.output,recipe_path=self.recipe)
        self.assertFalse(self.output.exists());self.generate.assert_not_called()

    def test_foreign_root_is_refused_before_output(self):
        self.recipe.write_bytes(encoded(dict(schema_version=1,scope='cpu_fixture_source_recipe',
            inputs=[dict(root='ambient',path='file',sha256='0'*64,size_bytes=1)])))
        with self.assertRaisesRegex(Error,'cpu_source_input_root'):
            cpu_sources.prepare(self.fex,self.runtime,self.output,recipe_path=self.recipe)
        self.assertFalse(self.output.exists());self.generate.assert_not_called()

    def test_recipe_cannot_escape_declared_component_root(self):
        self.recipe.write_bytes(encoded(dict(schema_version=1,scope='cpu_fixture_source_recipe',
            inputs=[dict(root='fex',path='../outside',sha256='0'*64,size_bytes=1)])))
        with self.assertRaisesRegex(Error,'unsafe_path'):
            cpu_sources.prepare(self.fex,self.runtime,self.output,recipe_path=self.recipe)
        self.assertFalse(self.output.exists());self.generate.assert_not_called()

    def test_source_root_must_match_actual_loaded_generator(self):
        with self.assertRaisesRegex(Error,'cpu_generator_source_root'):
            cpu_sources.prepare(self.root,self.runtime,self.output)
        self.assertFalse(self.output.exists());self.generate.assert_not_called()


if __name__=='__main__':unittest.main()
