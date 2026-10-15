# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Concrete game preparation facts; types alone confer no execution authority."""
from dataclasses import dataclass
from pathlib import Path
from pear_runtime import build
from pear_runtime.assembly import core
from pear_runtime.assembly._common import encoded
from pear_runtime.errors import need


@dataclass(frozen=True)
class PreparedGame:
    game_root: Path
    executable_ref: dict
    target: dict
    source_files: list
    snapshot_ref: dict


def validate_prepared(prepared,value,output):
    need(type(prepared) is PreparedGame,'game_prepared_type')
    root=Path(output)/'game'
    need(isinstance(prepared.game_root,Path) and prepared.game_root==root and
         root.is_dir() and root.resolve(strict=True)==root,'game_prepared_root')
    executable=root/'Megabonk.exe';target=root/'GameAssembly.dll'
    for path in (executable,target):
        need(not path.is_symlink() and path.resolve(strict=True)==path,'game_prepared_alias')
    need(prepared.executable_ref==build.fact(executable),'game_prepared_executable')
    info=target.stat();expected=dict(dev=info.st_dev,ino=info.st_ino,bytes=info.st_size,
                                    sha256=build.fact(target)['sha256'])
    need(prepared.target==expected and all(type(prepared.target[k]) is int for k in ('dev','ino','bytes')),
         'game_prepared_target')
    need(type(prepared.source_files) is list and len(prepared.source_files)==69 and
         encoded(prepared.source_files)==encoded([row['ref'] for row in value['game_files']]),'game_prepared_sources')
    need(prepared.snapshot_ref==value['snapshot_ref'],'game_prepared_snapshot')
    core.checked_ref(prepared.snapshot_ref)
    return executable,dict(expected)
