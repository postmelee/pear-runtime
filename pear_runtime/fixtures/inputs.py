# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
# Exact helpers from Pear tools/dxmt/translated_inputs.py; see fixture-parent-import.json.
from pathlib import Path
import hashlib
import json
import stat
from pear_runtime.errors import need
from pear_runtime.assembly._common import decode_json, relative, read_relative

def digest(raw):return hashlib.sha256(raw).hexdigest()

def read(path):return decode_json(Path(path).read_bytes(),64*1024**2,max_nodes=1000000)

def save(path,value):Path(path).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')

def fact(path):
    p=Path(path);need(p.is_file() and not p.is_symlink(),'translated_regular_file')
    return dict(path=str(p),sha256=digest(p.read_bytes()),size_bytes=p.stat().st_size)

def check_files(root,rows):
    need(rows and len({r['path'] for r in rows})==len(rows),'translated_inventory_set')
    for row in rows:
        relative(row['path']);p=Path(root)/row['path'];raw=read_relative(root,row['path'],64*1024**2)
        need(digest(raw)==row['sha256'] and len(raw)==row['size_bytes'],'translated_inventory_changed')
        if 'mode' in row:need(stat.S_IMODE(p.stat().st_mode)==row['mode'],'translated_inventory_mode')
