# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit current artifact admission and the original synthetic-prefix inventory."""
from __future__ import annotations

import hashlib
import os
import stat

from pear_runtime.assembly import core as assembly
from pear_runtime.errors import need

H = lambda raw: hashlib.sha256(raw).hexdigest()


def prefix_inventory(root):
    # Wine drive names contain colons and have two intentional symlinks; the
    # signed bundle inventory has a different, stricter path vocabulary.
    rows=[]
    for path in sorted(root.rglob('*')):
        rel=str(path.relative_to(root));info=path.lstat()
        if stat.S_ISLNK(info.st_mode):
            target=os.readlink(path)
            need((rel,target) in {('dosdevices/c:','../drive_c'),('dosdevices/z:','/')},'integration_prefix_link')
            rows.append({'path':rel,'kind':'link','target':target})
        elif stat.S_ISREG(info.st_mode):
            rows.append({'path':rel,'kind':'file','size':info.st_size,'mode':stat.S_IMODE(info.st_mode),'sha256':H(path.read_bytes())})
        else:
            need(stat.S_ISDIR(info.st_mode),'integration_prefix_special_file')
            rows.append({'path':rel,'kind':'directory','mode':stat.S_IMODE(info.st_mode)})
    return rows


def current(runtime_ref, operation_ref, profile_ref, helper_root, output):
    """Retain the complete current authority check; never infer its operation ref.

    The caller owns the live interval and worker group. This adapter grants no
    execution authority from historical records and preserves all original errors.
    """
    return assembly.verify_current_authority(runtime_ref, profile_ref, helper_root, output,
                                             operation_ref=operation_ref)
