# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
# Selection and CandidateDescription retain their original Pear dataclass fields.
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Selection:
    name: str
    runtime: Path


@dataclass(frozen=True)
class CandidateDescription:
    name: str
    scope: str
