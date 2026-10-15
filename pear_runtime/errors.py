# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Stable errors extracted from Pear component preparation."""

class Error(Exception):
    """A stable public error code, without raw paths or subprocess diagnostics."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise Error(code)
