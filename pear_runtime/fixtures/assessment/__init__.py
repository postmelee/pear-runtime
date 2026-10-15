# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Preserved assessment chain; caller owns exact candidate and run admission."""
from .wake import assess as assess_owned

__all__ = ['assess_owned']
