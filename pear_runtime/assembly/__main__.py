# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Command-line entrypoint; importing the package never launches assembly."""
from .driver import main

if __name__ == "__main__":
    raise SystemExit(main())
