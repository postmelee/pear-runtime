# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""The canonical generator must preserve the selected consumer interface bytes."""
from pathlib import Path
import unittest

from pear_runtime.abort_header import header


class SharedHeaderTests(unittest.TestCase):
    def test_generated_header_matches_selected_consumer_bytes(self):
        selected = Path(__file__).resolve().parents[2] / 'include/PearAbortObservation.h'
        self.assertEqual(header().encode('utf-8'), selected.read_bytes())


if __name__ == '__main__':
    unittest.main()
