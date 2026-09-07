# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Root test-suite configuration.

Ensures the repository root is importable so tests can reach the shared
``tests.support`` helpers regardless of which test directory pytest starts
from. The integration suite is intentionally not a package directory, so it
cannot rely on package-relative imports alone.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
