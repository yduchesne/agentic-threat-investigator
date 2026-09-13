# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic fake intelligence runtime (PR 23D).

The ``fake`` operating mode replaces only the external intelligence-source
implementations with repository-owned deterministic fixtures and adapters.
This package owns the versioned synthetic world catalog, the fixture-backed
live providers, and the fake-data bootstrap. It never imports application
test code, never performs network I/O, and never mutates PostgreSQL except
through the explicit bootstrap command path.
"""
