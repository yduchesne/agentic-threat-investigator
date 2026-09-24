# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Thin test-only re-export of the canonical Report Writer fixture map (PR 30E).

PR 30E promoted the canonical fixture map into
``agentic_threat_investigator.evaluation.report_writer.scenarios``; this
module is a deprecated test-only compatibility alias. New code should import
from the canonical evaluation package.
"""

from __future__ import annotations

from agentic_threat_investigator.evaluation.report_writer.scenarios import (
    REPORT_WRITER_FIXTURES,
    report_writer_fixture,
)

__all__ = ["REPORT_WRITER_FIXTURES", "report_writer_fixture"]
