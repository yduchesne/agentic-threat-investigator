# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Authoritative Evidence Analyst application results (PR 21).

``EvidenceAnalysisResult`` is the narrow application-layer output of one
Evidence Analyst execution after Assessment persistence: the persisted
Assessment, the required bounded disposition, and the authoritative
Investigation version allocated by the same transaction. The disposition is
a typed semantic output of the analyst decision and is never inferred from
verdict, confidence, findings, or recommendation prose.

This module lives outside the ``evidence_analyst`` package so the Assessment
persistence service can import it without creating an import cycle through
the package initializer.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.domain.assessment import Assessment
from agentic_threat_investigator.domain.investigation import AnalysisDisposition


class EvidenceAnalysisResult(BaseModel):
    """Typed result of one persisted Evidence Analyst execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    assessment: Assessment
    disposition: AnalysisDisposition
    investigation_version: int
