# SPDX-License-Identifier: AGPL-3.0-only
"""Structured Report Writer application services (PR 23B).

The Report Writer transforms ATI's already-persisted authoritative analytical
inputs (current Assessment, its Evidence/RelationshipObservation provenance,
persisted ResearchResults) into a structured, provenance-backed
:class:`~agentic_threat_investigator.domain.report.InvestigationReport` that
PR 23C serves and the deterministic formatter renders. It never collects
Evidence, performs RAG retrieval, changes investigation policy, determines
the analytical verdict, or creates new threat-intelligence facts.
"""
