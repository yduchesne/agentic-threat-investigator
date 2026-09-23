# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Optional external evaluation backends (PR 30B).

Backends project the repository-owned PR 30 evaluation contract onto
external platforms (LangSmith first). They are optional projections only:
ATI remains authoritative for identity, semantics, verdicts, digests, and
gates, and nothing under ``evaluation/common`` imports them.
"""
