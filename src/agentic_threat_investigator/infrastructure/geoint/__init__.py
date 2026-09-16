# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Upstream reference-geography supply path (PR 26B-2).

Deterministic source adapters (GeoNames, Natural Earth) and the ATI
Geography Corpus builder that turn operator-supplied local source files into
the documented ATI Geography Corpus NDJSON consumed by
``ati-geography-import``. Nothing in this package writes PostgreSQL, and
nothing downloads upstream data.
"""
