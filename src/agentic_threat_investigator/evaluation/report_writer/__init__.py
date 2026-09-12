# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Repository-owned Report Writer evaluation baseline (PR 23B).

The Report Writer evaluation answers a deterministic question about the
delivered PR 23B runtime: given a known persisted investigation snapshot and
the production Report Writer execution path, is the final persisted report
acceptably grounded and faithful to the authoritative Assessment/Research
inputs? It is deliberately NOT the generic PR 27 evaluator platform and uses
no LLM-as-judge, embeddings, regex fact extraction, or fuzzy similarity.
"""
