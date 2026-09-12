# SPDX-License-Identifier: AGPL-3.0-only
"""Application query/read contracts for analyst-facing data browsing.

PR 23A introduces a dedicated application read layer separate from the
execution-oriented write repositories. Query services own bounded filters,
deterministic ordering, opaque keyset cursors, and page contracts; they never
own HTTP semantics, request DTOs, or report generation.
"""
