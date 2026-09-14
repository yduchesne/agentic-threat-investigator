// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Detail error classification (PR 24C §16).
//
// The scoped 404 contract means "not found or not accessible" — it never
// enumerates cross-Investigation resources.

import type { ApiError } from "../api/errors";

/** Whether one error is the scoped resource 404 (cannot enumerate). */
export function isNotFound404(error: ApiError | null): boolean {
  return error !== null && error.kind === "api" && error.status === 404;
}