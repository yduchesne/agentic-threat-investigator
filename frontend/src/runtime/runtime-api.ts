// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Runtime-mode API boundary functions (PR 24A / PR 23D contract).

import { apiRequest } from "../api/client";
import type { RuntimeInfo } from "../api/schema-types";

/** Fetch the authenticated runtime composition metadata. */
export async function fetchRuntime(signal?: AbortSignal): Promise<RuntimeInfo> {
  return apiRequest<RuntimeInfo>("/runtime", { signal });
}