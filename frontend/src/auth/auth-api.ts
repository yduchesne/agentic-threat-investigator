// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Authentication API boundary functions (PR 24A).

import { apiGet, apiRequest } from "../api/client";
import type { LoginCredentials, PublicUser } from "../api/schema-types";

/**
 * Authenticate with the real PR 23C contract.
 *
 * This is the only request allowed to run before the `ati_csrf` cookie
 * exists. The password is serialized once and never retained.
 */
export async function loginCommand(credentials: LoginCredentials): Promise<PublicUser> {
  return apiRequest<PublicUser>("/auth/login", {
    method: "POST",
    body: credentials,
    csrf: "absent-ok",
  });
}

/** Resolve the current session to the public user DTO. */
export async function fetchMe(signal?: AbortSignal): Promise<PublicUser> {
  return apiGet<PublicUser>("/auth/me", signal);
}

/**
 * Revoke the current session (CSRF-protected; idempotent, 204).
 *
 * Returns `null` because TanStack Query rejects undefined mutation data.
 */
export async function logoutCommand(): Promise<null> {
  await apiRequest<void>("/auth/logout", { method: "POST" });
  return null;
}