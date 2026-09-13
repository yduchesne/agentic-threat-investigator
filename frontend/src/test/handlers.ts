// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Central MSW handlers (PR 24A).
//
// Budget the deterministic HTTP surface for /auth/me, /auth/login,
// /auth/logout and /runtime. Tests compose the handlers they need; the
// harness (see server.ts) rejects unhandled requests loudly.

import type { HttpHandler } from "msw";
import { http, HttpResponse } from "msw";
import type { JsonBodyType } from "msw";

import type { PublicUser } from "../api/schema-types";

export const ANALYST_USER: PublicUser = {
  id: "10000000-0000-4000-8000-000000000001",
  alias: "analyst-a",
  role: "analyst",
};

export const ADMIN_USER: PublicUser = {
  id: "10000000-0000-4000-8000-000000000002",
  alias: "admin-a",
  role: "admin",
};

/** Build a stable public API error envelope response. */
export function errorResponse(
  status: number,
  code: string,
  requestId: string = "test-request-id",
): HttpResponse<JsonBodyType> {
  return HttpResponse.json(
    { error: { code, message: `${code} (test message)`, request_id: requestId } },
    { status },
  );
}

/** Build a JSON success response. */
export function jsonResponse<T extends JsonBodyType>(body: T, status: number = 200): HttpResponse<JsonBodyType> {
  return HttpResponse.json(body, { status });
}

// /auth/me ---------------------------------------------------------------

export const authMeSuccess = http.get("*/api/v1/auth/me", () => jsonResponse(ANALYST_USER));
export const authMe401 = http.get("*/api/v1/auth/me", () => errorResponse(401, "authentication_required"));
export const authMe500 = http.get("*/api/v1/auth/me", () => errorResponse(500, "internal_error"));
export const authMeNetworkError = http.get("*/api/v1/auth/me", () => HttpResponse.error());

// /auth/login ------------------------------------------------------------

export const loginSuccess = http.post("*/api/v1/auth/login", () => jsonResponse(ANALYST_USER));
export const loginInvalid = http.post("*/api/v1/auth/login", () => errorResponse(401, "invalid_credentials"));
export const loginRateLimited = http.post("*/api/v1/auth/login", () => errorResponse(429, "rate_limited"));
export const loginUnavailable = http.post("*/api/v1/auth/login", () => errorResponse(503, "dependency_unavailable"));
export const loginNetworkError = http.post("*/api/v1/auth/login", () => HttpResponse.error());

// /auth/logout -----------------------------------------------------------

export const logoutSuccess = http.post("*/api/v1/auth/logout", () => new HttpResponse(null, { status: 204 }));

// /runtime ---------------------------------------------------------------

export const runtimeFake = http.get("*/api/v1/runtime", () => jsonResponse({ operating_mode: "fake" }));
export const runtimeProduction = http.get("*/api/v1/runtime", () => jsonResponse({ operating_mode: "production" }));
export const runtimeFailure = http.get("*/api/v1/runtime", () => errorResponse(503, "dependency_unavailable"));
export const runtimeNetworkError = http.get("*/api/v1/runtime", () => HttpResponse.error());

/**
 * Stateful login-flow handlers mirroring the real session lifecycle:
 * `/auth/me` returns 401 until a successful login turns it into 200, and
 * login sets the double-submit CSRF cookie the way the real server does.
 */
export function loginFlowHandlers(
  user: PublicUser = ANALYST_USER,
): HttpHandler[] {
  let authenticated = false;
  return [
    http.get("*/api/v1/auth/me", () =>
      authenticated ? jsonResponse(user) : errorResponse(401, "authentication_required")),
    http.post("*/api/v1/auth/login", () => {
      authenticated = true;
      document.cookie = "ati_csrf=test-csrf-token";
      return jsonResponse(user);
    }),
    http.post("*/api/v1/auth/logout", () => {
      // Mirror the real server: revoke the session and expire the CSRF cookie.
      authenticated = false;
      document.cookie = "ati_csrf=; Max-Age=0";
      return new HttpResponse(null, { status: 204 });
    }),
    runtimeFake,
  ];
}