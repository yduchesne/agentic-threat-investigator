// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// QueryClient retry policy tests (PR 24A U33-U34).
//
// Server state retries are bounded: never for mutations, never for
// 401/403, at most one transient GET/network retry.

import { describe, expect, it } from "vitest";

import { ApiError } from "../api/errors";
import { MUTATION_RETRY_COUNT, createAppQueryClient, queryRetryPolicy } from "./queryClient";

function api(status: number, code: string): ApiError {
  return new ApiError("api", status, code, `${code} message`);
}

describe("queryRetryPolicy", () => {
  it("never retries 401 (U34)", () => {
    expect(queryRetryPolicy(0, api(401, "authentication_required"))).toBe(false);
    expect(queryRetryPolicy(1, api(401, "authentication_required"))).toBe(false);
  });

  it("never retries 403 (U34)", () => {
    expect(queryRetryPolicy(0, api(403, "forbidden"))).toBe(false);
    expect(queryRetryPolicy(2, api(403, "forbidden"))).toBe(false);
  });

  it("does not retry other public 4xx failures", () => {
    expect(queryRetryPolicy(0, api(404, "not_found"))).toBe(false);
    expect(queryRetryPolicy(0, api(429, "rate_limited"))).toBe(false);
    expect(queryRetryPolicy(0, api(422, "validation_error"))).toBe(false);
  });

  it("retries transient 5xx failures at most once", () => {
    expect(queryRetryPolicy(0, api(500, "internal_error"))).toBe(true);
    expect(queryRetryPolicy(1, api(500, "internal_error"))).toBe(false);
  });

  it("retries transport/network failures at most once", () => {
    const network = new ApiError("transport", 0, "network_error", "network");
    expect(queryRetryPolicy(0, network)).toBe(true);
    expect(queryRetryPolicy(1, network)).toBe(false);
  });

  it("bounds unexpected non-typed errors to a single retry", () => {
    expect(queryRetryPolicy(0, new Error("boom"))).toBe(true);
    expect(queryRetryPolicy(1, new Error("boom"))).toBe(false);
  });

  it("builds a client with no mutation retry (U33)", () => {
    expect(MUTATION_RETRY_COUNT).toBe(0);
    expect(createAppQueryClient()).toBeDefined();
  });
});