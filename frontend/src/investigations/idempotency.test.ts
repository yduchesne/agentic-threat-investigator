// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Idempotency-key lifecycle tests (PR 24B U12-U15, §12).

import { beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/errors";
import type { CreateInvestigationInput } from "../api/schema-types";
import {
  IDEMPOTENCY_KEY_GRAMMAR,
  IdempotencyAttemptStore,
  createIdempotencyKey,
  isCreateAttemptOutcomeUncertain,
  payloadFingerprint,
} from "./idempotency";

const INPUT_A: CreateInvestigationInput = {
  objective: "assess the delivery domain",
  indicators: [{ type: "domain", value: "update-package.test" }],
};

const INPUT_B: CreateInvestigationInput = {
  ...INPUT_A,
  objective: "assess a different domain",
};

describe("create-attempt outcome uncertainty classifier (PR 24F)", () => {
  it("classifies a transport failure as commit-uncertain", () => {
    const error = new ApiError("transport", 0, "network_error", "lost");
    expect(isCreateAttemptOutcomeUncertain(error)).toBe(true);
  });

  it("classifies API 5xx envelopes (500/502/503) as commit-uncertain", () => {
    for (const status of [500, 502, 503]) {
      const error = new ApiError("api", status, "internal_error", "boom");
      expect(isCreateAttemptOutcomeUncertain(error)).toBe(true);
    }
  });

  it("classifies a malformed 5xx response as commit-uncertain", () => {
    // A 500 whose body is not the stable error envelope surfaces as an
    // unexpected-response; the HTTP status still decides uncertainty.
    const error = new ApiError("unexpected-response", 500, "unexpected_response", "bad body");
    expect(isCreateAttemptOutcomeUncertain(error)).toBe(true);
  });

  it("never classifies CSRF-before-transport as uncertain", () => {
    const error = new ApiError("csrf", 0, "csrf_missing", "no cookie");
    expect(isCreateAttemptOutcomeUncertain(error)).toBe(false);
  });

  it("settles definitive 4xx API rejections", () => {
    for (const [status, code] of [
      [400, "validation_error"],
      [401, "authentication_required"],
      [403, "forbidden"],
      [409, "idempotency_conflict"],
      [422, "validation_error"],
    ] as const) {
      const error = new ApiError("api", status, code, "rejected");
      expect(isCreateAttemptOutcomeUncertain(error)).toBe(false);
    }
  });

  it("settles definitive unexpected-response 4xx responses", () => {
    const error = new ApiError(
      "unexpected-response",
      400,
      "unexpected_response",
      "bad body",
    );
    expect(isCreateAttemptOutcomeUncertain(error)).toBe(false);
  });
});

describe("idempotency keys", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("generates a cryptographically strong key on first use (U12)", () => {
    const store = new IdempotencyAttemptStore();
    const attempt = store.begin(payloadFingerprint(INPUT_A));
    expect(attempt.key).toMatch(IDEMPOTENCY_KEY_GRAMMAR);
    expect(attempt.uncertain).toBe(false);
  });

  it("never uses Math.random (U15)", () => {
    const mathRandom = vi.spyOn(Math, "random");
    const store = new IdempotencyAttemptStore();
    store.begin(payloadFingerprint(INPUT_A));
    expect(mathRandom).not.toHaveBeenCalled();
  });

  it("reuses the same key for an uncertain retry of unchanged content (U13)", () => {
    const store = new IdempotencyAttemptStore();
    const first = store.begin(payloadFingerprint(INPUT_A));
    store.markUncertain();
    const retry = store.begin(payloadFingerprint(INPUT_A));
    expect(retry.key).toBe(first.key);
    expect(retry.fingerprint).toBe(first.fingerprint);
  });

  it("generates a new key when semantic payload changes after an uncertain attempt (U14)", () => {
    const store = new IdempotencyAttemptStore();
    const first = store.begin(payloadFingerprint(INPUT_A));
    store.markUncertain();
    const changed = store.begin(payloadFingerprint(INPUT_B));
    expect(changed.key).not.toBe(first.key);
  });

  it("generates a new key after the attempt is settled (success/definitive rejection)", () => {
    const store = new IdempotencyAttemptStore();
    const first = store.begin(payloadFingerprint(INPUT_A));
    store.markUncertain();
    store.settle();
    const next = store.begin(payloadFingerprint(INPUT_A));
    expect(next.key).not.toBe(first.key);
    expect(next.uncertain).toBe(false);
  });

  it("rejects an uncertain reuse only for the exact same fingerprint", () => {
    const store = new IdempotencyAttemptStore();
    const first = store.begin(payloadFingerprint(INPUT_A));
    store.markUncertain();
    // Same semantic content, different key order in the JSON -> same
    // fingerprint; indicators order matters (backend fingerprint is
    // canonicalized server-side, so the browser uses a stable client shape).
    const stable = store.begin(payloadFingerprint(INPUT_A));
    expect(stable.key).toBe(first.key);
    // A different objective is a different logical request.
    const other = store.begin(payloadFingerprint(INPUT_B));
    expect(other.key).not.toBe(first.key);
  });

  it("produces keys that satisfy the backend 1..128 visible-ASCII grammar", () => {
    const keys = Array.from({ length: 32 }, () => createIdempotencyKey());
    for (const key of keys) {
      expect(key).toMatch(IDEMPOTENCY_KEY_GRAMMAR);
      expect(key.length).toBeGreaterThanOrEqual(1);
      expect(key.length).toBeLessThanOrEqual(128);
    }
    expect(new Set(keys).size).toBe(keys.length);
  });
});