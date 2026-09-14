// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Browser idempotency-key lifecycle for logical submissions (PR 24B §12).
//
// A logical attempt is one semantic request payload plus one key. The key
// is generated cryptographically (never `Math.random`), kept only in
// in-memory attempt state (never localStorage/sessionStorage/URL/logs/UI),
// retained when retrying a transport-uncertain attempt with unchanged
// content, and replaced when the semantic content changes or the previous
// attempt is definitively settled.

import type { ApiError } from "../api/errors";
import type { CreateInvestigationInput } from "../api/schema-types";

/** Backend grammar: bounded visible ASCII, 1..128 characters (PR 23C). */
export const IDEMPOTENCY_KEY_GRAMMAR = /^[A-Za-z0-9._~-]{1,128}$/;

/** One in-memory logical submission attempt. */
export interface IdempotencyAttempt {
  key: string;
  /** Canonical fingerprint of the semantic request (never the key). */
  fingerprint: string;
  /** True while the server may have committed the attempt (lost response). */
  uncertain: boolean;
}

/** Normalized stable fingerprint of one semantic create payload. */
export function payloadFingerprint(input: CreateInvestigationInput): string {
  return JSON.stringify(input);
}

/**
 * Whether one create attempt's commit outcome is uncertain enough that an
 * unchanged retry must reuse the same Idempotency-Key (PR 24B §12; PR 24F §6).
 *
 * A transport failure (status 0, no HTTP response) and every HTTP response
 * with status >= 500 are commit-uncertain: the browser cannot determine
 * whether the request committed atomically and the response path then
 * failed, or failed before commit, so the safe retry reuses the same key
 * for the same semantic payload and lets the backend resolve the ambiguity.
 *
 * Everything else is definitive and settles the attempt: a pre-transport
 * CSRF failure (``kind === "csrf"``, still ``status === 0``) happens before
 * any request could commit, and definitive 4xx responses (validation,
 * idempotency conflict, auth/permission) are authoritative rejections.
 * The classifier deliberately never keys purely off ``error.status === 0``.
 */
export function isCreateAttemptOutcomeUncertain(error: ApiError): boolean {
  if (error.kind === "transport") {
    return true;
  }
  if (error.kind === "api" || error.kind === "unexpected-response") {
    return error.status >= 500;
  }
  return false;
}

/**
 * Generate one cryptographically strong idempotency key.
 *
 * Uses `crypto.randomUUID` when available and falls back to
 * `crypto.getRandomValues` with an RFC 4122 v4-shaped UUID. `Math.random`
 * is never used.
 */
export function createIdempotencyKey(): string {
  const cryptoApi = typeof crypto !== "undefined" ? crypto : undefined;
  if (cryptoApi !== undefined && typeof cryptoApi.randomUUID === "function") {
    return cryptoApi.randomUUID();
  }
  const bytes = new Uint8Array(16);
  if (cryptoApi === undefined) {
    throw new Error("crypto is unavailable for idempotency key generation");
  }
  cryptoApi.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Owns the current logical attempt for one create form session.
 *
 * `begin` reuses the previous key only when the previous attempt is
 * transport-uncertain AND the semantic fingerprint is unchanged; any other
 * situation starts a new key. `markUncertain` records a lost-response
 * situation so a retry reuses the key. `settle` ends the attempt (success
 * or definitive backend rejection) so the next submission is a new logical
 * request with a new key.
 */
export class IdempotencyAttemptStore {
  private attempt: IdempotencyAttempt | null = null;

  /** The current attempt, if any. */
  current(): IdempotencyAttempt | null {
    return this.attempt;
  }

  /** Begin (or safely reuse) one logical attempt for a fingerprint. */
  begin(fingerprint: string): IdempotencyAttempt {
    const current = this.attempt;
    if (
      current !== null &&
      current.uncertain &&
      current.fingerprint === fingerprint
    ) {
      return current;
    }
    const next: IdempotencyAttempt = {
      key: createIdempotencyKey(),
      fingerprint,
      uncertain: false,
    };
    this.attempt = next;
    return next;
  }

  /** Record transport uncertainty so a retry safely reuses the key. */
  markUncertain(): void {
    if (this.attempt !== null) {
      this.attempt = { ...this.attempt, uncertain: true };
    }
  }

  /** Settle the attempt (success or definitive rejection) -> new key next. */
  settle(): void {
    this.attempt = null;
  }
}