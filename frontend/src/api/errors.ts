// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Typed ATI API error model (PR 24A).
//
// One class carries every failure mode the frontend must distinguish so the
// presentation layer can render safe, localized text. Public API errors
// retain the stable envelope fields (status/code/message/request_id).
// Transport, unexpected-response and client CSRF failures use stable
// client-side codes and never expose raw backend payloads.

export type ApiErrorKind = "api" | "transport" | "unexpected-response" | "csrf";

/** Stable client-side code for network/transport failures. */
export const TRANSPORT_ERROR_CODE = "network_error";
/** Stable client-side code when a response cannot be interpreted safely. */
export const UNEXPECTED_RESPONSE_CODE = "unexpected_response";
/** Stable client-side code when an unsafe request lacks the CSRF cookie. */
export const CSRF_MISSING_CODE = "csrf_missing";

export interface ParsedErrorDetail {
  /** Stable public error code from the backend envelope. */
  code: string;
  /** Safe backend-provided message. */
  message: string;
  /** Bounded request correlation ID, when the envelope provides one. */
  requestId: string | null;
}

/**
 * Extract the stable error envelope fields from an unknown response payload.
 *
 * Returns `null` when the payload is not the documented
 * `{"error": {"code", "message", "request_id"}}` shape; the caller must
 * then produce a safe unexpected-response error instead of trusting the
 * body.
 */
export function parseErrorEnvelope(value: unknown): ParsedErrorDetail | null {
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const candidate = value as { error?: unknown };
  const error = candidate.error;
  if (typeof error !== "object" || error === null) {
    return null;
  }
  const fields = error as { code?: unknown; message?: unknown; request_id?: unknown };
  if (typeof fields.code !== "string" || typeof fields.message !== "string") {
    return null;
  }
  return {
    code: fields.code,
    message: fields.message,
    requestId: typeof fields.request_id === "string" ? fields.request_id : null,
  };
}

/** Whether a thrown value looks like a fetch AbortError (request cancelled). */
export function isAbortError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) {
    return false;
  }
  return (error as { name?: unknown }).name === "AbortError";
}

/**
 * The single typed frontend API error.
 *
 * `status` is the HTTP status when one was received and `0` otherwise.
 * `code` is the stable backend code for `kind === "api"` failures, or a
 * stable client-side code otherwise.
 */
export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;

  constructor(
    kind: ApiErrorKind,
    status: number,
    code: string,
    message: string,
    requestId: string | null = null,
  ) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }

  /** True for failures where a bounded transient retry is meaningful. */
  get isTransient(): boolean {
    return this.status === 0 || this.status >= 500;
  }
}

/** True when the error is the stable 401 unauthenticated API error. */
export function isUnauthenticated(error: ApiError): boolean {
  return error.kind === "api" && error.status === 401;
}

/** Build an ApiError from the parsed stable envelope. */
export function apiErrorFromEnvelope(status: number, detail: ParsedErrorDetail): ApiError {
  return new ApiError("api", status, detail.code, detail.message, detail.requestId);
}

/** Build a transport/network error without exposing the underlying cause. */
export function transportError(message = "Network request failed."): ApiError {
  return new ApiError("transport", 0, TRANSPORT_ERROR_CODE, message);
}

/** Build a safe unexpected-response error for a non-envelope body. */
export function unexpectedResponseError(status: number): ApiError {
  return new ApiError(
    "unexpected-response",
    status,
    UNEXPECTED_RESPONSE_CODE,
    "The API returned an unexpected response.",
  );
}

/** Build the client CSRF error raised before transport when the cookie is absent. */
export function csrfMissingError(): ApiError {
  return new ApiError(
    "csrf",
    0,
    CSRF_MISSING_CODE,
    "The CSRF cookie is missing for this unsafe request.",
  );
}