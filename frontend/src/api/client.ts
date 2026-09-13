// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// One controlled ATI fetch boundary (PR 24A).
//
// Every browser API call funnels through `apiRequest`. It owns relative
// browser-facing base URL, credentials, Accept header, single JSON
// serialization, the double-submit CSRF header for unsafe requests, Abort
// signal threading, and translation of responses into typed data or typed
// ApiError values. It never navigates, shows toasts, mutates the Query
// cache, decides auth redirects, retries, or knows Investigation
// semantics.

import { CSRF_HEADER_NAME, readCsrfToken } from "./csrf";
import {
  apiErrorFromEnvelope,
  csrfMissingError,
  isAbortError,
  parseErrorEnvelope,
  transportError,
  unexpectedResponseError,
} from "./errors";

/** The browser-facing API base; proxied by Nginx and Vite alike. */
export const API_BASE_PATH = "/api/v1";

/**
 * Build the request URL from the relative browser-facing base.
 *
 * The base never contains a host. In the browser (and in jsdom tests) the
 * page origin supplies the authority so the request stays same-origin
 * under both the Vite dev proxy and the Nginx `/api` reverse proxy. The
 * Node environment (unit tests) cannot fetch relative URLs, so resolving
 * here keeps one code path for every runtime.
 */
function requestTarget(path: string): string {
  const suffix = `${API_BASE_PATH}${path}`;
  if (typeof window !== "undefined" && window.location?.href) {
    try {
      return new URL(suffix, window.location.href).toString();
    } catch {
      return suffix;
    }
  }
  return suffix;
}
export const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

/** CSRF policy for one request. */
export type CsrfPolicy = "required" | "absent-ok";

export interface ApiRequestOptions {
  method?: HttpMethod;
  /** JSON-serializable body; serialized exactly once. */
  body?: unknown;
  /** Optional caller-provided cancellation signal. */
  signal?: AbortSignal;
  /** Unsafe-request CSRF policy (login is the only "absent-ok" caller). */
  csrf?: CsrfPolicy;
}

const UNSAFE_METHODS: ReadonlySet<HttpMethod> = new Set(["POST", "PUT", "PATCH", "DELETE"]);

function isUnsafeMethod(method: HttpMethod): boolean {
  return UNSAFE_METHODS.has(method);
}

/**
 * Execute one ATI API request and return the typed payload.
 *
 * Throws `ApiError` for every failure mode; callers never see raw
 * `fetch` errors or response bodies.
 */
export async function apiRequest<T>(path: string, options: ApiRequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const unsafe = isUnsafeMethod(method);
  const headers: Record<string, string> = { Accept: "application/json" };

  if (unsafe) {
    const token = readCsrfToken();
    if (token === null && options.csrf !== "absent-ok") {
      // Failing before transport beats knowingly sending a server-rejected
      // request. Login is the only unsafe request allowed to proceed first.
      throw csrfMissingError();
    }
    if (token !== null) {
      headers[CSRF_HEADER_NAME] = token;
    }
  }

  const init: RequestInit = {
    method,
    headers,
    credentials: "include",
  };
  if (options.signal !== undefined) {
    init.signal = options.signal;
  }
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }

  let response: Response;
  try {
    response = await fetch(requestTarget(path), init);
  } catch (error) {
    if (isAbortError(error)) {
      // Cancellation must reach the caller untouched so Query clients can
      // treat it as abandonment rather than a failure.
      throw error;
    }
    throw transportError();
  }

  if (response.status === 204) {
    return undefined as T;
  }

  const text = await response.text();
  let payload: unknown = undefined;
  if (text.length > 0) {
    try {
      payload = JSON.parse(text);
    } catch {
      throw unexpectedResponseError(response.status);
    }
  }

  if (response.ok) {
    return payload as T;
  }

  const detail = parseErrorEnvelope(payload);
  if (detail === null) {
    throw unexpectedResponseError(response.status);
  }
  throw apiErrorFromEnvelope(response.status, detail);
}

/** A concise checked wrapper used by feature query modules. */
export async function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  return apiRequest<T>(path, { signal });
}