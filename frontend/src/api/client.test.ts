// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// ATI HTTP boundary tests (PR 24A U02-U07, U11-U12, U32).

import { describe, expect, it, vi } from "vitest";

import { API_BASE_PATH, apiRequest } from "./client";
import { CSRF_COOKIE_NAME } from "./csrf";
import { ApiError } from "./errors";
import { ANALYST_USER } from "../test/handlers";

/** Install a scripted fetch implementation for request-shape assertions. */
function stubFetch(): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn(
    async (_url: string, _init: RequestInit): Promise<Response> => {
      throw new Error("stub fetch called without a configured response");
    },
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

interface CapturedInit {
  method: string;
  credentials: unknown;
  headers: Map<string, string>;
  body: string | undefined;
  signal: unknown;
  url: string;
}

function header(headers: Map<string, string>, name: string): string | undefined {
  return headers.get(name.toLowerCase());
}

function initFrom(fetchMock: ReturnType<typeof vi.fn>): CapturedInit {
  const call = fetchMock.mock.calls[0];
  const url = String(call[0]);
  const init = (call[1] ?? {}) as {
    method?: string;
    credentials?: string;
    headers?: HeadersInit;
    body?: BodyInit;
    signal?: AbortSignal;
  };
  return {
    url,
    method: init.method ?? "GET",
    credentials: init.credentials,
    headers: new Map(new Headers(init.headers ?? {}).entries()),
    body: typeof init.body === "string" ? init.body : undefined,
    signal: init.signal,
  };
}

async function respondJson(status: number, body: unknown): Promise<void> {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      return new Response(JSON.stringify(body), {
        status,
        headers: { "content-type": "application/json" },
      });
    }),
  );
}

describe("apiRequest", () => {
  it("uses the relative /api/v1 base resolved to the page origin (U32, U02)", async () => {
    const fetchMock = stubFetch();
    document.cookie = `${CSRF_COOKIE_NAME}=csrf`;
    await apiRequest<unknown>("/auth/me", { method: "GET", csrf: "absent-ok" }).catch(() => undefined);
    const captured = initFrom(fetchMock);
    expect(captured.url.startsWith(`${window.location.origin}${API_BASE_PATH}/auth/me`)).toBe(true);
    expect(captured.credentials).toBe("include");
    expect(header(captured.headers, "Accept")).toBe("application/json");
    expect(captured.url.includes("localhost:8000")).toBe(false);
  });

  it("sends X-CSRF-Token for unsafe authenticated requests (U08)", async () => {
    const fetchMock = stubFetch();
    document.cookie = `${CSRF_COOKIE_NAME}=token%20value`;
    await apiRequest<unknown>("/auth/logout", { method: "POST" }).catch(() => undefined);
    const captured = initFrom(fetchMock);
    expect(captured.method).toBe("POST");
    expect(header(captured.headers, "X-CSRF-Token")).toBe("token value");
  });

  it("allows login before the CSRF cookie exists (U11)", async () => {
    const fetchMock = stubFetch();
    document.cookie = "";
    await apiRequest<unknown>("/auth/login", {
      method: "POST",
      body: { username: "a", password: "b" },
      csrf: "absent-ok",
    }).catch(() => undefined);
    const captured = initFrom(fetchMock);
    expect(header(captured.headers, "X-CSRF-Token")).toBeUndefined();
    expect(header(captured.headers, "Content-Type")).toBe("application/json");
    expect(captured.body).toBe('{"username":"a","password":"b"}');
  });

  it("fails clearly before transport when an unsafe request lacks the CSRF cookie (U12)", async () => {
    const fetchMock = stubFetch();
    document.cookie = "";
    const error = await apiRequest<unknown>("/auth/logout", { method: "POST" }).catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.kind).toBe("csrf");
    expect(apiError.code).toBe("csrf_missing");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns typed JSON on success (U03)", async () => {
    await respondJson(200, ANALYST_USER);
    const result = await apiRequest<typeof ANALYST_USER>("/auth/me");
    expect(result).toEqual(ANALYST_USER);
  });

  it("handles 204 cleanly (U04)", async () => {
    document.cookie = `${CSRF_COOKIE_NAME}=csrf`;
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204 })));
    const result = await apiRequest<undefined>("/auth/logout", { method: "POST" });
    expect(result).toBeUndefined();
  });

  it("retains the public error envelope fields (U05)", async () => {
    await respondJson(404, { error: { code: "not_found", message: "Nope.", request_id: "rq-1" } });
    const error = await apiRequest<unknown>("/nope").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.kind).toBe("api");
    expect(apiError.status).toBe(404);
    expect(apiError.code).toBe("not_found");
    expect(apiError.message).toBe("Nope.");
    expect(apiError.requestId).toBe("rq-1");
  });

  it("maps malformed error bodies to a safe unexpected-response error (U06)", async () => {
    await respondJson(500, "<html>not an envelope</html>");
    const error = await apiRequest<unknown>("/boom").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.kind).toBe("unexpected-response");
    expect(apiError.code).toBe("unexpected_response");
    expect(apiError.status).toBe(500);
    expect(apiError.message).not.toContain("<html>");
    expect(apiError.message).not.toContain("python");
  });

  it("maps network failures to transport errors, never a fake 401 (U07)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("Failed to fetch");
      }),
    );
    const error = await apiRequest<unknown>("/auth/me").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.kind).toBe("transport");
    expect(apiError.status).toBe(0);
    expect(apiError.code).toBe("network_error");
    expect(apiError.status).not.toBe(401);
  });

  it("rethrows AbortError untouched", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new DOMException("The operation was aborted.", "AbortError");
      }),
    );
    const caught = await apiRequest<unknown>("/auth/me").catch((value: unknown) => value);
    expect(isAbortErrorLike(caught)).toBe(true);
  });
});

function isAbortErrorLike(value: unknown): boolean {
  return typeof value === "object" && value !== null && (value as { name?: unknown }).name === "AbortError";
}