// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// CSRF cookie parsing tests (PR 24A U08-U10).

import { describe, expect, it } from "vitest";

import { CSRF_COOKIE_NAME, readCookie, readCsrfToken } from "./csrf";

describe("readCookie / readCsrfToken", () => {
  it("reads the exact ati_csrf cookie by name", () => {
    document.cookie = "path=/";
    document.cookie = "ati_csrf=abc123";
    document.cookie = "ati_session=secret";
    expect(readCsrfToken()).toBe("abc123");
  });

  it("ignores similarly named cookies (U09)", () => {
    document.cookie = "ati_csrfx=wrong-1";
    document.cookie = "xati_csrf=wrong-2";
    document.cookie = "ati_csrf=right";
    expect(readCsrfToken()).toBe("right");
    document.cookie = "old_csrf=leftover";
    document.cookie = `${CSRF_COOKIE_NAME}=; Max-Age=0`;
    document.cookie = "xati_csrf=only-similar";
    expect(readCsrfToken()).toBeNull();
  });

  it("decodes percent-encoded cookie values (U10)", () => {
    document.cookie = `${CSRF_COOKIE_NAME}=ab%2Bc%20d%3D`;
    expect(readCsrfToken()).toBe("ab+c d=");
  });

  it("returns null when the cookie is missing or blank", () => {
    document.cookie = "path=/";
    expect(readCsrfToken()).toBeNull();
    document.cookie = `${CSRF_COOKIE_NAME}=`;
    expect(readCsrfToken()).toBeNull();
  });

  it("returns null for malformed percent-encoding without throwing", () => {
    document.cookie = `${CSRF_COOKIE_NAME}=%zz`;
    expect(readCsrfToken()).toBeNull();
  });

  it("trims surrounding whitespace", () => {
    document.cookie = `  ${CSRF_COOKIE_NAME}  =  abc  ; path=/`;
    expect(readCsrfToken()).toBe("abc");
  });

  it("never exposes the session cookie through the CSRF reader", () => {
    document.cookie = "ati_session=super-secret-token";
    document.cookie = "ati_csrf=csrf-token";
    expect(readCookie("ati_session")).toBeNull();
    expect(readCookie(CSRF_COOKIE_NAME)).toBe("csrf-token");
  });
});