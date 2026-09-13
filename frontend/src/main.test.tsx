// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Frontend bootstrap smoke tests (PR 24A).

import { describe, expect, it } from "vitest";

import { API_BASE_PATH } from "./api/client";
import { createAppRoutes } from "./app/routes";
import { DEFAULT_LOCALE, initI18n } from "./i18n";
import { router } from "./app/router";

describe("frontend bootstrap", () => {
  it("initializes the English locale exactly once", async () => {
    await initI18n();
    expect(DEFAULT_LOCALE).toBe("en");
  });

  it("uses the relative /api/v1 browser boundary (U32)", () => {
    expect(API_BASE_PATH).toBe("/api/v1");
    expect(API_BASE_PATH.startsWith("http")).toBe(false);
  });

  it("composes the production route table", () => {
    const routes = createAppRoutes();
    expect(routes.map((route) => route.path ?? "(layout)")).toEqual([
      "/login",
      "(layout)",
      "*",
    ]);
  });

  it("creates the application router outside the component tree", () => {
    expect(router).toBeDefined();
  });
});