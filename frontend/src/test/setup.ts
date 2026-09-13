// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Vitest global setup (PR 24A): jest-dom matchers, i18n initialization
// before any render, per-test DOM/cookie/global cleanup.

import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";

import { afterEach, beforeAll, vi } from "vitest";

import { initI18n } from "../i18n";

beforeAll(async () => {
  await initI18n();
});

/** Clear the jsdom cookie jar (the empty-string setter is a no-op). */
function clearCookies(): void {
  const jar = document.cookie;
  if (!jar) {
    return;
  }
  for (const part of jar.split(";")) {
    const entry = part.trim();
    const separator = entry.indexOf("=");
    if (separator > 0) {
      document.cookie = `${entry.slice(0, separator).trim()}=; Max-Age=0`;
    }
  }
}

afterEach(() => {
  cleanup();
  clearCookies();
  vi.unstubAllGlobals();
});