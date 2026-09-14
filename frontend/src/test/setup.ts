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

/**
 * Minimal ResizeObserver stub for jsdom.
 *
 * @xyflow/react (the PR 24E graph visualization dependency) mounts a
 * ZoomPane that constructs a ResizeObserver in an effect; jsdom does not
 * ship one. The stub never reports sizes (jsdom has no layout), which is
 * exactly right for component tests that assert semantics, not pixels —
 * the canvas limits are exercised on the real stack by the Playwright
 * suite, which runs in Chromium.
 */
class ResizeObserverStub implements ResizeObserver {
  private callback: ResizeObserverCallback;

  constructor(callback: ResizeObserverCallback) {
    this.callback = callback;
  }

  observe(): void {}

  unobserve(): void {}

  disconnect(): void {}

  // ResizeObserver uses a callback trigger; keep the reference for the
  // structural contract without ever reporting layout in jsdom.
  protected trigger(): void {
    // Never invoked: jsdom provides no layout to observe.
  }
}

if (typeof globalThis.ResizeObserver === "undefined") {
  globalThis.ResizeObserver = ResizeObserverStub;
}

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