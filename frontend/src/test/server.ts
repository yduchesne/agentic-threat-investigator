// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Centralized MSW node server lifecycle (PR 24A).
//
// One server instance; each test installs exactly the handlers it needs at
// test start (see `setHttpHandlers`), so no handler state leaks across
// tests and every Query cache is isolated per test. Any request matching
// no installed handler fails the test loudly.

import type { HttpHandler } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, beforeEach } from "vitest";

const server = setupServer();

/** Start the shared MSW server for one test file (module scope). */
export function useHttp(): void {
  beforeAll(() => {
    server.listen({ onUnhandledRequest: "error" });
  });
  beforeEach(() => {
    server.resetHandlers();
  });
  afterEach(() => {
    server.resetHandlers();
  });
  afterAll(() => {
    server.close();
  });
}

/** Install exactly the given handlers for the active test. */
export function setHttpHandlers(...handlers: HttpHandler[]): void {
  server.resetHandlers(...handlers);
}