// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Vitest configuration (PR 24A): jsdom environment, one setup file,
// centralized MSW handlers and isolated QueryClients per test.

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    environmentOptions: {
      jsdom: { url: "http://localhost:8080/" },
    },
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    // PR 31F-6: real-route component tests boot the full providers/router/query
    // stack and PR 31F-6's deferred navigation commits add one macrotask per
    // interaction; under parallel suite load the default 5s per-test cap
    // produces misleading timeouts on this development hardware. 15s keeps
    // the assertions unchanged while removing load-induced flake.
    testTimeout: 15_000,
    restoreMocks: true,
    clearMocks: true,
  },
});
