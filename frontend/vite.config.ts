// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Vite configuration (PR 24A).
//
// The development server listens on 8080 — the documented local public
// browser origin — and proxies browser `/api/v1/...` calls to the local
// backend so feature code never hard-codes an API host (the production
// Nginx container provides the same `/api` boundary).

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 8080,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        // Browser Origin/Referer headers pass through unchanged so PR 23C
        // CSRF origin validation keeps working through the dev proxy.
        changeOrigin: false,
      },
    },
  },
});