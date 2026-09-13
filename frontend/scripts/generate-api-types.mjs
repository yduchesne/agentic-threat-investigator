#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Deterministic OpenAPI -> TypeScript API type generation (PR 24A).
//
// The committed OpenAPI snapshot (tests/fixtures/openapi_v1.json) is the
// single authoritative source for generation. CI never fetches a live dev
// server's OpenAPI document.
//
// The snapshot references the documented ErrorResponse envelope
// (#/components/schemas/ErrorResponse and ErrorDetail) from every route's
// error responses, but the FastAPI document does not serialise the backing
// Pydantic models into `components`. This script injects that exact
// documented envelope (docs/API.md, src/.../api/errors.py) so the
// generated TypeScript types are complete. The committed snapshot file is
// never modified.
//
// Usage:
//   node scripts/generate-api-types.mjs            # regenerate in place
//   node scripts/generate-api-types.mjs --check    # verify Committed types are current
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const FIXTURE_PATH = resolve(ROOT, "..", "tests", "fixtures", "openapi_v1.json");
const OUTPUT_PATH = resolve(ROOT, "src", "api", "schema.generated.ts");
const CLI_PATH = resolve(ROOT, "node_modules", "openapi-typescript", "bin", "cli.js");
const CHECK = process.argv.includes("--check");

const ERROR_RESPONSE_SCHEMA = {
  additionalProperties: false,
  description: "The stable public API error envelope (documented in docs/API.md).",
  properties: {
    error: { $ref: "#/components/schemas/ErrorDetail" },
  },
  required: ["error"],
  title: "ErrorResponse",
  type: "object",
};

const ERROR_DETAIL_SCHEMA = {
  additionalProperties: false,
  description: "One stable error detail inside the public envelope.",
  properties: {
    code: { description: "Stable public error code.", title: "Code", type: "string" },
    message: { description: "Safe human-readable message.", title: "Message", type: "string" },
    request_id: { description: "Bounded request correlation ID.", title: "Request Id", type: "string" },
  },
  required: ["code", "message", "request_id"],
  title: "ErrorDetail",
  type: "object",
};

const spec = JSON.parse(await readFile(FIXTURE_PATH, "utf8"));
spec.components ??= {};
spec.components.schemas ??= {};
spec.components.schemas.ErrorResponse ??= ERROR_RESPONSE_SCHEMA;
spec.components.schemas.ErrorDetail ??= ERROR_DETAIL_SCHEMA;

const tempDir = await mkdtemp(resolve(String(tmpdir), "ati-openapi-types-"));
const tempSchemaPath = resolve(tempDir, "openapi_v1.json");
await writeFile(tempSchemaPath, JSON.stringify(spec, null, 2), "utf8");

const args = [
  CLI_PATH,
  tempSchemaPath,
  "--root-types",
  "--root-types-no-schema-prefix",
  "--output",
  OUTPUT_PATH,
];
if (CHECK) {
  args.push("--check");
}

const result = spawnSync(process.execPath, args, { cwd: ROOT });
if (result.status !== 0) {
  process.stderr.write(
    String(result.stderr || result.stdout || "") +
      (CHECK
        ? "\nGenerated API types are stale relative to tests/fixtures/openapi_v1.json.\n" +
          "Run `npm run api:generate` and commit the regenerated file.\n"
        : "\nOpenAPI type generation failed.\n"),
  );
  process.exit(typeof result.status === "number" ? result.status : 1);
}
if (result.stderr) {
  process.stderr.write(String(result.stderr));
}