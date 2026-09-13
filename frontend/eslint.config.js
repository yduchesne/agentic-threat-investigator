// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// ESLint flat config (PR 24A).
// The OpenAPI-derived type file is generated and never hand-edited.

import parser from "@typescript-eslint/parser";
import tseslint from "@typescript-eslint/eslint-plugin";

export default [
  {
    ignores: [
      "dist/**",
      "test-results/**",
      "playwright-report/**",
      "src/api/schema.generated.ts",
    ],
  },
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: { parser },
    plugins: { "@typescript-eslint": tseslint },
    rules: {
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
  {
    files: ["**/*.{js,mjs,cjs}"],
    rules: {},
  },
];