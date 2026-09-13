// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// i18next initialization (PR 24A).
//
// English is the first locale. User-visible shell and authentication
// strings are translation-backed; backend-controlled analytical content
// and API error messages are intentionally not translated here. Resources
// are static bundled JSON only — no remote translation service, no
// persisted language state. Interpolation escaping stays enabled.

import i18next from "i18next";
import { initReactI18next } from "react-i18next";

import auth from "./locales/en/auth.json";
import common from "./locales/en/common.json";
import shell from "./locales/en/shell.json";

/** The v0.1 shipped locale. */
export const DEFAULT_LOCALE = "en";

/** The three 24A translation namespaces. */
export const NAMESPACES = ["common", "auth", "shell"] as const;

const RESOURCES = {
  en: { common, auth, shell },
};

let initPromise: Promise<void> | null = null;

/** Initialize i18next exactly once; idempotent thereafter. */
export function initI18n(): Promise<void> {
  if (initPromise === null) {
    initPromise = i18next
      .use(initReactI18next)
      .init({
        lng: DEFAULT_LOCALE,
        fallbackLng: DEFAULT_LOCALE,
        ns: [...NAMESPACES],
        defaultNS: "common",
        resources: RESOURCES,
      })
      .then(() => undefined);
  }
  return initPromise;
}

/** Keep the document language attribute aligned with the active locale. */
export function applyDocumentLocale(locale: string = DEFAULT_LOCALE): void {
  if (typeof document !== "undefined") {
    document.documentElement.lang = locale;
  }
}