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
import evidence from "./locales/en/evidence.json";
import geolocation from "./locales/en/geolocation.json";
import geoint from "./locales/en/geoint.json";
import history from "./locales/en/history.json";
import investigations from "./locales/en/investigations.json";
import overview from "./locales/en/overview.json";
import pivots from "./locales/en/pivots.json";
import relationshipEvolution from "./locales/en/relationshipEvolution.json";
import relationships from "./locales/en/relationships.json";
import report from "./locales/en/report.json";
import research from "./locales/en/research.json";
import shell from "./locales/en/shell.json";
import timeline from "./locales/en/timeline.json";

/** The v0.1 shipped locale. */
export const DEFAULT_LOCALE = "en";

/** The PR 24A + PR 24B + PR 24C + PR 24D + PR 24E + PR 25B + PR 26E translation namespaces. */
export const NAMESPACES = [
  "common",
  "auth",
  "shell",
  "investigations",
  "overview",
  "report",
  "evidence",
  "geolocation",
  "geoint",
  "relationships",
  "relationshipEvolution",
  "research",
  "timeline",
  "history",
  "pivots",
] as const;

const RESOURCES = {
  en: {
    common,
    auth,
    shell,
    investigations,
    overview,
    report,
    evidence,
    geolocation,
    geoint,
    relationships,
    relationshipEvolution,
    research,
    timeline,
    history,
    pivots,
  },
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