// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// ATI frontend entry point (PR 24A).
//
// i18n initializes before normal app render; a render error boundary wraps
// the whole tree; the Browser Router keeps URL state and one QueryClient
// keeps server state (created outside the component tree).

import { StrictMode, type ReactElement } from "react";
import { createRoot } from "react-dom/client";
import { useTranslation } from "react-i18next";
import { RouterProvider } from "react-router";

import { AppProviders } from "./app/AppProviders";
import { router } from "./app/router";
import { AppErrorBoundary } from "./components/ErrorBoundary";
import { applyDocumentLocale, initI18n } from "./i18n";

/** Wrap the routed tree with the safe global render boundary. */
function RootBoundary({ children }: { children: ReactElement }): ReactElement {
  const { t } = useTranslation("common");
  return (
    <AppErrorBoundary
      title={t("errorBoundary.title")}
      message={t("errorBoundary.message")}
      reloadLabel={t("errorBoundary.reload")}
    >
      {children}
    </AppErrorBoundary>
  );
}

async function main(): Promise<void> {
  await initI18n();
  applyDocumentLocale();
  const root = document.getElementById("root");
  if (root === null) {
    throw new Error("ATI frontend root element is missing.");
  }
  createRoot(root).render(
    <StrictMode>
      <RootBoundary>
        <AppProviders>
          <RouterProvider router={router} />
        </AppProviders>
      </RootBoundary>
    </StrictMode>,
  );
}

void main();