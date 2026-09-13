// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Stable application composition (PR 24A): i18n is initialized before the
// app renders; MUI theme + CssBaseline, one QueryClient and the Router
// provider wrap the application tree.

import { CssBaseline, ThemeProvider } from "@mui/material";
import { Global } from "@emotion/react";
import { QueryClientProvider } from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";
import type { ReactElement, ReactNode } from "react";

import { createAppQueryClient } from "./queryClient";
import { ATI_THEME, PRIMARY_COLOR } from "./theme";

const defaultQueryClient = createAppQueryClient();

export interface AppProvidersProps {
  children: ReactNode;
  /** Overridable for isolated tests; production uses the shared client. */
  queryClient?: QueryClient;
}

/** Compose the MUI theme, TanStack Query client and children. */
export function AppProviders({ children, queryClient }: AppProvidersProps): ReactElement {
  return (
    <QueryClientProvider client={queryClient ?? defaultQueryClient}>
      <ThemeProvider theme={ATI_THEME}>
        <CssBaseline />
        <Global
          styles={{
            ":focus-visible": {
              outline: "2px solid",
              outlineColor: PRIMARY_COLOR,
              outlineOffset: "2px",
            },
          }}
        />
        {children}
      </ThemeProvider>
    </QueryClientProvider>
  );
}