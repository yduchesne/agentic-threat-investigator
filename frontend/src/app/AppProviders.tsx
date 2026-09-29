// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Stable application composition (PR 24A): i18n is initialized before the
// app renders; MUI theme + CssBaseline, one QueryClient and the Router
// provider wrap the application tree.
//
// PR 31F-4: appearance is browser-local presentation state owned by the
// narrow AppearanceProvider. The active appearance selects one stable
// prebuilt theme from the centralized registry (never rebuilt per render),
// and the QueryClient identity is untouched by appearance changes — server
// state, investigation state and URL state survive switching. The global
// focus-visible rule and the Leaflet chrome rules consume the active
// theme's semantic tokens.

import { CssBaseline, ThemeProvider } from "@mui/material";
import { Global } from "@emotion/react";
import { QueryClientProvider } from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";
import type { ReactElement, ReactNode } from "react";

import { AppearanceProvider, useAppearance } from "./AppearanceProvider";
import { createAppQueryClient } from "./queryClient";
import { ATI_THEMES } from "./theme";
import type { Theme } from "@mui/material/styles";

const defaultQueryClient = createAppQueryClient();

export interface AppProvidersProps {
  children: ReactNode;
  /** Overridable for isolated tests; production uses the shared client. */
  queryClient?: QueryClient;
}

/**
 * Apply the active appearance's theme, baseline, focus rule and Leaflet
 * chrome. Rendering stays exactly one MUI ThemeProvider + one CssBaseline.
 */
function AppearanceBoundary({ children }: { children: ReactNode }): ReactElement {
  const { appearance } = useAppearance();
  const theme = ATI_THEMES[appearance] ?? ATI_THEMES.light;
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Global
        styles={{
          ":focus-visible": {
            outline: "2px solid",
            outlineColor: theme.ati.focus.visible,
            outlineOffset: "2px",
          },
        }}
      />
      <LeafletChrome theme={theme} />
      {children}
    </ThemeProvider>
  );
}

/**
 * ATI-owned Leaflet chrome only: map container ground, control/attribution
 * chips and popup surfaces. Never touches the OSM tile URL, tile pixels,
 * attribution text, coordinates or markers.
 */
function LeafletChrome({ theme }: { theme: Theme }): ReactElement | null {
  const tokens = theme.ati;
  return (
    <Global
      styles={{
        ".leaflet-container": {
          backgroundColor: tokens.map.container,
          color: tokens.text.primary,
        },
        ".leaflet-control-attribution": {
          backgroundColor: tokens.map.overlay,
          color: tokens.text.secondary,
        },
        ".leaflet-control-attribution a": {
          color: tokens.accent.secondary,
        },
        ".leaflet-bar": {
          border: `1px solid ${tokens.map.border}`,
        },
        ".leaflet-bar a": {
          backgroundColor: tokens.map.overlay,
          color: tokens.text.primary,
        },
        ".leaflet-bar a:hover": {
          backgroundColor: tokens.map.overlay,
          color: tokens.text.primary,
        },
        ".leaflet-popup-content-wrapper": {
          backgroundColor: tokens.surface.elevated,
          color: tokens.text.primary,
        },
        ".leaflet-popup-tip": {
          backgroundColor: tokens.surface.elevated,
        },
        ".leaflet-popup-close-button": {
          color: tokens.text.secondary,
        },
      }}
    />
  );
}

/** Compose the appearance, MUI theme, TanStack Query client and children. */
export function AppProviders({ children, queryClient }: AppProvidersProps): ReactElement {
  return (
    <QueryClientProvider client={queryClient ?? defaultQueryClient}>
      <AppearanceProvider>
        <AppearanceBoundary>{children}</AppearanceBoundary>
      </AppearanceProvider>
    </QueryClientProvider>
  );
}
