// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// ATI analyst-workbench theme (PR 24A).
//
// One restrained, accessible design foundation: compact readable spacing,
// table-ready typography, visible focus, and consistent status semantics.
// No third-party font CDN is used; system font stacks keep the workbench
// fast and offline-deterministic.

import { createTheme } from "@mui/material/styles";

/** Primary action color: dark steel blue from the ATI range. */
export const PRIMARY_COLOR = "#1b5e8c";
/** Warning/attention color used by the persistent FAKE DATA surface. */
export const WARNING_COLOR = "#8a5b00";
/** Danger/error color. */
export const ERROR_COLOR = "#b3261e";

/** Monospace stack for IOC values, identifiers and request IDs. */
export const MONO_FONT_STACK =
  '"SFMono-Regular", "Roboto Mono", "Cascadia Code", "Consolas", "Menlo", monospace';

/** The single ATI application theme. */
export const ATI_THEME = createTheme({
  palette: {
    primary: { main: PRIMARY_COLOR, dark: "#13466a", light: "#3d84bb" },
    warning: { main: WARNING_COLOR },
    error: { main: ERROR_COLOR },
    success: { main: "#14643a" },
    info: { main: "#12648c" },
    background: { default: "#f4f6f8", paper: "#ffffff" },
  },
  shape: { borderRadius: 6 },
  typography: {
    htmlFontSize: 16,
    fontFamily: '"Inter", "Segoe UI", "Helvetica Neue", "Arial", "Noto Sans", sans-serif',
    body1: { fontSize: "0.9375rem", lineHeight: 1.5 },
    body2: { fontSize: "0.8125rem", lineHeight: 1.45 },
    h1: { fontSize: "1.5rem", lineHeight: 1.25, fontWeight: 600 },
    h2: { fontSize: "1.25rem", lineHeight: 1.3, fontWeight: 600 },
    h3: { fontSize: "1.0625rem", lineHeight: 1.35, fontWeight: 600 },
    subtitle1: { fontSize: "0.9375rem", lineHeight: 1.4, fontWeight: 700 },
    subtitle2: { fontSize: "0.8125rem", lineHeight: 1.4, fontWeight: 700 },
    caption: { fontSize: "0.75rem", lineHeight: 1.4 },
    overline: { fontSize: "0.6875rem", lineHeight: 1.4, letterSpacing: "0.06em", textTransform: "uppercase" },
  },
  components: {
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: { root: { textTransform: "none" } },
    },
    MuiLink: {
      defaultProps: { underline: "hover" },
    },
    MuiTextField: {
      defaultProps: { size: "medium" },
    },
    MuiCard: {
      styleOverrides: { root: { border: "1px solid #d7dbe0" } },
    },
  },
});