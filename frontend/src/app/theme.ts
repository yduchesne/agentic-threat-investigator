// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// ATI analyst-workbench theme system (PR 24A foundation, PR 31F-4 multi-theme).
//
// One restrained, accessible design foundation: compact readable spacing,
// table-ready typography, visible focus, and consistent status semantics.
// No third-party font CDN is used; system font stacks keep the workbench
// fast and offline-deterministic.
//
// PR 31F-4 evolves the single theme into a centralized semantic multi-theme
// architecture. The four bounded appearances (Light, Dark, Wargames,
// Control Room) are prebuilt once at module load — no theme is ever rebuilt
// per render — and every presentation surface consumes the typed semantic
// tokens through ``theme.ati`` instead of branching on theme names. MUI
// module augmentation carries the token contract through the public
// ``@mui/material/styles`` types; no ``any`` is used to bypass typing.

import { createTheme, type Components, type Theme } from "@mui/material/styles";

import {
  DEFAULT_APPEARANCE,
  type AppearancePreference,
} from "./appearance";

/** Primary action color (Light): dark steel blue from the ATI range. */
export const PRIMARY_COLOR = "#1b5e8c";
/** Warning/attention color (Light), used by the persistent FAKE DATA surface. */
export const WARNING_COLOR = "#8a5b00";
/** Danger/error color (Light). */
export const ERROR_COLOR = "#b3261e";

/** Monospace stack for IOC values, identifiers and request IDs. */
export const MONO_FONT_STACK =
  '"SFMono-Regular", "Roboto Mono", "Cascadia Code", "Consolas", "Menlo", monospace';

/**
 * Typed semantic token contract shared by every ATI appearance.
 *
 * Feature components consume these tokens (via ``theme.ati``) and never
 * branch on appearance names. Every theme defines the exact same contract;
 * no theme-specific fallbacks are needed at call sites.
 */
export interface AtiSemanticTokens {
  /** Shared surface tones. */
  surface: {
    /** Primary chrome (app bar, header). */
    primary: string;
    /** Elevated surfaces (cards, dialogs, menus). */
    elevated: string;
    /** Subtle page/well background. */
    subtle: string;
  };
  /** Text tones. */
  text: {
    primary: string;
    secondary: string;
    /** Technical values (monospace, identifiers, request IDs). */
    technical: string;
  };
  /** Action/attention accents. */
  accent: {
    primary: string;
    secondary: string;
  };
  /** Borders and dividers. */
  border: {
    default: string;
    emphasis: string;
  };
  /** Canvas/marquee selection. */
  selection: {
    background: string;
    border: string;
  };
  /** Status semantics (never the only carrier of meaning). */
  status: {
    success: string;
    warning: string;
    critical: string;
    info: string;
  };
  /** Relationship-graph (React Flow) presentation. */
  graph: {
    canvas: string;
    pattern: string;
    node: {
      background: string;
      border: string;
      text: string;
      selected: string;
    };
    edge: {
      default: string;
      label: string;
      selected: string;
    };
  };
  /** Map (Leaflet) container chrome. */
  map: {
    container: string;
    overlay: string;
    border: string;
  };
  /** Visible keyboard focus outline. */
  focus: {
    visible: string;
  };
}

/**
 * MUI module augmentation: the semantic token contract travels on every ATI
 * theme through the public ``Theme`` / ``ThemeOptions`` types.
 */
declare module "@mui/material/styles" {
  interface Theme {
    ati: AtiSemanticTokens;
  }
  interface ThemeOptions {
    ati?: AtiSemanticTokens;
  }
}

/** Shared compact workbench typography for every appearance. */
function themeTypography() {
  return {
    htmlFontSize: 16,
    fontFamily:
      '"Inter", "Segoe UI", "Helvetica Neue", "Arial", "Noto Sans", sans-serif',
    body1: { fontSize: "0.9375rem", lineHeight: 1.5 },
    body2: { fontSize: "0.8125rem", lineHeight: 1.45 },
    h1: { fontSize: "1.5rem", lineHeight: 1.25, fontWeight: 600 },
    h2: { fontSize: "1.25rem", lineHeight: 1.3, fontWeight: 600 },
    h3: { fontSize: "1.0625rem", lineHeight: 1.35, fontWeight: 600 },
    subtitle1: { fontSize: "0.9375rem", lineHeight: 1.4, fontWeight: 700 },
    subtitle2: { fontSize: "0.8125rem", lineHeight: 1.4, fontWeight: 700 },
    caption: { fontSize: "0.75rem", lineHeight: 1.4 },
    overline: {
      fontSize: "0.6875rem",
      lineHeight: 1.4,
      letterSpacing: "0.06em",
      textTransform: "uppercase",
    },
  };
}

/** Primal, theme-wide MUI component overrides (PR 31F-4 shared integration). */
function themeComponents(
  borderColor: string,
  interactiveColor: string,
  inputBorderColor: string,
  inputTextColor: string,
  colorScheme: "light" | "dark",
): Components<Theme> {
  return {
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: { root: { textTransform: "none" } },
    },
    MuiLink: {
      defaultProps: { underline: "hover" },
      styleOverrides: {
        root: {
          color: interactiveColor,
          "&:visited": { color: interactiveColor },
        },
      },
    },
    MuiCssBaseline: {
      styleOverrides: {
        "a, a:visited": {
          color: interactiveColor,
        },
      },
    },
    MuiTextField: {
      defaultProps: { size: "medium" },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          color: inputTextColor,
          colorScheme,
          "& .MuiOutlinedInput-notchedOutline": {
            borderColor: inputBorderColor,
          },
          "&:hover .MuiOutlinedInput-notchedOutline": {
            borderColor: inputBorderColor,
          },
          "&.Mui-disabled": {
            color: inputTextColor,
            WebkitTextFillColor: inputTextColor,
          },
          "&.Mui-disabled .MuiOutlinedInput-notchedOutline": {
            borderColor: inputBorderColor,
          },
          "& input.Mui-disabled": {
            WebkitTextFillColor: inputTextColor,
          },
        },
      },
    },
    MuiInputLabel: {
      styleOverrides: {
        root: {
          color: inputTextColor,
          "&.Mui-disabled": { color: inputTextColor },
        },
      },
    },
    MuiSelect: {
      styleOverrides: {
        select: {
          color: inputTextColor,
          "&.Mui-disabled": {
            color: inputTextColor,
            WebkitTextFillColor: inputTextColor,
          },
        },
        icon: {
          color: inputTextColor,
          "&.Mui-disabled": { color: inputTextColor },
        },
      },
    },
    MuiToggleButton: {
      styleOverrides: {
        root: {
          color: interactiveColor,
          borderColor,
          "&.Mui-selected": {
            color: interactiveColor,
          },
          "&.Mui-disabled": {
            color: interactiveColor,
            borderColor,
            opacity: 0.55,
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: { root: { border: `1px solid ${borderColor}` } },
    },
  };
}

/**
 * Light — the canonical ATI appearance and default theme.
 *
 * Preserves the current-main visual foundation as closely as practical:
 * light neutral surfaces, dark steel blue primary, table-ready spacing.
 */
const LIGHT_TOKENS: AtiSemanticTokens = {
  surface: { primary: "#ffffff", elevated: "#ffffff", subtle: "#f4f6f8" },
  text: { primary: "#1f2328", secondary: "#5f6368", technical: "#1f2328" },
  accent: { primary: PRIMARY_COLOR, secondary: "#12648c" },
  border: { default: "#d7dbe0", emphasis: "#8f98a3" },
  selection: {
    background: "rgba(27, 94, 140, 0.08)",
    border: "rgba(27, 94, 140, 0.8)",
  },
  status: {
    success: "#14643a",
    warning: WARNING_COLOR,
    critical: ERROR_COLOR,
    info: "#12648c",
  },
  graph: {
    canvas: "#f4f6f8",
    pattern: "#c6ccd4",
    node: {
      background: "#ffffff",
      border: PRIMARY_COLOR,
      text: "#1f2328",
      selected: PRIMARY_COLOR,
    },
    edge: { default: "#b1b1b7", label: "#ffffff", selected: "#555555" },
  },
  map: {
    container: "#e8eaee",
    overlay: "rgba(255, 255, 255, 0.85)",
    border: "#d7dbe0",
  },
  focus: { visible: PRIMARY_COLOR },
};

const LIGHT_THEME = createTheme({
  palette: {
    primary: { main: PRIMARY_COLOR, dark: "#13466a", light: "#3d84bb" },
    warning: { main: WARNING_COLOR },
    error: { main: ERROR_COLOR },
    success: { main: "#14643a" },
    info: { main: "#12648c" },
    background: { default: "#f4f6f8", paper: "#ffffff" },
    divider: "#d7dbe0",
    text: { primary: "#1f2328", secondary: "#5f6368" },
  },
  shape: { borderRadius: 6 },
  typography: themeTypography(),
  components: themeComponents(
    LIGHT_TOKENS.border.default,
    LIGHT_TOKENS.accent.primary,
    LIGHT_TOKENS.border.default,
    LIGHT_TOKENS.text.primary,
    "light",
  ),
  ati: LIGHT_TOKENS,
});

/**
 * Dark — professional dark analyst workbench.
 *
 * Neutral dark surfaces, readable text, a restrained blue/cyan accent and
 * clear status semantics.
 */
const DARK_TOKENS: AtiSemanticTokens = {
  surface: { primary: "#1c2026", elevated: "#1c2026", subtle: "#14171c" },
  text: { primary: "#e8eaed", secondary: "#a5aeb9", technical: "#c8d2dc" },
  accent: { primary: "#4a8dc8", secondary: "#4a9fd0" },
  border: { default: "#2a3038", emphasis: "#465875" },
  selection: {
    background: "rgba(74, 141, 200, 0.16)",
    border: "rgba(74, 141, 200, 0.9)",
  },
  status: {
    success: "#3f9c6d",
    warning: "#c7903d",
    critical: "#e05b56",
    info: "#4a9fd0",
  },
  graph: {
    canvas: "#14171c",
    pattern: "#333b45",
    node: {
      background: "#1c2026",
      border: "#4a8dc8",
      text: "#e8eaed",
      selected: "#6ba4dc",
    },
    edge: { default: "#8a93a0", label: "#1c2026", selected: "#c8d2dc" },
  },
  map: {
    container: "#101419",
    overlay: "rgba(28, 32, 38, 0.85)",
    border: "#2a3038",
  },
  focus: { visible: "#6ba4dc" },
};

const DARK_THEME = createTheme({
  palette: {
    primary: { main: "#4a8dc8", dark: "#31618f", light: "#6ba4dc" },
    warning: { main: "#c7903d" },
    error: { main: "#e05b56" },
    success: { main: "#3f9c6d" },
    info: { main: "#4a9fd0" },
    background: { default: "#14171c", paper: "#1c2026" },
    divider: "#2a3038",
    text: { primary: "#e8eaed", secondary: "#a5aeb9" },
  },
  shape: { borderRadius: 6 },
  typography: themeTypography(),
  components: themeComponents(
    DARK_TOKENS.border.default,
    DARK_TOKENS.accent.primary,
    "#ffffff",
    "#ffffff",
    "dark",
  ),
  ati: DARK_TOKENS,
});

/**
 * Wargames — restrained technical terminal workbench.
 *
 * Near-black surfaces, green/amber technical accents, sharper borders and
 * selective monospace for technical values. No scan lines, blinking, CRT
 * distortion, sound, animated noise, or all-monospace prose.
 */
const WARGAMES_TOKENS: AtiSemanticTokens = {
  surface: { primary: "#10150f", elevated: "#10150f", subtle: "#0a0d0a" },
  text: { primary: "#d4dcc9", secondary: "#94a08b", technical: "#b8c9a8" },
  accent: { primary: "#41a85f", secondary: "#3fb3a0" },
  border: { default: "#2a372a", emphasis: "#41a85f" },
  selection: {
    background: "rgba(65, 168, 95, 0.14)",
    border: "rgba(65, 168, 95, 0.9)",
  },
  status: {
    success: "#41a85f",
    warning: "#d9a441",
    critical: "#d9534f",
    info: "#3fb3a0",
  },
  graph: {
    canvas: "#0a0d0a",
    pattern: "#1f2a1f",
    node: {
      background: "#10150f",
      border: "#41a85f",
      text: "#d4dcc9",
      selected: "#5fc47c",
    },
    edge: { default: "#3f4f3f", label: "#10150f", selected: "#8fc79b" },
  },
  map: {
    container: "#070a07",
    overlay: "rgba(16, 21, 15, 0.85)",
    border: "#2a372a",
  },
  focus: { visible: "#5fc47c" },
};

const WARGAMES_THEME = createTheme({
  palette: {
    primary: { main: "#41a85f", dark: "#2e7d46", light: "#5fc47c" },
    warning: { main: "#d9a441" },
    error: { main: "#d9534f" },
    success: { main: "#41a85f" },
    info: { main: "#3fb3a0" },
    background: { default: "#0a0d0a", paper: "#10150f" },
    divider: "#1f2a1f",
    text: { primary: "#d4dcc9", secondary: "#94a08b" },
  },
  shape: { borderRadius: 3 },
  typography: themeTypography(),
  components: themeComponents(
    WARGAMES_TOKENS.border.default,
    WARGAMES_TOKENS.accent.primary,
    "#ffffff",
    "#ffffff",
    "dark",
  ),
  ati: WARGAMES_TOKENS,
});

/**
 * Control Room — navy/black displays workbench.
 *
 * Cyan/blue displays, thin illuminated boundaries, compact information-dense
 * panels and restrained warning colors. No government agency branding,
 * logos or seals.
 */
const CONTROL_ROOM_TOKENS: AtiSemanticTokens = {
  surface: { primary: "#0f1a2c", elevated: "#0f1a2c", subtle: "#0a1220" },
  text: { primary: "#d8e6ee", secondary: "#8fa7b8", technical: "#a5d3e6" },
  accent: { primary: "#2fb8d9", secondary: "#57cfe8" },
  border: { default: "#1e3552", emphasis: "#2fb8d9" },
  selection: {
    background: "rgba(47, 184, 217, 0.14)",
    border: "rgba(47, 184, 217, 0.9)",
  },
  status: {
    success: "#3ec97a",
    warning: "#e0963d",
    critical: "#e2554f",
    info: "#2fb8d9",
  },
  graph: {
    canvas: "#0a1220",
    pattern: "#1a2c44",
    node: {
      background: "#0f1a2c",
      border: "#2fb8d9",
      text: "#d8e6ee",
      selected: "#57cfe8",
    },
    edge: { default: "#2c4a6e", label: "#0f1a2c", selected: "#7fd4ea" },
  },
  map: {
    container: "#060b14",
    overlay: "rgba(15, 26, 44, 0.85)",
    border: "#1e3552",
  },
  focus: { visible: "#57cfe8" },
};

const CONTROL_ROOM_THEME = createTheme({
  palette: {
    primary: { main: "#2fb8d9", dark: "#1e7fa6", light: "#57cfe8" },
    warning: { main: "#e0963d" },
    error: { main: "#e2554f" },
    success: { main: "#3ec97a" },
    info: { main: "#2fb8d9" },
    background: { default: "#0a1220", paper: "#0f1a2c" },
    divider: "#152438",
    text: { primary: "#d8e6ee", secondary: "#8fa7b8" },
  },
  shape: { borderRadius: 2 },
  typography: themeTypography(),
  components: themeComponents(
    CONTROL_ROOM_TOKENS.border.default,
    CONTROL_ROOM_TOKENS.accent.primary,
    "#ffffff",
    "#ffffff",
    "dark",
  ),
  ati: CONTROL_ROOM_TOKENS,
});

/**
 * Stable prebuilt registry of every bounded ATI appearance.
 *
 * Themes are built once at module load and never rebuilt per render. The
 * record is keyed by the exact finite appearance set; the provider boundary
 * never accepts unvalidated values.
 */
export const ATI_THEMES: Readonly<Record<AppearancePreference, Theme>> = {
  light: LIGHT_THEME,
  dark: DARK_THEME,
  wargames: WARGAMES_THEME,
  "control-room": CONTROL_ROOM_THEME,
};

/**
 * Resolve the stable theme for an appearance.
 *
 * The type is bounded, but the registry lookup stays defensive so an
 * unexpected runtime value can never crash the provider: unknown values
 * fall back to the canonical Light theme.
 */
export function createAtiTheme(appearance: AppearancePreference): Theme {
  return ATI_THEMES[appearance] ?? ATI_THEMES[DEFAULT_APPEARANCE];
}
