// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Semantic theme factory contracts (PR 31F-4 T01..T09).
//
// Every bounded appearance must produce a complete, typed semantic token
// contract with no gaps and no theme-name branching at call sites. Assert
// structural completeness rather than brittle snapshots of whole MUI theme
// objects.

import { describe, expect, it } from "vitest";

import { DEFAULT_APPEARANCE } from "./appearance";
import type { AppearancePreference } from "./appearance";
import { ATI_THEMES, createAtiTheme } from "./theme";
import type { AtiSemanticTokens } from "./theme";

/** Every leaf token path the contract requires. */
const REQUIRED_TOKEN_PATHS: readonly string[] = [
  "surface.primary",
  "surface.elevated",
  "surface.subtle",
  "text.primary",
  "text.secondary",
  "text.technical",
  "accent.primary",
  "accent.secondary",
  "border.default",
  "border.emphasis",
  "selection.background",
  "selection.border",
  "status.success",
  "status.warning",
  "status.critical",
  "status.info",
  "graph.canvas",
  "graph.pattern",
  "graph.node.background",
  "graph.node.border",
  "graph.node.text",
  "graph.node.selected",
  "graph.edge.default",
  "graph.edge.label",
  "graph.edge.selected",
  "map.container",
  "map.overlay",
  "map.border",
  "focus.visible",
];

function tokenAt(tokens: AtiSemanticTokens, path: string): unknown {
  let value: unknown = tokens;
  for (const part of path.split(".")) {
    if (typeof value !== "object" || value === null) {
      return undefined;
    }
    value = (value as Record<string, unknown>)[part];
  }
  return value;
}

function expectCompleteTokens(tokens: AtiSemanticTokens): void {
  for (const path of REQUIRED_TOKEN_PATHS) {
    const value = tokenAt(tokens, path);
    expect(
      typeof value === "string" && value.trim().length > 0,
      `token ${path} must be a non-empty string`,
    ).toBe(true);
  }
}

describe("Semantic theme factory (T01..T09)", () => {
  it("T09: the default appearance resolves to the Light theme", () => {
    expect(DEFAULT_APPEARANCE).toBe("light");
    expect(createAtiTheme(DEFAULT_APPEARANCE)).toBe(ATI_THEMES.light);
  });

  it("T09: every bounded appearance has a stable prebuilt theme", () => {
    for (const [appearance, theme] of Object.entries(ATI_THEMES)) {
      const preference = appearance as AppearancePreference;
      expect(theme, `theme for ${appearance}`).toBe(createAtiTheme(preference));
      expect(theme.ati).toBeDefined();
    }
    expect(Object.keys(ATI_THEMES).sort()).toEqual(
      ["control-room", "dark", "light", "wargames"],
    );
  });

  it("T01: Light defines the complete semantic token contract", () => {
    expectCompleteTokens(ATI_THEMES.light.ati);
  });

  it("T02: Dark defines the complete semantic token contract", () => {
    expectCompleteTokens(ATI_THEMES.dark.ati);
  });

  it("T03: Wargames defines the complete semantic token contract", () => {
    expectCompleteTokens(ATI_THEMES.wargames.ati);
  });

  it("T04: Control Room defines the complete semantic token contract", () => {
    expectCompleteTokens(ATI_THEMES["control-room"].ati);
  });

  it("T05: every theme defines a visible keyboard-focus token", () => {
    for (const theme of Object.values(ATI_THEMES)) {
      expect(theme.ati.focus.visible.length).toBeGreaterThan(0);
    }
  });

  it("T06: every theme defines all four status tokens", () => {
    for (const theme of Object.values(ATI_THEMES)) {
      const status = theme.ati.status;
      expect(status.success.length).toBeGreaterThan(0);
      expect(status.warning.length).toBeGreaterThan(0);
      expect(status.critical.length).toBeGreaterThan(0);
      expect(status.info.length).toBeGreaterThan(0);
    }
  });

  it("T07: every theme defines complete graph tokens (canvas/node/edge)", () => {
    for (const theme of Object.values(ATI_THEMES)) {
      const graph = theme.ati.graph;
      expect(graph.canvas.length).toBeGreaterThan(0);
      expect(graph.node.selected.length).toBeGreaterThan(0);
      expect(graph.edge.default.length).toBeGreaterThan(0);
      expect(graph.edge.selected.length).toBeGreaterThan(0);
      expect(graph.edge.label.length).toBeGreaterThan(0);
    }
  });

  it("T08: every theme defines complete map tokens", () => {
    for (const theme of Object.values(ATI_THEMES)) {
      const map = theme.ati.map;
      expect(map.container.length).toBeGreaterThan(0);
      expect(map.overlay.length).toBeGreaterThan(0);
      expect(map.border.length).toBeGreaterThan(0);
    }
  });

  it("accent/selection/border token categories stay complete in every theme", () => {
    for (const theme of Object.values(ATI_THEMES)) {
      expectCompleteTokens(theme.ati);
    }
  });

  it("contained primary actions have explicit readable foregrounds", () => {
    for (const theme of Object.values(ATI_THEMES)) {
      expect(theme.palette.primary.contrastText).not.toBe(theme.palette.primary.main);
      expect(theme.palette.primary.contrastText.length).toBeGreaterThan(0);
    }
  });

  it("Light preserves the historical primary color", () => {
    expect(ATI_THEMES.light.palette.primary.main).toBe("#1b5e8c");
    expect(ATI_THEMES.light.ati.accent.primary).toBe("#1b5e8c");
  });
});
