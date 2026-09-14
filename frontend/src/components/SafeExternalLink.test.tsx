// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Safe external link tests (PR 24C E04, E05, E06).
//
// Only explicit HTTP(S) URLs become links with safe attributes; unsafe
// schemes and markup-bearing text render as escaped plain content.

import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { renderProviders } from "../test/render";
import { isSafeHttpUrl, SafeExternalLink } from "./SafeExternalLink";

describe("SafeExternalLink", () => {
  it("renders explicit HTTPS URLs as safe links (E04)", () => {
    renderProviders(
      <SafeExternalLink url="https://example.invalid/evidence/1" ariaLabel="Source URL" />,
    );
    const link = screen.getByRole("link", { name: "Source URL" });
    expect(link).toHaveAttribute("href", "https://example.invalid/evidence/1");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noreferrer");
    expect(isSafeHttpUrl("http://example.invalid")).toBe(true);
  });

  it("never links unsafe URL schemes (E05)", () => {
    renderProviders(
      <SafeExternalLink url="javascript:alert(1)" ariaLabel="Source URL" />,
    );
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByText("javascript:alert(1)")).toBeInTheDocument();
    expect(isSafeHttpUrl("javascript:alert(1)")).toBe(false);
    expect(isSafeHttpUrl("data:text/plain;base64,AAAA")).toBe(false);
    expect(isSafeHttpUrl(null)).toBe(false);
    expect(isSafeHttpUrl("not a url")).toBe(false);
  });

  it("escapes markup instead of rendering it (E06)", () => {
    renderProviders(
      <SafeExternalLink url="<img src=x onerror=alert(1)>" ariaLabel="Source URL" />,
    );
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  });
});