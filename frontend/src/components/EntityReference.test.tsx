// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// EntityReference presentation tests (PR 31F-5 D1/D2; EP01/EP02/EP05).
//
// The primitive is presentation-only: value primary, translated type
// adjacent, optional technical ID secondary. It never fetches and never
// owns Pivot behavior.

import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { renderProviders } from "../test/render";
import { EntityReference } from "./EntityReference";

describe("EntityReference", () => {
  it("renders value primary with the translated type immediately adjacent", () => {
    renderProviders(
      <EntityReference
        value="update-package.test"
        type="domain"
      />,
    );
    expect(screen.getByText("update-package.test")).toBeInTheDocument();
    expect(screen.getByText("Domain")).toBeInTheDocument();
  });

  it("renders the value alone when the type is missing (EP02)", () => {
    const { result } = renderProviders(
      <EntityReference value="update-package.test" type={null} />,
    );
    expect(screen.getByText("update-package.test")).toBeInTheDocument();
    expect(result.container.querySelectorAll("code")).toHaveLength(0);
  });

  it("renders only the unavailable marker when the value is missing", () => {
    const { result } = renderProviders(
      <EntityReference value={undefined} type="domain" />,
    );
    expect(screen.getByText("—")).toBeInTheDocument();
    expect(result.container.textContent).not.toContain("Domain");
  });

  it("renders the canonical ID as secondary technical identity (EP05)", () => {
    const { result } = renderProviders(
      <EntityReference
        value="malware.badloader_v2"
        type="malware"
        id="40000000-0000-4000-8000-000000000102"
      />,
    );
    expect(screen.getByText("malware.badloader_v2")).toBeInTheDocument();
    expect(screen.getByText("Malware")).toBeInTheDocument();
    expect(screen.getByTitle("40000000-0000-4000-8000-000000000102")).toBeInTheDocument();
    // The value text appears before the compact UUID in document order.
    const text = result.container.textContent ?? "";
    expect(text.indexOf("malware.badloader_v2")).toBeLessThan(text.indexOf("40000000"));
  });
});
