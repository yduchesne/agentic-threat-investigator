// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only

import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { renderProviders } from "../test/render";
import { CompactId } from "./CompactId";

describe("CompactId", () => {
  it("uses an accessible icon-only copy action instead of visible Copy text", () => {
    renderProviders(
      <CompactId
        id="40000000-0000-4000-8000-000000000001"
        label="Evidence ID"
      />,
    );

    expect(screen.getByText("40000000")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Copy ID 40000000" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Copy")).toBeNull();
  });
});
