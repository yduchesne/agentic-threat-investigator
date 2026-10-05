// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only

import { screen } from "@testing-library/react";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { describe, expect, it } from "vitest";

import { AppProviders } from "../app/AppProviders";
import { freshQueryClient, renderProviders } from "../test/render";
import { CompactId } from "./CompactId";

/** Render one element under a minimal router + production providers. */
function renderRouted(ui: ReactElement) {
  const router = createMemoryRouter(
    [{ path: "/", element: ui }],
    { initialEntries: ["/"] },
  );
  return render(
    <AppProviders queryClient={freshQueryClient()}>
      <RouterProvider router={router} useTransitions={false} />
    </AppProviders>,
  );
}

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

  it("L01/L02/L03: a linked ID renders once with the exact href and a copy control", () => {
    const id = "40000000-0000-4000-8000-000000000001";
    renderRouted(
      <CompactId
        id={id}
        label="Evidence ID"
        to={`/investigations/inv-1/evidence/${id}`}
      />,
    );

    const link = screen.getByRole("link", { name: "Evidence ID" });
    expect(link).toHaveAttribute(
      "href",
      `/investigations/inv-1/evidence/${id}`,
    );
    // The visible short ID appears exactly once (not duplicated by copy).
    expect(screen.getAllByText("40000000")).toHaveLength(1);
    // The full UUID stays available and the copy control copies it.
    expect(screen.getByTitle(id)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Copy ID 40000000" }),
    ).toBeInTheDocument();
  });
});
