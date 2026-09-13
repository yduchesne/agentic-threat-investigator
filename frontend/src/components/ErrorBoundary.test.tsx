// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Global render error boundary tests (PR 24A U35).

import { screen } from "@testing-library/react";
import type { ReactElement } from "react";
import { describe, expect, it } from "vitest";

import { AppErrorBoundary } from "./ErrorBoundary";
import { renderProviders } from "../test/render";

/** A component that always throws while rendering. */
function ExplodingComponent(): ReactElement {
  throw new Error("exploded-internals-xyzzy");
}

describe("AppErrorBoundary", () => {
  it("renders a safe surface and never exposes the thrown message (U35)", async () => {
    renderProviders(
      <AppErrorBoundary title="Something went wrong" message="The application hit an unexpected problem. Your session is unaffected." reloadLabel="Reload page">
        <ExplodingComponent />
      </AppErrorBoundary>,
    );
    expect(await screen.findByText("Something went wrong")).toBeInTheDocument();
    expect(
      screen.getByText("The application hit an unexpected problem. Your session is unaffected."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/exploded-internals/)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reload page" })).toBeInTheDocument();
  });
});