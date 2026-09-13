// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// FAKE DATA runtime indicator tests (PR 24A U25-U27).

import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  ANALYST_USER,
  authMeSuccess,
  runtimeFailure,
  runtimeFake,
  runtimeNetworkError,
  runtimeProduction,
} from "../test/handlers";

useHttp();

describe("FakeDataBanner", () => {
  it("renders a persistent textual FAKE DATA indicator in fake mode (U25)", async () => {
    setHttpHandlers(authMeSuccess, runtimeFake);
    renderAtPath("/investigations");
    expect(await screen.findByText("FAKE DATA")).toBeInTheDocument();
    expect(
      screen.getByText("Running against deterministic local fake intelligence sources. No live external data is used."),
    ).toBeInTheDocument();
  });

  it("renders no fake indicator in production mode (U26)", async () => {
    setHttpHandlers(authMeSuccess, runtimeProduction);
    renderAtPath("/investigations");
    expect(await screen.findByText(ANALYST_USER.alias)).toBeInTheDocument();
    expect(screen.queryByText("FAKE DATA")).not.toBeInTheDocument();
  });

  it("shows a bounded warning and keeps the shell usable on runtime failure (U27)", async () => {
    setHttpHandlers(authMeSuccess, runtimeFailure);
    renderAtPath("/investigations");
    expect(await screen.findByText("Runtime mode unavailable")).toBeInTheDocument();
    expect(screen.queryByText("FAKE DATA")).not.toBeInTheDocument();
    // The shell stays fully usable; nothing silently assumes production.
    expect(await screen.findByRole("heading", { name: "Investigations" })).toBeInTheDocument();
    expect(await screen.findByText(ANALYST_USER.alias)).toBeInTheDocument();
  });

  it("shows the bounded warning on runtime network failure", async () => {
    setHttpHandlers(authMeSuccess, runtimeNetworkError);
    renderAtPath("/investigations");
    expect(await screen.findByText("Runtime mode unavailable")).toBeInTheDocument();
    expect(screen.queryByText("FAKE DATA")).not.toBeInTheDocument();
  });
});