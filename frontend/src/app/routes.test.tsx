// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Route topology tests through the real route table (PR 24A U20-U22, U30).

import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  ANALYST_USER,
  authMe401,
  authMeSuccess,
  runtimeFake,
} from "../test/handlers";

useHttp();

describe("route topology", () => {
  it("redirects protected /investigations to /login when unauthenticated (U20)", async () => {
    setHttpHandlers(authMe401);
    renderAtPath("/investigations");
    await screen.findByRole("heading", { name: "Sign in" });
    expect(screen.queryByText("FAKE DATA")).not.toBeInTheDocument();
    expect(screen.queryByText(ANALYST_USER.alias)).not.toBeInTheDocument();
  });

  it("renders the authenticated shell for a real /auth/me user (U21)", async () => {
    setHttpHandlers(authMeSuccess, runtimeFake);
    renderAtPath("/investigations");
    expect(
      await screen.findByRole("heading", { name: "Agentic Threat Investigator" }),
    ).toBeInTheDocument();
    expect(await screen.findByText(ANALYST_USER.alias)).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "Investigations" })).toBeInTheDocument();
  });

  it("redirects the authenticated / route to /investigations", async () => {
    setHttpHandlers(authMeSuccess, runtimeFake);
    renderAtPath("/");
    expect(
      await screen.findByRole("heading", { name: "Investigations" }),
    ).toBeInTheDocument();
  });

  it("redirects authenticated /login to /investigations (U22)", async () => {
    setHttpHandlers(authMeSuccess, runtimeFake);
    renderAtPath("/login");
    expect(
      await screen.findByRole("heading", { name: "Investigations" }),
    ).toBeInTheDocument();
  });

  it("renders a safe 404 for unknown paths (U30)", async () => {
    // NotFoundPage performs no API request.
    setHttpHandlers();
    renderAtPath("/definitely-not-a-route");
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
    expect(await screen.findByText("The requested page does not exist.")).toBeInTheDocument();
  });
});