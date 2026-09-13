// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// RequireAuth guard tests (PR 24A U13-U15, U19, U29).

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { delay, http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  ANALYST_USER,
  authMe401,
  authMe500,
  authMeNetworkError,
  authMeSuccess,
  loginFlowHandlers,
  runtimeFake,
} from "../test/handlers";

useHttp();

describe("RequireAuth", () => {
  it("shows the authenticated shell on /auth/me 200 (U13)", async () => {
    setHttpHandlers(authMeSuccess, runtimeFake);
    renderAtPath("/investigations");
    expect(await screen.findByText(ANALYST_USER.alias)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Sign in" })).not.toBeInTheDocument();
  });

  it("treats /auth/me 401 as unauthenticated and sends the user to /login (U14)", async () => {
    setHttpHandlers(authMe401);
    renderAtPath("/investigations");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByText(ANALYST_USER.alias)).not.toBeInTheDocument();
  });

  it("shows a recoverable error surface on /auth/me 500, never login (U15)", async () => {
    setHttpHandlers(authMe500);
    renderAtPath("/investigations");
    expect(await screen.findByText("Unable to verify session")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Sign in" })).not.toBeInTheDocument();
    expect(screen.queryByText(ANALYST_USER.alias)).not.toBeInTheDocument();
  });

  it("shows a recoverable error surface on /auth/me network failure (U15)", async () => {
    setHttpHandlers(authMeNetworkError);
    renderAtPath("/investigations");
    expect(await screen.findByText("Unable to verify session")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Sign in" })).not.toBeInTheDocument();
  });

  it("never flashes protected content while auth state is loading (U29)", async () => {
    // A delayed /auth/me keeps the query pending long enough to assert the
    // loading surface (and absence of protected content).
    setHttpHandlers(
      http.get("*/api/v1/auth/me", async () => {
        await delay(120);
        return HttpResponse.json(
          { error: { code: "authentication_required", message: "auth required", request_id: "rq" } },
          { status: 401 },
        );
      }),
    );
    renderAtPath("/investigations");
    expect(await screen.findByText("Verifying session…")).toBeInTheDocument();
    expect(screen.queryByText(ANALYST_USER.alias)).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Investigations" })).not.toBeInTheDocument();
    // The delayed response resolves to a 401 unauthenticated state.
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });

  it("clears the session state after logout (U19)", async () => {
    setHttpHandlers(...loginFlowHandlers());
    renderAtPath("/login");
    await userEvent.type(await screen.findByLabelText(/^Username/), ANALYST_USER.alias);
    await userEvent.type(screen.getByLabelText(/^Password/), "correct-horse");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText(ANALYST_USER.alias)).toBeInTheDocument();

    const signOut = await screen.findByRole("button", { name: "Sign out" });
    signOut.click();
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByText(ANALYST_USER.alias)).not.toBeInTheDocument();
    // The auth server state was invalidated; no protected shell remains.
    expect(screen.queryByText("FAKE DATA")).not.toBeInTheDocument();
  });
});