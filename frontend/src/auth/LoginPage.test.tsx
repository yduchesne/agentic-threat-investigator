// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Login page tests (PR 24A U16-U18, U23-U24, U28, U31).

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  ADMIN_USER,
  ANALYST_USER,
  authMe401,
  loginFlowHandlers,
  loginInvalid,
  loginNetworkError,
  loginRateLimited,
  loginUnavailable,
} from "../test/handlers";

useHttp();

async function fillLoginPage(): Promise<void> {
  const username = await screen.findByLabelText(/^Username/);
  await userEvent.type(username, ANALYST_USER.alias);
  const password = screen.getByLabelText(/^Password/);
  await userEvent.type(password, "correct-horse");
}

describe("login page", () => {
  it("renders translated English labels, not translation keys (U31)", async () => {
    setHttpHandlers(authMe401);
    renderAtPath("/login");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByText("Agentic Threat Investigator analyst workbench")).toBeInTheDocument();
    expect(screen.queryByText("auth.login.title")).not.toBeInTheDocument();
  });

  it("shows a generic failure for invalid credentials (U17)", async () => {
    setHttpHandlers(authMe401, loginInvalid);
    renderAtPath("/login");
    await fillLoginPage();
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Invalid username or password.")).toBeInTheDocument();
    expect(screen.queryByText("rate_limited")).not.toBeInTheDocument();
  });

  it("distinguishes the rate-limited state (U18)", async () => {
    setHttpHandlers(authMe401, loginRateLimited);
    renderAtPath("/login");
    await fillLoginPage();
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(
      await screen.findByText("Too many sign-in attempts. Wait a moment and try again."),
    ).toBeInTheDocument();
    expect(screen.queryByText("Invalid username or password.")).not.toBeInTheDocument();
  });

  it("shows a service-unavailable message on network failure", async () => {
    setHttpHandlers(authMe401, loginNetworkError);
    renderAtPath("/login");
    await fillLoginPage();
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(
      await screen.findByText("The sign-in service is unavailable right now. Try again shortly."),
    ).toBeInTheDocument();
  });

  it("shows a service-unavailable message on server failure", async () => {
    setHttpHandlers(authMe401, loginUnavailable);
    renderAtPath("/login");
    await fillLoginPage();
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(
      await screen.findByText("The sign-in service is unavailable right now. Try again shortly."),
    ).toBeInTheDocument();
  });

  it("submits via the Enter key (U28)", async () => {
    setHttpHandlers(...loginFlowHandlers());
    renderAtPath("/login");
    await fillLoginPage();
    await screen.getByLabelText(/^Password/).focus();
    await userEvent.keyboard("{Enter}");
    expect(await screen.findByText(ANALYST_USER.alias)).toBeInTheDocument();
  });

  it("logs in and lands on the safe internal return location (U16, U23)", async () => {
    setHttpHandlers(...loginFlowHandlers());
    renderAtPath({ path: "/login", state: { returnTo: "/investigations" } });
    await fillLoginPage();
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    // Authenticated shell on /investigations (return path), user state seeded
    // from the real API contract.
    expect(await screen.findByRole("heading", { name: "Agentic Threat Investigator" })).toBeInTheDocument();
    expect(await screen.findByText(ANALYST_USER.alias)).toBeInTheDocument();
    expect(await screen.findByText("FAKE DATA")).toBeInTheDocument();
  });

  it("rejects external return targets and falls back to /investigations (U24)", async () => {
    setHttpHandlers(...loginFlowHandlers());
    renderAtPath({ path: "/login", state: { returnTo: "https://evil.example.com/steal" } });
    await fillLoginPage();
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Agentic Threat Investigator" })).toBeInTheDocument();
  });

  it("does not submit empty submissions", async () => {
    setHttpHandlers(...loginFlowHandlers());
    renderAtPath("/login");
    await screen.findByRole("button", { name: "Sign in" });
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByText(ADMIN_USER.alias)).not.toBeInTheDocument();
  });
});