// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Create Investigation tests (PR 24B U08-U19, §11-§13).

import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import { CSRF_COOKIE_NAME } from "../api/csrf";
import type { CreateRequestRecord } from "../test/handlers";
import {
  authMeSuccess,
  buildInvestigation,
  createInvestigationHandler,
  investigationDetailHandler,
  investigationsListHandler,
  jsonResponse,
  runtimeFake,
} from "../test/handlers";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import { IDEMPOTENCY_KEY_GRAMMAR } from "./idempotency";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];
const NEW_INVESTIGATION_ID = "60000000-0000-4000-8000-000000000001";

/** Simulate the real authenticated session: the CSRF cookie set at login. */
function installCsrfCookie(): void {
  document.cookie = `${CSRF_COOKIE_NAME}=test-csrf-token`;
}

/** Fill the required objective + one indicator (and wait for the render). */
async function fillRequiredForm(): Promise<void> {
  await screen.findByRole("button", { name: "Submit" });
  installCsrfCookie();
  await userEvent.click(screen.getByRole("button", { name: "Add indicator" }));
  await userEvent.type(screen.getByLabelText(/^Objective/), "assess the delivery domain");
  await userEvent.type(
    screen.getByLabelText("Indicator value 1"),
    "update-package.test",
  );
}

/** Timed wait until at least `expected` create requests were recorded. */
async function waitForRequests(
  requests: CreateRequestRecord[],
  expected = 1,
): Promise<void> {
  const deadline = Date.now() + 3000;
  while (requests.length < expected && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  expect(requests.length).toBeGreaterThanOrEqual(expected);
}

function lastKey(requests: CreateRequestRecord[]): string {
  const request = requests.at(-1);
  expect(request?.idempotencyKey).toBeTruthy();
  return request?.idempotencyKey ?? "";
}

describe("Create Investigation", () => {
  it("rejects an empty objective locally (U08)", async () => {
    setHttpHandlers(...AUTH, investigationsListHandler([]));
    renderAtPath("/investigations/new");
    await screen.findByRole("button", { name: "Submit" });
    installCsrfCookie();
    await userEvent.type(screen.getByLabelText("Indicator value 1"), "example.com");
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect(await screen.findByText("Objective is required.")).toBeInTheDocument();
  });

  it("rejects a submission without any indicator value (U09)", async () => {
    setHttpHandlers(...AUTH, investigationsListHandler([]));
    renderAtPath("/investigations/new");
    await screen.findByRole("button", { name: "Submit" });
    installCsrfCookie();
    await userEvent.type(screen.getByLabelText(/^Objective/), "assess a domain");
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect(
      await screen.findByText("At least one indicator with a value is required."),
    ).toBeInTheDocument();
  });

  it("adds and removes indicator rows with accessible controls (U10)", async () => {
    setHttpHandlers(...AUTH, investigationsListHandler([]));
    renderAtPath("/investigations/new");
    await screen.findByRole("button", { name: "Submit" });

    const removeFirst = screen.getByRole("button", { name: "Remove indicator 1" });
    expect(removeFirst).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Add indicator" }));
    expect(screen.getByLabelText("Indicator value 2")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove indicator 1" })).toBeEnabled();

    await userEvent.click(screen.getByRole("button", { name: "Remove indicator 2" }));
    expect(screen.queryByLabelText("Indicator value 2")).not.toBeInTheDocument();
  });

  it("submits the exact generated EntityType enum after selection (U11)", async () => {
    const { handler, requests } = createInvestigationHandler();
    setHttpHandlers(...AUTH, investigationsListHandler([]), handler);
    renderAtPath("/investigations/new");
    await screen.findByRole("button", { name: "Submit" });
    installCsrfCookie();
    await userEvent.type(screen.getByLabelText(/^Objective/), "assess an IP");
    // Change the indicator type from the default domain to ip_address.
    const combobox = screen.getByRole("combobox");
    await userEvent.click(combobox);
    const listbox = await screen.findByRole("listbox");
    await userEvent.click(await within(listbox).findByText("IP address"));
    await userEvent.type(screen.getByLabelText("Indicator value 1"), "203.0.113.7");
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));

    await waitForRequests(requests);
    const body = requests.at(-1)?.body as {
      indicators?: Array<{ type: string; value: string }>;
      objective?: string;
    };
    expect(body?.indicators?.[0]?.type).toBe("ip_address");
    expect(body?.indicators?.[0]?.value).toBe("203.0.113.7");
    expect(body?.objective).toBe("assess an IP");
  });

  it("generates a cryptographic key on the first submit (U12)", async () => {
    const { handler, requests } = createInvestigationHandler();
    setHttpHandlers(...AUTH, investigationsListHandler([]), handler);
    renderAtPath("/investigations/new");
    await fillRequiredForm();
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    await waitForRequests(requests);
    expect(lastKey(requests)).toMatch(IDEMPOTENCY_KEY_GRAMMAR);
  });

  it(
    "reuses the same key for a transport-uncertain retry (U13)",
    async () => {
      const create = createInvestigationHandler({ failWith: "transport" });
      setHttpHandlers(
        ...AUTH,
        investigationsListHandler([]),
        investigationDetailHandler(
          buildInvestigation({
            id: NEW_INVESTIGATION_ID,
            status: "pending",
            objective: "assess the delivery domain",
          }),
        ),
        create.handler,
      );
      renderAtPath("/investigations/new");
      await fillRequiredForm();
      await userEvent.click(screen.getByRole("button", { name: "Submit" }));
      expect(
        await screen.findByText(
          "Submission status is uncertain. Retry will safely reuse the same submission identifier.",
        ),
      ).toBeInTheDocument();
      expect(create.requests).toHaveLength(1);
      const firstKey = lastKey(create.requests);

      create.failWith("ok");
      await userEvent.click(screen.getByRole("button", { name: "Submit" }));
      await waitForRequests(create.requests, 2);
      expect(lastKey(create.requests)).toBe(firstKey);
    },
    20_000,
  );

  /** Run one uncertain-first retry flow and return the two observed keys. */
  async function runUncertainRetry(
    initialFail:
      | "server500"
      | "server502"
      | "server503"
      | "malformed500",
  ): Promise<{ firstKey: string; secondKey: string }> {
    const create = createInvestigationHandler({ failWith: initialFail });
    setHttpHandlers(
      ...AUTH,
      investigationsListHandler([]),
      investigationDetailHandler(
        buildInvestigation({
          id: NEW_INVESTIGATION_ID,
          status: "pending",
          objective: "assess the delivery domain",
        }),
      ),
      create.handler,
    );
    renderAtPath("/investigations/new");
    await fillRequiredForm();
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect(
      await screen.findByText(
        "Submission status is uncertain. Retry will safely reuse the same submission identifier.",
      ),
    ).toBeInTheDocument();
    expect(create.requests).toHaveLength(1);
    const firstKey = lastKey(create.requests);

    create.failWith("ok");
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    await waitForRequests(create.requests, 2);
    const secondKey = lastKey(create.requests);
    return { firstKey, secondKey };
  }

  it("reuses the same key after an API 500 envelope (F-B02)", async () => {
    const { firstKey, secondKey } = await runUncertainRetry("server500");
    expect(secondKey).toBe(firstKey);
  }, 20_000);

  it("reuses the same key after an API 502 envelope (F-B03)", async () => {
    const { firstKey, secondKey } = await runUncertainRetry("server502");
    expect(secondKey).toBe(firstKey);
  }, 20_000);

  it("reuses the same key after an API 503 envelope (F-B04)", async () => {
    const { firstKey, secondKey } = await runUncertainRetry("server503");
    expect(secondKey).toBe(firstKey);
  }, 20_000);

  it("reuses the same key after a malformed 500 response (F-B05)", async () => {
    const { firstKey, secondKey } = await runUncertainRetry("malformed500");
    expect(secondKey).toBe(firstKey);
  }, 20_000);

  it("edits after an uncertain 503 still generate a new key (F-B11)", async () => {
    const create = createInvestigationHandler({ failWith: "server503" });
    setHttpHandlers(
      ...AUTH,
      investigationsListHandler([]),
      investigationDetailHandler(
        buildInvestigation({
          id: NEW_INVESTIGATION_ID,
          status: "pending",
          objective: "assess the delivery domain",
        }),
      ),
      create.handler,
    );
    renderAtPath("/investigations/new");
    await fillRequiredForm();
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    await screen.findByText(/Submission status is uncertain/);
    const firstKey = lastKey(create.requests);

    create.failWith("ok");
    const objective = screen.getByLabelText(/^Objective/);
    await userEvent.clear(objective);
    await userEvent.type(objective, "assess a different delivery domain");
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    await waitForRequests(create.requests, 2);
    expect(lastKey(create.requests)).not.toBe(firstKey);
  }, 20_000);

  it("settles on validation 400/422: the next submit uses a new key (F-B06)", async () => {
    const create = createInvestigationHandler({ failWith: "validation" });
    setHttpHandlers(
      ...AUTH,
      investigationsListHandler([]),
      investigationDetailHandler(
        buildInvestigation({
          id: NEW_INVESTIGATION_ID,
          status: "pending",
          objective: "assess the delivery domain",
        }),
      ),
      create.handler,
    );
    renderAtPath("/investigations/new");
    await fillRequiredForm();
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect(
      await screen.findByText("The investigation could not be submitted."),
    ).toBeInTheDocument();
    // No uncertain banner for a definitive 4xx rejection.
    expect(screen.queryByText(/Submission status is uncertain/)).toBeNull();
    const firstKey = lastKey(create.requests);

    create.failWith("ok");
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    await waitForRequests(create.requests, 2);
    expect(lastKey(create.requests)).not.toBe(firstKey);
  }, 20_000);

  it.each<"unauthorized" | "forbidden">(["unauthorized", "forbidden"])(
    "settles auth/permission %s responses: the next submit uses a new key (F-B08)",
    async (failWith) => {
      const create = createInvestigationHandler({ failWith });
      setHttpHandlers(
        ...AUTH,
        investigationsListHandler([]),
        investigationDetailHandler(
          buildInvestigation({
            id: NEW_INVESTIGATION_ID,
            status: "pending",
            objective: "assess the delivery domain",
          }),
        ),
        create.handler,
      );
      renderAtPath("/investigations/new");
      await fillRequiredForm();
      await userEvent.click(screen.getByRole("button", { name: "Submit" }));
      expect(
        await screen.findByText("The investigation could not be submitted."),
      ).toBeInTheDocument();
      expect(screen.queryByText(/Submission status is uncertain/)).toBeNull();
      const firstKey = lastKey(create.requests);

      create.failWith("ok");
      await userEvent.click(screen.getByRole("button", { name: "Submit" }));
      await waitForRequests(create.requests, 2);
      expect(lastKey(create.requests)).not.toBe(firstKey);
    },
    20_000,
  );

  it("never treats a pre-transport CSRF failure as uncertain (F-B09)", async () => {
    const create = createInvestigationHandler();
    setHttpHandlers(
      ...AUTH,
      investigationsListHandler([]),
      investigationDetailHandler(
        buildInvestigation({
          id: NEW_INVESTIGATION_ID,
          status: "pending",
          objective: "assess the delivery domain",
        }),
      ),
      create.handler,
    );
    renderAtPath("/investigations/new");
    await screen.findByRole("button", { name: "Submit" });
    // By design, omit the CSRF cookie: the request fails before transport.
    await userEvent.type(screen.getByLabelText(/^Objective/), "assess the delivery domain");
    await userEvent.type(
      screen.getByLabelText("Indicator value 1"),
      "update-package.test",
    );
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect(
      await screen.findByText("A required security cookie is missing. Reload the page and try again."),
    ).toBeInTheDocument();
    // Definite local failure: no uncertain banner and nothing hit the wire.
    expect(screen.queryByText(/Submission status is uncertain/)).toBeNull();
    expect(create.requests).toHaveLength(0);

    // The attempt settled: the next explicit submit is a fresh logical
    // request once the cookie exists, and it reaches the server.
    installCsrfCookie();
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    await waitForRequests(create.requests, 1);
    expect(lastKey(create.requests)).toMatch(IDEMPOTENCY_KEY_GRAMMAR);
    expect(screen.queryByText(/Submission status is uncertain/)).toBeNull();
  }, 20_000);

  it("uses a new key when the semantic payload changed after an uncertain attempt (U14)", async () => {
    const create = createInvestigationHandler({ failWith: "transport" });
    setHttpHandlers(
      ...AUTH,
      investigationsListHandler([]),
      investigationDetailHandler(
        buildInvestigation({
          id: NEW_INVESTIGATION_ID,
          status: "pending",
          objective: "assess the delivery domain",
        }),
      ),
      create.handler,
    );
    renderAtPath("/investigations/new");
    await fillRequiredForm();
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    await screen.findByText(/Submission status is uncertain/);
    const firstKey = lastKey(create.requests);

    // The analyst edits the objective, then resubmits: a new logical
    // request must never reuse the old attempt key.
    create.failWith("ok");
    const objective = screen.getByLabelText(/^Objective/);
    await userEvent.clear(objective);
    await userEvent.type(objective, "assess a different delivery domain");
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    await waitForRequests(create.requests, 2);
    expect(lastKey(create.requests)).not.toBe(firstKey);
  });

  it("navigates immediately to the workspace after 202 (U16)", async () => {
    const { handler } = createInvestigationHandler();
    setHttpHandlers(
      ...AUTH,
      investigationsListHandler([]),
      investigationDetailHandler(
        buildInvestigation({
          id: NEW_INVESTIGATION_ID,
          status: "running",
          objective: "assess the delivery domain",
        }),
      ),
      handler,
    );
    renderAtPath("/investigations/new");
    await fillRequiredForm();
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));

    // Workspace visible immediately: persistent header + Overview tab.
    expect(
      await screen.findByRole("heading", { name: "assess the delivery domain" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Overview" })).toBeInTheDocument();
    // Fake-mode indicator stays visible inside the workspace.
    expect(screen.getByText("FAKE DATA")).toBeInTheDocument();
  });

  it("invalidates the Investigation list after a successful create (U17)", async () => {
    const create = createInvestigationHandler();
    // Stateful list: empty before create, one Investigation after the 202.
    const statefulList = http.get("*/api/v1/investigations", () =>
      jsonResponse({
        items: create.requests.length > 0
          ? [buildInvestigation({ id: NEW_INVESTIGATION_ID })]
          : [],
        next_cursor: null,
      }),
    );
    setHttpHandlers(
      ...AUTH,
      statefulList,
      investigationDetailHandler(
        buildInvestigation({
          id: NEW_INVESTIGATION_ID,
          status: "pending",
          objective: "assess the delivery domain",
        }),
      ),
      create.handler,
    );
    renderAtPath("/investigations");
    expect(await screen.findByText("No investigations yet")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("link", { name: "New Investigation" }));
    await fillRequiredForm();
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));

    // Land in the workspace (create does not wait for the worker)...
    await screen.findByRole("heading", { name: "assess the delivery domain" });
    await waitForRequests(create.requests);

    // ...return to the list: the create invalidated the list cache, so a
    // refetch shows the new durable Investigation.
    await userEvent.click(screen.getByRole("link", { name: "Investigations" }));
    expect(
      await screen.findByText("assess the update-package delivery domain"),
    ).toBeInTheDocument();
  });

  it("surfaces an explicit safe idempotency-conflict error and forces a new attempt (U18)", async () => {
    const create = createInvestigationHandler({ failWith: "conflict" });
    setHttpHandlers(
      ...AUTH,
      investigationsListHandler([]),
      investigationDetailHandler(
        buildInvestigation({
          id: NEW_INVESTIGATION_ID,
          status: "pending",
          objective: "assess the delivery domain",
        }),
      ),
      create.handler,
    );
    renderAtPath("/investigations/new");
    await fillRequiredForm();
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect(
      await screen.findByText(
        "This submission identifier was already used for a different request. Start a new submission and try again.",
      ),
    ).toBeInTheDocument();
    const firstKey = lastKey(create.requests);

    create.failWith("ok");
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    await waitForRequests(create.requests, 2);
    // The conflict settles the attempt: a new logical request uses a new key.
    expect(lastKey(create.requests)).not.toBe(firstKey);
  });

  it("surfaces a safe validation failure (U19)", async () => {
    const { handler } = createInvestigationHandler({ failWith: "validation" });
    setHttpHandlers(...AUTH, investigationsListHandler([]), handler);
    renderAtPath("/investigations/new");
    await fillRequiredForm();
    await userEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect(
      await screen.findByText("The investigation could not be submitted."),
    ).toBeInTheDocument();
  });
});