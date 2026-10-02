// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 31K GraphActionPanel tests (K-FE05..K-FE11, K-FE18 panel boundary).
//
// The panel routes ONE canonical graph Entity through the EXISTING
// Investigation create command: CSRF cookie, Idempotency-Key, request DTO
// (objective + exact canonical type/value), no provider/Coordinator calls
// from the browser, and the exact create-attempt uncertainty/idempotency
// semantics (transport-uncertain retries reuse the key; definitive
// rejections settle; a semantic payload change starts a new attempt).

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router";

import { CSRF_COOKIE_NAME } from "../api/csrf";
import type { CreateRequestRecord } from "../test/handlers";
import {
  createInvestigationHandler,
  investigationsListHandler,
  jsonResponse,
} from "../test/handlers";
import { renderProviders } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import { IDEMPOTENCY_KEY_GRAMMAR } from "../investigations/idempotency";
import {
  GraphActionPanel,
  type GraphActionPanelProps,
} from "./GraphActionPanel";
import type { GraphActionEntity } from "./graph-actions";

useHttp();

/** The canonical graph Entity that all panel tests route. */
const SELECTION: GraphActionEntity = {
  entityId: "40000000-0000-4000-8000-000000000101",
  entityType: "domain",
  entityValue: "update-package.test",
};

const TYPE_LABELS: Record<string, string> = {
  domain: "Domain",
  ip_address: "IP address",
};

/** Simulate the real authenticated session: the CSRF cookie set at login. */
function installCsrfCookie(): void {
  document.cookie = `${CSRF_COOKIE_NAME}=test-csrf-token`;
}

function renderPanel(overrides: Partial<GraphActionPanelProps> = {}): void {
  renderProviders(
    <MemoryRouter>
      <GraphActionPanel
        selection={overrides.selection ?? SELECTION}
        entityTypeLabel={
          overrides.entityTypeLabel ?? ((type: string) => TYPE_LABELS[type] ?? type)
        }
        onCancel={overrides.onCancel ?? (() => {})}
      />
    </MemoryRouter>,
  );
}

/** The in-flow panel region (non-modal section with the localized title). */
function panelRegion(): HTMLElement {
  return screen.getByRole("region", { name: "Start investigation" });
}

async function waitForRequests(
  requests: CreateRequestRecord[],
  expected: number,
): Promise<void> {
  await waitFor(() => expect(requests.length).toBeGreaterThanOrEqual(expected));
}

describe("PR 31K GraphActionPanel", () => {
  it("K-FE01/K-FE18: renders the canonical Entity type/value/id and a factual objective", () => {
    renderPanel();
    const panel = panelRegion();
    // Human-readable presentation metadata from the canonical Entity
    // (intro sentence carries the localized type/value).
    expect(within(panel).getByText(/^Starts an ATI investigation for Domain update-package\.test\./)).toBeInTheDocument();
    expect(
      within(panel).getByText(
        "Canonical Entity ID: 40000000-0000-4000-8000-000000000101",
      ),
    ).toBeInTheDocument();
    // Prefilled neutral objective; no analytical claims.
    expect(screen.getByLabelText(/^Objective/)).toHaveValue(
      "Investigate Domain update-package.test",
    );
  });

  it("K-FE05/K-FE08: submit routes exactly one durable command with the exact canonical type/value", async () => {
    const create = createInvestigationHandler();
    setHttpHandlers(create.handler, investigationsListHandler([]));
    renderPanel();
    const user = userEvent.setup();
    installCsrfCookie();
    await user.click(screen.getByRole("button", { name: "Start investigation" }));
    await waitForRequests(create.requests, 1);
    const body = create.requests[0].body as {
      objective: string;
      indicators: { type: string; value: string }[];
    };
    expect(body.objective).toBe("Investigate Domain update-package.test");
    expect(body.indicators).toEqual([
      { type: "domain", value: "update-package.test" },
    ]);
    expect(create.requests[0].csrfToken).toBe("test-csrf-token");
    expect(create.requests[0].idempotencyKey).toMatch(IDEMPOTENCY_KEY_GRAMMAR);
  });

  it("K-FE06: a blank objective is rejected locally with no request", async () => {
    const create = createInvestigationHandler();
    setHttpHandlers(create.handler, investigationsListHandler([]));
    renderPanel();
    const user = userEvent.setup();
    installCsrfCookie();
    await user.clear(screen.getByLabelText(/^Objective/));
    await user.click(screen.getByRole("button", { name: "Start investigation" }));
    expect(
      await screen.findByText("Enter an objective for the investigation."),
    ).toBeInTheDocument();
    expect(create.requests).toHaveLength(0);
  });

  it("K-FE07: a second click while pending never issues a second request", async () => {
    const deferred = deferredCreateHandler();
    setHttpHandlers(deferred.handler, investigationsListHandler([]));
    renderPanel();
    const user = userEvent.setup();
    installCsrfCookie();
    await user.click(screen.getByRole("button", { name: "Start investigation" }));
    await waitForRequests(deferred.requests, 1);
    // While the first response is pending the panel shows the pending state
    // and both the disablement and the local busy guard block a second
    // semantic submission for the same attempt.
    expect(screen.getByRole("button", { name: "Starting…" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Starting…" }));
    fireEvent.click(screen.getByRole("button", { name: "Starting…" }));
    expect(deferred.requests).toHaveLength(1);
    deferred.release(
      jsonResponse(
        {
          id: "60000000-0000-4000-8000-000000000001",
          status: "pending",
          created_at: "2026-06-01T10:00:00Z",
        },
        202,
      ),
    );
    // The durable command remains exactly one once the response settles.
    await waitFor(() => expect(deferred.requests).toHaveLength(1));
  });

  it("K-FE09: a typed validation failure surfaces a safe localized error with no second request", async () => {
    const create = createInvestigationHandler({ failWith: "validation" });
    setHttpHandlers(create.handler, investigationsListHandler([]));
    renderPanel();
    const user = userEvent.setup();
    installCsrfCookie();
    await user.click(screen.getByRole("button", { name: "Start investigation" }));
    expect(
      await screen.findByText("Unable to start the investigation."),
    ).toBeInTheDocument();
    expect(create.requests).toHaveLength(1);
    // The panel stays in flow; no navigation/remount happened.
    expect(panelRegion()).toBeInTheDocument();
  });

  it("K-FE10: a transport-uncertain retry retains the same Idempotency-Key", async () => {
    const create = createInvestigationHandler({ failWith: "transport" });
    setHttpHandlers(create.handler, investigationsListHandler([]));
    renderPanel();
    const user = userEvent.setup();
    installCsrfCookie();
    await user.click(screen.getByRole("button", { name: "Start investigation" }));
    expect(
      await screen.findByText(
        "Submission status is uncertain. Retry will safely reuse the same submission identifier.",
      ),
    ).toBeInTheDocument();
    await waitForRequests(create.requests, 1);
    const firstKey = create.requests[0].idempotencyKey;
    create.failWith("ok");
    await user.click(screen.getByRole("button", { name: "Start investigation" }));
    await waitForRequests(create.requests, 2);
    expect(create.requests[1].idempotencyKey).toBe(firstKey);
  });

  it("K-FE11: a semantic payload change after a settled attempt starts a new attempt/key", async () => {
    const create = createInvestigationHandler({ failWith: "validation" });
    setHttpHandlers(create.handler, investigationsListHandler([]));
    renderPanel();
    const user = userEvent.setup();
    installCsrfCookie();
    await user.click(screen.getByRole("button", { name: "Start investigation" }));
    await screen.findByText("Unable to start the investigation.");
    await waitForRequests(create.requests, 1);
    const settledKey = create.requests[0].idempotencyKey;
    create.failWith("ok");
    // Editing the objective changes the semantic payload; the next submit is
    // a new logical request with a new cryptographically strong key.
    await user.type(
      screen.getByLabelText(/^Objective/),
      " focused on delivery",
    );
    await user.click(screen.getByRole("button", { name: "Start investigation" }));
    await waitForRequests(create.requests, 2);
    expect(create.requests[1].idempotencyKey).not.toBe(settledKey);
    expect(create.requests[1].idempotencyKey).toMatch(IDEMPOTENCY_KEY_GRAMMAR);
    const secondBody = create.requests[1].body as {
      objective: string;
      indicators: { type: string; value: string }[];
    };
    expect(secondBody.indicators).toEqual([
      { type: "domain", value: "update-package.test" },
    ]);
  });

  it("K-FE04: cancel/clear closes the panel without any request", async () => {
    const create = createInvestigationHandler();
    setHttpHandlers(create.handler, investigationsListHandler([]));
    let cancelCalls = 0;
    renderPanel({ onCancel: () => { cancelCalls += 1; } });
    const user = userEvent.setup();
    installCsrfCookie();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(create.requests).toHaveLength(0);
    // The caller (workspace) receives the clear callback and hides the panel.
    expect(cancelCalls).toBe(1);
  });
});

/** One POST /investigations handler that stays pending until released. */
function deferredCreateHandler(): {
  handler: ReturnType<typeof http.post>;
  requests: CreateRequestRecord[];
  release: (response: HttpResponse<JsonBodyType>) => void;
} {
  const requests: CreateRequestRecord[] = [];
  let releaseCallback: ((response: HttpResponse<JsonBodyType>) => void) | null = null;
  const handler = http.post("*/api/v1/investigations", async ({ request }) => {
    const body = await request.json();
    requests.push({
      body,
      idempotencyKey: request.headers.get("Idempotency-Key"),
      csrfToken: request.headers.get("X-CSRF-Token"),
    });
    return new Promise<HttpResponse<JsonBodyType>>((resolve) => {
      releaseCallback = resolve;
    });
  });
  return {
    handler,
    requests,
    release: (response: HttpResponse<JsonBodyType>) => {
      if (releaseCallback === null) {
        throw new Error("no pending create request to release");
      }
      releaseCallback(response);
      releaseCallback = null;
    },
  };
}
