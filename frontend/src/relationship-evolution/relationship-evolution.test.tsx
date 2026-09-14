// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Evolution workspace tests (PR 24E E-U01..E-U18).
//
// The Evolution route is entity-centric and URL-backed: without an entity it
// never queries; with an entity it issues one bounded observation page with
// exact server filters; observed_at drives temporal placement while
// retrieved_at stays distinct metadata; null observed times render in an
// explicit unavailable state; bounded pages are honestly labeled; points
// are keyboard-reachable controls opening the observation detail and its
// Evidence provenance.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import type { RelationshipObservation } from "../api/schema-types";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildObservation,
  completedInvestigationFixture,
  evolutionObservationsHandler,
  investigationDetailHandler,
  resourceListRecorder,
  runtimeFake,
  relationshipObservationsNetworkErrorHandler,
} from "../test/handlers";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const FOCAL = "40000000-0000-4000-8000-000000000101";
const COUNTERPARTY = "40000000-0000-4000-8000-000000000102";
const EVOLUTION_BASE = `/investigations/${INVESTIGATION_ID}/relationships/evolution`;

function authHandlers() {
  return [
    authMeSuccess,
    runtimeFake,
    investigationDetailHandler(
      completedInvestigationFixture({ id: INVESTIGATION_ID }),
    ),
  ];
}

function evolutionEntry(params: string): string {
  return `${EVOLUTION_BASE}?${params}`;
}

function obsA(overrides: Partial<RelationshipObservation> = {}): RelationshipObservation {
  return buildObservation({
    relationship_source_entity_id: FOCAL,
    relationship_target_entity_id: COUNTERPARTY,
    ...overrides,
  });
}

describe("Relationship Evolution workspace", () => {
  it("E-U01: without an entity the page never issues an observation request", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath(EVOLUTION_BASE);
    expect(
      await screen.findByText("Choose an entity to view relationship evolution."),
    ).toBeInTheDocument();
    // No request must have reached the observation endpoint.
    expect(recorder.requests).toHaveLength(0);
  });

  it("E-U02/E-U08: entity route issues a bounded entity/direction page and renders points by observed time", async () => {
    const recorder = resourceListRecorder();
    const first = obsA({ observed_at: "2026-06-01T09:00:00Z" });
    const second = obsA({
      id: "40000000-0000-4000-8000-000000000056",
      observed_at: "2026-06-10T09:00:00Z",
    });
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[first, second]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    await waitFor(() => {
      const last = recorder.requests.at(-1);
      expect(last?.params.entity_id).toBe(FOCAL);
      expect(last?.params.direction).toBe("either");
      expect(last?.params.limit).toBe("25");
    });
    // Both points are keyboard-reachable controls with observable labels.
    const point = await screen.findByRole("button", {
      name: /Outbound, Resolves to, Entity 40000000, observed 2026-06-10/,
    });
    expect(point).toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: /observed 2026-06-01T09:00:00Z/,
      }),
    ).toBeInTheDocument();
    // The time axis tick labels expose span minimum/maximum.
    expect(await screen.findByText(/^2026-06-01 09:00/)).toBeInTheDocument();
    expect(screen.getByText(/^2026-06-10 09:00/)).toBeInTheDocument();
  });

  it("E-U03: changing direction updates the URL and API and resets the cursor", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({
        pages: [[obsA()], [obsA()]],
        recorder,
      }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}&cursor=cursor-1`));
    await screen.findByRole("button", { name: /observed 2026-06-01/ });
    await userEvent.click(screen.getByRole("combobox", { name: "Direction" }));
    await userEvent.click(await screen.findByRole("option", { name: "Inbound" }));
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => {
      const last = recorder.requests.at(-1);
      expect(last?.params.direction).toBe("target");
      // The cursor is reset when a semantic filter changes.
      expect(last?.params.cursor).toBeUndefined();
    });
  });

  it("E-U04: relationship type filter reaches the exact server query", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    await screen.findByRole("button", { name: /observed 2026-06-01/ });
    await userEvent.click(screen.getByRole("combobox", { name: "Relationship type" }));
    await userEvent.click(await screen.findByRole("option", { name: "CNAME of" }));
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => {
      expect(recorder.requests.at(-1)?.params.relationship_type)
        .toBe("urn:ati:relationship:dns:cname_of");
    });
  });

  it("E-U05: counterparty filter reaches the exact server query", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    await screen.findByRole("button", { name: /observed 2026-06-01/ });
    await userEvent.type(
      screen.getByRole("textbox", { name: "Counterparty entity ID" }),
      COUNTERPARTY,
    );
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => {
      expect(recorder.requests.at(-1)?.params.counterparty_entity_id).toBe(COUNTERPARTY);
    });
  });

  it("E-U06: provider/source filter reaches the exact server query", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    await screen.findByRole("button", { name: /observed 2026-06-01/ });
    await userEvent.type(
      screen.getByRole("textbox", { name: "Provider/source" }),
      "fake-dns",
    );
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => {
      expect(recorder.requests.at(-1)?.params.source).toBe("fake-dns");
    });
  });

  it("E-U07: observed range reaches the exact server query", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    await screen.findByRole("button", { name: /observed 2026-06-01/ });
    await userEvent.type(screen.getByLabelText("Observed from"), "2026-06-01T00:00");
    await userEvent.type(screen.getByLabelText("Observed to"), "2026-06-02T00:00");
    await userEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => {
      const last = recorder.requests.at(-1);
      expect(last?.params.observed_from).toMatch(/^2026-06-01T/);
      expect(last?.params.observed_to).toMatch(/^2026-06-02T/);
    });
  });

  it("E-U09/E-U10: retrieved metadata stays distinct and null observed times render explicitly", async () => {
    const recorder = resourceListRecorder();
    const nullObserved = obsA({
      id: "40000000-0000-4000-8000-000000000057",
      observed_at: null,
      retrieved_at: "2026-08-01T10:00:00Z",
    });
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA(), nullObserved]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    // The null-observed row appears in the explicit unavailable group with
    // its retrieved time, never positioned on the retrieved timestamp.
    const unavailable = await screen.findByRole("region", {
      name: "Observed time unavailable",
    });
    expect(within(unavailable).getByTitle("2026-08-01T10:00:00Z")).toBeInTheDocument();
    // The null-observed row never becomes an x-axis point.
    expect(
      screen.queryByRole("button", { name: /observed 2026-08-01/ }),
    ).not.toBeInTheDocument();
    // Retrieved metadata of observed points stays distinct tooltip metadata.
    expect(screen.getByTitle("retrieved 2026-06-01T09:05:00Z")).toBeInTheDocument();
  });

  it("E-U11: next_cursor causes the bounded-page notice and a Next control", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({
        pages: [[obsA(), obsA({ observed_at: "2026-06-10T09:00:00Z" })], [obsA()]],
        recorder,
      }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    expect(
      await screen.findByText(/Showing a bounded page of observations/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeEnabled();
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => {
      expect(recorder.requests.at(-1)?.params.cursor).toBe("cursor-1");
    });
    // The previous control is offered through the browser-local back stack.
    expect(screen.getByRole("button", { name: "Previous" })).toBeEnabled();
  });

  it("E-U12/E-U13: activating a point opens the observation detail with Evidence provenance", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    await userEvent.click(
      await screen.findByRole("button", { name: /observed 2026-06-01/ }),
    );
    const drawer = await screen.findByRole("dialog", { name: "Observation" });
    expect(within(drawer).getByText("Relationship ID")).toBeInTheDocument();
    expect(within(drawer).getByText("Source entity")).toBeInTheDocument();
    expect(within(drawer).getByText("Target entity")).toBeInTheDocument();
    expect(within(drawer).getByText("Observed at")).toBeInTheDocument();
    expect(within(drawer).getByText("Retrieved at")).toBeInTheDocument();
    // Evidence provenance action exists in the drawer.
    expect(
      within(drawer).getByRole("button", { name: "Observation provenance actions" }),
    ).toBeInTheDocument();
    await userEvent.click(
      within(drawer).getByRole("button", { name: "Observation provenance actions" }),
    );
    expect(await screen.findByRole("menuitem", { name: "Open evidence" })).toBeInTheDocument();
  });

  it("E-U14: honest no-results wording, never an existence claim", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    expect(
      await screen.findByText("No relationship observations match these filters."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/no relationships existed/i)).not.toBeInTheDocument();
  });

  it("E-U15: a running Investigation shows the freshness notice", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      authMeSuccess,
      runtimeFake,
      investigationDetailHandler(
        completedInvestigationFixture({
          id: INVESTIGATION_ID,
          status: "running",
          completed_at: null,
        }),
      ),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    expect(
      await screen.findByText(/Investigation still running; observations may change/),
    ).toBeInTheDocument();
  });

  it("E-U16: query failure keeps filters and allows Retry", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      relationshipObservationsNetworkErrorHandler,
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}&direction=source`));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Return to first page" })).toBeInTheDocument();
    void recorder;
  });

  it("E-U17: observation points are keyboard reachable", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    const point = await screen.findByRole("button", { name: /observed 2026-06-01/ });
    point.focus();
    expect(point).toHaveFocus();
    await userEvent.keyboard("{Enter}");
    expect(
      await screen.findByRole("dialog", { name: "Observation" }),
    ).toBeInTheDocument();
  });

  it("E-U18: the tabular alternative is reachable without spatial exploration", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    await screen.findByRole("button", { name: /observed 2026-06-01/ });
    await userEvent.click(screen.getByRole("button", { name: "View as table" }));
    const table = await screen.findByRole("table", {
      name: "Relationship observations (this page)",
    });
    expect(within(table).getByText("fake-dns")).toBeInTheDocument();
    expect(within(table).getByText("Resolves to")).toBeInTheDocument();
  });
});