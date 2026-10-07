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

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { http } from "msw";
import { describe, expect, it } from "vitest";
import userEvent from "@testing-library/user-event";

import type { RelationshipObservation } from "../api/schema-types";
import { localDateTimeToIso } from "../analyst-table/filters";
import {
  graphTemporalDraftToCommitted,
  type GraphTemporalDraft,
} from "../relationship-graph/GraphTemporalControls";
import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildGraphEdge,
  buildGraphNeighborhood,
  buildGraphNode,
  buildObservation,
  completedInvestigationFixture,
  evolutionObservationsHandler,
  graphNeighborhoodHandler,
  investigationDetailHandler,
  jsonResponse,
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
    const heading = await screen.findByRole("heading", { name: "Observation" });
    const drawer = heading.parentNode as HTMLElement;
    expect(within(drawer).getByText("Relationship ID")).toBeInTheDocument();
    expect(within(drawer).getByText("Source entity")).toBeInTheDocument();
    expect(within(drawer).getByText("Target entity")).toBeInTheDocument();
    expect(within(drawer).getByText("Observed at")).toBeInTheDocument();
    expect(within(drawer).getByText("Retrieved at")).toBeInTheDocument();
    // Evidence provenance action exists in the detail.
    expect(
      within(drawer).getByRole("button", { name: "Observation provenance actions" }),
    ).toBeInTheDocument();
    await userEvent.click(
      within(drawer).getByRole("button", { name: "Observation provenance actions" }),
    );
    expect(await screen.findByRole("link", { name: "Evidence" })).toBeInTheDocument();
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
      // The focal indicator's exact Entity read succeeds; only the
      // observation query fails, so the bounded Retry surface is unambiguous.
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder,
      }),
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
      await screen.findByRole("heading", { name: "Observation" }),
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
      name: "Relationship history (this page)",
    });
    expect(within(table).getByText("fake-dns")).toBeInTheDocument();
    expect(within(table).getByText("Resolves to")).toBeInTheDocument();
  });
});
describe("Relationship Evolution counterparty presentation (PR 31F-1)", () => {
  function obsWithMetadata(): RelationshipObservation {
    return buildObservation({
      relationship_source_entity_id: FOCAL,
      relationship_target_entity_id: COUNTERPARTY,
      relationship_source_entity_type: "domain",
      relationship_source_entity_value: "update-package.test",
      relationship_target_entity_type: "ip_address",
      relationship_target_entity_value: "192.0.2.1",
      observed_at: "2026-06-01T09:00:00Z",
    });
  }

  it("F1-U17/U21: an outbound lane shows the counterparty Entity type/value and includes it in accessibility", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsWithMetadata()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    // Lane heading renders the counterparty Entity type/value text.
    expect(await screen.findByText("IP address 192.0.2.1")).toBeInTheDocument();
    // Compact technical identity stays available as secondary metadata.
    expect(
      screen.getAllByRole("button", { name: /Copy ID/ }).length,
    ).toBeGreaterThan(0);
    // The point aria label carries the semantic counterparty.
    expect(
      screen.getByRole("button", {
        name: /Outbound, Resolves to, IP address 192\.0\.2\.1, observed 2026-06-01/,
      }),
    ).toBeInTheDocument();
  });

  it("F1-U22: the table alternative renders the human-readable counterparty with canonical identity", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsWithMetadata()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    await screen.findByRole("button", { name: /observed 2026-06-01/ });
    await userEvent.click(screen.getByRole("button", { name: "View as table" }));
    const table = await screen.findByRole("table", {
      name: "Relationship history (this page)",
    });
    expect(within(table).getByText("IP address 192.0.2.1")).toBeInTheDocument();
    // Canonical identity is retained through the compact ID control.
    expect(within(table).getAllByRole("button", { name: /Copy ID/ }).length).toBeGreaterThan(0);
    // No invented value when the counterparty id column text is empty.
    expect(within(table).queryByText(`Entity ${COUNTERPARTY.slice(0, 8)}`)).not.toBeInTheDocument();
  });

  it("F1-U20: missing endpoint metadata falls back to the compact technical identity", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    // buildObservation carries no endpoint type/value -> technical fallback.
    expect(
      await screen.findByRole("button", {
        name: /Outbound, Resolves to, Entity 40000000, observed 2026-06-01/,
      }),
    ).toBeInTheDocument();
  });

  it("F1-U23: the CSV export prefers semantic endpoint fields and keeps the canonical identity", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsWithMetadata()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    await screen.findByRole("button", { name: /observed 2026-06-01/ });
    let captured = "";
    const originalCreate = URL.createObjectURL;
    const originalRevoke = URL.revokeObjectURL;
    const originalClick = HTMLAnchorElement.prototype.click;
    try {
      // Stub both halves of the object-URL API: jsdom lacks it natively, and
      // downloadCsv must not throw on a partial shim either.
      Object.defineProperty(URL, "createObjectURL", {
        configurable: true,
        value: (blob: Blob) => {
          const reader = new FileReader();
          reader.onloadend = () => {
            captured = String(reader.result ?? "");
          };
          reader.readAsText(blob);
          return "blob:mock";
        },
      });
      Object.defineProperty(URL, "revokeObjectURL", {
        configurable: true,
        value: (objectUrl: string) => {
          void objectUrl;
        },
      });
      HTMLAnchorElement.prototype.click = () => undefined;
      fireEvent.click(screen.getByRole("button", { name: "Export current page" }));
      await waitFor(() => expect(captured).toContain("Counterparty type"));
      expect(captured).toContain("Counterparty value");
      expect(captured).toContain("Counterparty ID");
      expect(captured).toContain("ip_address");
      expect(captured).toContain("192.0.2.1");
      expect(captured).toContain(COUNTERPARTY);
    } finally {
      Object.defineProperty(URL, "createObjectURL", { configurable: true, value: originalCreate });
      Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: originalRevoke });
      HTMLAnchorElement.prototype.click = originalClick;
    }
  });
});

describe("PR 31J temporal graph workspace (FE10..FE30)", () => {
  const GRAPH_VIEW = (params: string) =>
    evolutionEntry(`entity_id=${FOCAL}&view=graph&${params}`);
  // A committed 8-day observed range -> 8 one-day frames.
  const RANGE_START = "2026-02-01T00:00:00Z";
  const RANGE_END = "2026-02-09T00:00:00Z";
  const temporalUrl = (frame: string | null) => {
    const q =
      `graph_temporal=1&graph_time_start=${RANGE_START}&graph_time_end=${RANGE_END}`;
    return GRAPH_VIEW(frame === null ? q : `${q}&graph_time_frame=${frame}`);
  };
  const neighborhood = buildGraphNeighborhood();

  function temporalNeighborhoodHandler() {
    const recorder = resourceListRecorder();
    return {
      recorder,
      install: () =>
        setHttpHandlers(
          ...authHandlers(),
          graphNeighborhoodHandler({ neighborhood, recorder }),
        ),
    };
  }

  it("FE10: without temporal params the graph request stays ordinary", async () => {
    const { recorder, install } = temporalNeighborhoodHandler();
    install();
    renderAtPath(GRAPH_VIEW(""));
    await waitFor(() => expect(recorder.requests.length).toBeGreaterThan(0));
    const last = recorder.requests.at(-1);
    expect(last?.params.observed_from).toBeUndefined();
    expect(last?.params.observed_to).toBeUndefined();
    expect(last?.params.entity_id).toBe(FOCAL);
  });

  it("FE11/FE20: temporal frame 0 overrides the neighborhood request bounds", async () => {
    const { recorder, install } = temporalNeighborhoodHandler();
    install();
    renderAtPath(temporalUrl(null));
    await waitFor(() => expect(recorder.requests.length).toBeGreaterThan(0));
    const last = recorder.requests.at(-1);
    expect(last?.params.observed_from).toBe("2026-02-01T00:00:00Z");
    expect(last?.params.observed_to).toBe("2026-02-02T00:00:00Z");
  });

  it("FE12: Next frame advances the URL frame identity and request bounds", async () => {
    const { recorder, install } = temporalNeighborhoodHandler();
    install();
    const { router } = renderAtPath(temporalUrl(null));
    await waitFor(() => expect(recorder.requests.length).toBe(1));
    await userEvent.click(screen.getByRole("button", { name: "Next frame" }));
    await waitFor(() => expect(recorder.requests.length).toBe(2));
    const last = recorder.requests.at(-1);
    expect(last?.params.observed_from).toBe("2026-02-02T00:00:00Z");
    expect(last?.params.observed_to).toBe("2026-02-03T00:00:00Z");
    // The committed URL carries the new frame identity.
    expect(router.state.location.search).toContain("graph_time_frame=1");
  });

  it("FE13/FE14: Previous retreats and is disabled on the first frame", async () => {
    const { recorder, install } = temporalNeighborhoodHandler();
    install();
    renderAtPath(temporalUrl("1"));
    await waitFor(() => expect(recorder.requests.length).toBe(1));
    expect(recorder.requests.at(-1)?.params.observed_from).toBe("2026-02-02T00:00:00Z");
    await userEvent.click(screen.getByRole("button", { name: "Previous frame" }));
    await waitFor(() => expect(recorder.requests.length).toBe(2));
    expect(recorder.requests.at(-1)?.params.observed_from).toBe("2026-02-01T00:00:00Z");
    expect(screen.getByRole("button", { name: "Previous frame" })).toBeDisabled();
  });

  it("FE15: Next is disabled on the last frame", async () => {
    const { install } = temporalNeighborhoodHandler();
    install();
    renderAtPath(temporalUrl("7"));
    await waitFor(() => expect(screen.getByRole("button", { name: "Next frame" })).toBeDisabled());
  });

  it("FE16: Apply commits a new range and resets the frame index to 0", async () => {
    const { recorder, install } = temporalNeighborhoodHandler();
    install();
    const { router } = renderAtPath(temporalUrl("3"));
    await waitFor(() => expect(recorder.requests.length).toBe(1));
    // The committed tuple is already temporal active (frame 3 of 8); edit the
    // draft range directly. A new Apply resets to frame 0.
    const startInput = screen.getByLabelText("Range start");
    const endInput = screen.getByLabelText("Range end");
    await userEvent.clear(startInput);
    await userEvent.type(startInput, "2026-02-01T00:00");
    await userEvent.clear(endInput);
    await userEvent.type(endInput, "2026-02-03T00:00");
    await userEvent.click(within(screen.getByRole("group", { name: "Temporal exploration" })).getByRole("button", { name: "Apply temporal" }));
    await waitFor(() => expect(recorder.requests.length).toBe(2));
    const last = recorder.requests.at(-1);
    // The draft is local wall-clock; the committed/request values are UTC ISO.
    // The new range starts on 02-01; frame 0 boundary strictly follows the
    // start (half-open), and the frame index is NOT committed (reset to 0).
    expect(last?.params.observed_from).toMatch(/^2026-02-01T/);
    expect(
      Date.parse(last?.params.observed_to ?? "") >
        Date.parse(last?.params.observed_from ?? ""),
    ).toBe(true);
    expect(router.state.location.search).not.toContain("graph_time_frame=");
  });

  it("FE17: draft edits before Apply never commit URL or request", async () => {
    const { recorder, install } = temporalNeighborhoodHandler();
    install();
    const { router } = renderAtPath(temporalUrl(null));
    await waitFor(() => expect(recorder.requests.length).toBe(1));
    const before = router.state.location.search;
    const startInput = screen.getByLabelText("Range start");
    await userEvent.clear(startInput);
    await userEvent.type(startInput, "2026-02-02T00:00");
    expect(recorder.requests.length).toBe(1);
    expect(router.state.location.search).toBe(before);
  });

  it("FE18/FE29: Disable removes temporal params and restores ordinary graph bounds", async () => {
    const { recorder, install } = temporalNeighborhoodHandler();
    install();
    const { router } = renderAtPath(temporalUrl("2"));
    await waitFor(() => expect(recorder.requests.length).toBe(1));
    await userEvent.click(screen.getByRole("button", { name: "Disable temporal" }));
    await waitFor(() => expect(recorder.requests.length).toBe(2));
    const last = recorder.requests.at(-1);
    expect(last?.params.observed_from).toBeUndefined();
    expect(last?.params.observed_to).toBeUndefined();
    expect(router.state.location.search).not.toContain("graph_time_start");
    expect(router.state.location.search).not.toContain("graph_time_end");
  });

  it("FE19: unrelated graph URL params survive Apply/Prev/Next/Disable", async () => {
    const { recorder, install } = temporalNeighborhoodHandler();
    install();
    const { router } = renderAtPath(
      `${GRAPH_VIEW("graph_scope=known")}&graph_temporal=1&graph_time_start=${RANGE_START}&graph_time_end=${RANGE_END}`,
    );
    await waitFor(() => expect(recorder.requests.length).toBe(1));
    await userEvent.click(screen.getByRole("button", { name: "Next frame" }));
    await waitFor(() => expect(recorder.requests.length).toBe(2));
    expect(router.state.location.search).toContain("graph_scope=known");
    expect(recorder.requests.at(-1)?.params.scope).toBe("known");
    await userEvent.click(screen.getByRole("button", { name: "Disable temporal" }));
    await waitFor(() => expect(recorder.requests.length).toBe(3));
    expect(router.state.location.search).toContain("graph_scope=known");
    expect(recorder.requests.at(-1)?.params.scope).toBe("known");
  });

  it("FE26: the same committed frame reparses to the same request bounds", async () => {
    const { recorder, install } = temporalNeighborhoodHandler();
    install();
    renderAtPath(temporalUrl("4"));
    await waitFor(() => expect(recorder.requests.length).toBe(1));
    expect(recorder.requests.at(-1)?.params.observed_from).toBe("2026-02-05T00:00:00Z");
    expect(recorder.requests.at(-1)?.params.observed_to).toBe("2026-02-06T00:00:00Z");
  });

  it("FE27: an empty temporal frame renders the observational empty wording", async () => {
    const recorder = resourceListRecorder();
    // The backend guarantees the focal node on every 200: an empty frame is a
    // focal-only graph (same contract PR 31G asserts for isolated Entities).
    const focalOnly = buildGraphNeighborhood({
      nodes: [buildGraphNeighborhood().nodes[0]],
      edges: [],
      truncated: false,
    });
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({ neighborhood: focalOnly, recorder }),
    );
    renderAtPath(temporalUrl("5"));
    await screen.findByText(
      "No matching relationship observations were recorded in this frame.",
    );
    expect(
      screen.queryByText("No stable relationships are known for this entity in this Investigation."),
    ).not.toBeInTheDocument();
  });

  it("FE28: an invalid draft range is rejected and the committed graph is unchanged", async () => {
    const { recorder, install } = temporalNeighborhoodHandler();
    install();
    const { router } = renderAtPath(temporalUrl(null));
    await waitFor(() => expect(recorder.requests.length).toBe(1));
    const before = router.state.location.search;
    const startInput = screen.getByLabelText("Range start");
    const endInput = screen.getByLabelText("Range end");
    await userEvent.clear(startInput);
    await userEvent.type(startInput, "2026-02-09T00:00");
    await userEvent.clear(endInput);
    await userEvent.type(endInput, "2026-02-01T00:00");
    await userEvent.click(within(screen.getByRole("group", { name: "Temporal exploration" })).getByRole("button", { name: "Apply temporal" }));
    await screen.findByText(/Enter a valid observed range with a start before the end\./);
    expect(recorder.requests.length).toBe(1);
    expect(router.state.location.search).toBe(before);
  });

  it("FE30: the active-frame banner shows human 1-based numbering and half-open bounds", async () => {
    const { install } = temporalNeighborhoodHandler();
    install();
    renderAtPath(temporalUrl("2"));
    await screen.findByRole("status", {
      name: "Frame 3 of 8 — observations from 2026-02-03T00:00:00Z through before 2026-02-04T00:00:00Z",
    });
  });

  it("FE31 (PR 35-1): date-only temporal bounds normalize to local midnight", () => {
    const draft: GraphTemporalDraft = {
      temporal: true,
      rangeStart: "2026-02-01",
      rangeEnd: "2026-02-09",
      frameCount: 8,
    };
    const committed = graphTemporalDraftToCommitted(draft);
    // A valid date-only range commits local-midnight bounds (no malformed
    // range and no false ``start >= end`` result).
    expect(committed.temporal).toBe(true);
    expect(committed.rangeStart).toBe(localDateTimeToIso("2026-02-01"));
    expect(committed.rangeEnd).toBe(localDateTimeToIso("2026-02-09"));
    expect(committed.frameIndex).toBe(0);
  });
});

describe("PR 35-1 Relationship history linked Evidence + contextual Back", () => {
  it("L01/L02/L03: the history table Evidence ID is one linked compact ID with a copy control", async () => {
    const recorder = resourceListRecorder();
    const row = obsA({ evidence_id: "40000000-0000-4000-8000-000000000001" });
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[row]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    await screen.findByRole("button", { name: /observed 2026-06-01/ });
    await userEvent.click(screen.getByRole("button", { name: "View as table" }));
    const table = await screen.findByRole("table", {
      name: "Relationship history (this page)",
    });
    const link = within(table).getByRole("link", { name: "Evidence" });
    expect(link).toHaveAttribute(
      "href",
      `/investigations/${INVESTIGATION_ID}/evidence/40000000-0000-4000-8000-000000000001`,
    );
    // The short ID renders once; the full UUID stays copyable.
    expect(within(table).getAllByText("40000000").length).toBeGreaterThan(0);
    expect(
      within(table).getAllByRole("button", { name: /Copy ID/ }).length,
    ).toBeGreaterThan(0);
  });

  it("B01/B04: a valid internal returnTo renders Back and restores query + hash", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    const origin = `/investigations/${INVESTIGATION_ID}/evidence?source=rdap#top`;
    const { router } = renderAtPath({
      pathname: EVOLUTION_BASE,
      search: `?entity_id=${FOCAL}`,
      state: { returnTo: origin },
    });
    const back = await screen.findByRole("button", { name: "< Back" });
    await userEvent.click(back);
    await waitFor(() => {
      expect(
        `${router.state.location.pathname}${router.state.location.search}${router.state.location.hash}`,
      ).toBe(origin);
    });
  });

  it("N5/N6 (amendment): EVOLUTION <-> GRAPH preserves the return context", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder: resourceListRecorder(),
      }),
    );
    const origin = `/investigations/${INVESTIGATION_ID}/relationships`;
    const { router } = renderAtPath({
      pathname: EVOLUTION_BASE,
      search: `?entity_id=${FOCAL}`,
      state: { navigation: { returns: [{ pathname: origin, search: "", hash: "" }] } },
    });
    expect(await screen.findByRole("button", { name: "< Back" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Graph" }));
    await waitFor(() => expect(router.state.location.search).toContain("view=graph"));
    expect(screen.getByRole("button", { name: "< Back" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Evolution" }));
    await waitFor(() => expect(router.state.location.search).not.toContain("view=graph"));
    await userEvent.click(screen.getByRole("button", { name: "< Back" }));
    await waitFor(() => expect(router.state.location.pathname).toBe(origin));
  });

  it("B02: a direct/deep link without returnTo renders no Back control", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    await screen.findByRole("button", { name: /observed 2026-06-01/ });
    expect(screen.queryByRole("button", { name: "< Back" })).not.toBeInTheDocument();
  });

  it("B03: an external/invalid returnTo renders no Back control", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath({
      pathname: EVOLUTION_BASE,
      search: `?entity_id=${FOCAL}`,
      state: { returnTo: "https://evil.example/steal" },
    });
    await screen.findByRole("button", { name: /observed 2026-06-01/ });
    expect(screen.queryByRole("button", { name: "< Back" })).not.toBeInTheDocument();
  });
});

describe("PR 31H HOPS depth propagation (PR 35-1 Part 6)", () => {
  it("H01/H02/H03/H04: 1 -> 2 -> 3 hops changes the traversal request depth", async () => {
    const neighborhood = buildGraphNeighborhood();
    const traversalRequests: (string | null)[] = [];
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({ neighborhood, recorder: resourceListRecorder() }),
      http.get(
        "*/api/v1/investigations/:id/graph/entities/:entityId/traversal",
        ({ request }) => {
          const url = new URL(request.url);
          traversalRequests.push(url.searchParams.get("max_depth"));
          return jsonResponse(neighborhood);
        },
      ),
    );
    const { router } = renderAtPath(
      evolutionEntry(`entity_id=${FOCAL}&view=graph`),
    );
    await screen.findByRole("group", { name: "Graph context and filters" });
    // H01: committed depth 1 is the neighborhood endpoint; no traversal.
    expect(traversalRequests).toHaveLength(0);
    // H02: depth 2 commits and requests a bounded depth-2 traversal.
    await userEvent.click(screen.getByRole("button", { name: "2 hops" }));
    await userEvent.click(screen.getByRole("button", { name: /^Apply$/ }));
    await waitFor(() => expect(traversalRequests).toHaveLength(1));
    expect(traversalRequests[0]).toBe("2");
    expect(router.state.location.search).toContain("graph_depth=2");
    // H03: depth 3 replaces the depth-2 topology request.
    await userEvent.click(screen.getByRole("button", { name: "3 hops" }));
    await userEvent.click(screen.getByRole("button", { name: /^Apply$/ }));
    await waitFor(() => expect(traversalRequests).toHaveLength(2));
    expect(traversalRequests[1]).toBe("3");
    // H04: committed URL identity reflects the new depth.
    expect(router.state.location.search).toContain("graph_depth=3");
  });
});

describe("PR 35-8 focal exploration", () => {
  it("U21/U23: Explore re-roots History/Graph and clears stale transient graph state", async () => {
    const graphRecorder = resourceListRecorder();
    const obsRecorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder: graphRecorder,
      }),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder: obsRecorder }),
    );
    const { router } = renderAtPath(
      evolutionEntry(`entity_id=${FOCAL}&view=graph`),
    );
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    // Select the focal node so a stale selection panel exists pre-Explore.
    fireEvent.click(await screen.findByTestId(`rf__node-n:${FOCAL}`));
    expect(await screen.findByText("Entity: update-package.test")).toBeInTheDocument();
    // Right-click the counterparty and Explore it.
    fireEvent.contextMenu(
      document.querySelector(`[data-testid="rf__node-n:${COUNTERPARTY}"]`) as Element,
    );
    await userEvent.click(await screen.findByTestId("graph-explore-entity"));
    await waitFor(() => {
      expect(router.state.location.search).toContain(`entity_id=${COUNTERPARTY}`);
    });
    // The stale focal selection panel is cleared on the root change.
    await waitFor(() => {
      expect(screen.queryByText("Entity: update-package.test")).not.toBeInTheDocument();
    });
    // The re-root issued a fresh graph request rooted at the new focal.
    expect(graphRecorder.requests.at(-1)?.params.entity_id).toBe(COUNTERPARTY);
    // The History observation query follows the new focal Entity.
    await userEvent.click(screen.getByRole("button", { name: "Evolution" }));
    await waitFor(() => {
      expect(obsRecorder.requests.at(-1)?.params.entity_id).toBe(COUNTERPARTY);
    });
  });

  it("U25/U27: History shows the canonical focal value linked to Entity details", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder: resourceListRecorder(),
      }),
      evolutionObservationsHandler({ pages: [[obsA()]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    const value = await screen.findByTestId("focal-entity-value");
    expect(value).toHaveTextContent("update-package.test");
    expect(value).toHaveAttribute(
      "href",
      `/investigations/${INVESTIGATION_ID}/entities/${FOCAL}`,
    );
    expect(
      document.querySelector('[data-ati-id="relationship.focal-entity"]'),
    ).not.toBeNull();
  });

  it("U26: the Graph view shows the same canonical focal value", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder,
      }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}&view=graph`));
    const value = await screen.findByTestId("focal-entity-value");
    expect(value).toHaveTextContent("update-package.test");
  });

  it("U28: zero history rows still shows the focal value from the exact read", async () => {
    const recorder = resourceListRecorder();
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: buildGraphNeighborhood(),
        recorder: resourceListRecorder(),
      }),
      evolutionObservationsHandler({ pages: [[]], recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}`));
    expect(await screen.findByTestId("focal-entity-value")).toHaveTextContent(
      "update-package.test",
    );
  });

  it("U29: an empty graph still shows the focal value", async () => {
    const recorder = resourceListRecorder();
    const focalOnly = buildGraphNeighborhood({
      nodes: [buildGraphNeighborhood().nodes[0]],
      edges: [],
    });
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({ neighborhood: focalOnly, recorder }),
    );
    renderAtPath(evolutionEntry(`entity_id=${FOCAL}&view=graph`));
    expect(await screen.findByTestId("focal-entity-value")).toHaveTextContent(
      "update-package.test",
    );
  });

  it("U30: no valid focal Entity renders no fabricated indicator", async () => {
    setHttpHandlers(...authHandlers());
    renderAtPath(EVOLUTION_BASE);
    expect(
      await screen.findByText("Choose an entity to view relationship evolution."),
    ).toBeInTheDocument();
    expect(
      document.querySelector('[data-ati-id="relationship.focal-entity"]'),
    ).toBeNull();
    expect(screen.queryByTestId("focal-entity-value")).not.toBeInTheDocument();
  });
});

describe("PR 35-8 focal Explore Back navigation", () => {
  const C_ENTITY = "40000000-0000-4000-8000-000000000103";

  /** A three-node graph so A -> B -> C exploration can be exercised. */
  function threeNodeNeighborhood() {
    return buildGraphNeighborhood({
      nodes: [
        buildGraphNode({
          entity_id: FOCAL,
          entity_type: "domain",
          value: "update-package.test",
          display_name: "update-package.test",
        }),
        buildGraphNode({
          entity_id: COUNTERPARTY,
          entity_type: "ip_address",
          value: "203.0.113.10",
          display_name: "203.0.113.10",
        }),
        buildGraphNode({
          entity_id: C_ENTITY,
          entity_type: "url",
          value: "https://evil.example/payload",
          display_name: "https://evil.example/payload",
        }),
      ],
      edges: [
        buildGraphEdge({
          source_entity_id: FOCAL,
          target_entity_id: COUNTERPARTY,
        }),
        buildGraphEdge({
          relationship_id: "40000000-0000-4000-8000-000000000022",
          source_entity_id: FOCAL,
          target_entity_id: C_ENTITY,
        }),
      ],
    });
  }

  function renderExploration(extraParams = "", state?: unknown) {
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: threeNodeNeighborhood(),
        recorder: resourceListRecorder(),
      }),
    );
    return renderAtPath({
      pathname: `${EVOLUTION_BASE}`,
      search: `?entity_id=${FOCAL}&view=graph${extraParams}`,
      ...(state === undefined ? {} : { state }),
    });
  }

  async function explore(entityId: string): Promise<void> {
    fireEvent.contextMenu(
      document.querySelector(`[data-testid="rf__node-n:${entityId}"]`) as Element,
    );
    await userEvent.click(await screen.findByTestId("graph-explore-entity"));
  }

  function locationString(location: { pathname: string; search: string; hash: string }): string {
    return `${location.pathname}${location.search}${location.hash}`;
  }

  it("N01/N02/N07/N08: Graph A -> Explore B stores the exact A Graph and B Back returns to it", async () => {
    const { router } = renderExploration(
      "&graph_scope=known&direction=source&graph_temporal=1&graph_time_start=2026-02-01T00:00:00Z&graph_time_end=2026-02-09T00:00:00Z",
    );
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    const aLocation = locationString(router.state.location);
    await explore(COUNTERPARTY);
    await waitFor(() => {
      expect(router.state.location.search).toContain(`entity_id=${COUNTERPARTY}`);
    });
    // N01: the URL focal is B and the Graph view is preserved.
    const bLocation = locationString(router.state.location);
    expect(new URLSearchParams(router.state.location.search).get("view")).toBe(
      "graph",
    );
    // N02: B's Back target is the exact A Graph location (including filters
    // and temporal state).
    const back = await screen.findByRole("button", { name: "< Back" });
    await userEvent.click(back);
    await waitFor(() => {
      expect(locationString(router.state.location)).toBe(aLocation);
    });
    // N07/N08: filters and temporal params are restored exactly.
    const restored = new URLSearchParams(router.state.location.search);
    expect(restored.get("graph_scope")).toBe("known");
    expect(restored.get("direction")).toBe("source");
    expect(restored.get("graph_temporal")).toBe("1");
    expect(restored.get("graph_time_start")).toBe("2026-02-01T00:00:00Z");
    expect(restored.get("graph_time_end")).toBe("2026-02-09T00:00:00Z");
    // Sanity: B's location was not the A location.
    expect(bLocation).not.toBe(aLocation);
  });

  it("N04/N05/N06: A -> B -> C unwinds C -> B -> A exactly", async () => {
    const { router } = renderExploration();
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    const aLocation = locationString(router.state.location);
    await explore(COUNTERPARTY);
    await waitFor(() => {
      expect(router.state.location.search).toContain(`entity_id=${COUNTERPARTY}`);
    });
    const bLocation = locationString(router.state.location);
    await explore(C_ENTITY);
    await waitFor(() => {
      expect(router.state.location.search).toContain(`entity_id=${C_ENTITY}`);
    });
    // N05: C Back -> exact B Graph.
    await userEvent.click(await screen.findByRole("button", { name: "< Back" }));
    await waitFor(() => {
      expect(locationString(router.state.location)).toBe(bLocation);
    });
    // N06: B Back -> exact A Graph.
    await userEvent.click(await screen.findByRole("button", { name: "< Back" }));
    await waitFor(() => {
      expect(locationString(router.state.location)).toBe(aLocation);
    });
  });

  it("N03: Explore pushes A ahead of an older ancestor R, which remains after A", async () => {
    const ancestor = `/investigations/${INVESTIGATION_ID}/evidence?source=rdap#top`;
    setHttpHandlers(
      ...authHandlers(),
      graphNeighborhoodHandler({
        neighborhood: threeNodeNeighborhood(),
        recorder: resourceListRecorder(),
      }),
      http.get("*/api/v1/investigations/:id/evidence", () =>
        jsonResponse({ items: [], next_cursor: null }),
      ),
    );
    const { router } = renderAtPath({
      pathname: `${EVOLUTION_BASE}`,
      search: `?entity_id=${FOCAL}&view=graph`,
      state: {
        navigation: {
          returns: [
            {
              pathname: `/investigations/${INVESTIGATION_ID}/evidence`,
              search: "?source=rdap",
              hash: "#top",
            },
          ],
        },
      },
    });
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    const aLocation = locationString(router.state.location);
    await explore(COUNTERPARTY);
    await waitFor(() => {
      expect(router.state.location.search).toContain(`entity_id=${COUNTERPARTY}`);
    });
    // First Back -> A (the immediately preceding Graph), not R.
    await userEvent.click(await screen.findByRole("button", { name: "< Back" }));
    await waitFor(() => {
      expect(locationString(router.state.location)).toBe(aLocation);
    });
    // Second Back -> the older ancestor R, still preserved after A.
    await userEvent.click(await screen.findByRole("button", { name: "< Back" }));
    await waitFor(() => {
      expect(locationString(router.state.location)).toBe(ancestor);
    });
  });
});
