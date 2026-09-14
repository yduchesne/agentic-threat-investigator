// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Graph component tests (PR 24E E-G05..E-G11).
//
// The graph is a bounded one-hop visualization of stable Relationships.
// The canvas itself is a visualization detail (no brittle pixel/layout
// snapshots); the always-present accessible edge list carries the exact-ID
// navigation, the bounded-neighborhood notice is ordinary text, and the
// empty state is explicit. Node/edge identity semantics live in the pure
// model tests (relationship-graph-model.test.ts).

import { screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildRelationship,
  completedInvestigationFixture,
  graphRelationshipsHandler,
  investigationDetailHandler,
  resourceListRecorder,
  runtimeFake,
} from "../test/handlers";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const FOCAL = "40000000-0000-4000-8000-000000000101";
const B = "40000000-0000-4000-8000-000000000102";

function graphEntry(): string {
  return (
    `/investigations/${INVESTIGATION_ID}/relationships/evolution` +
    `?entity_id=${FOCAL}&view=graph&observed_from=2026-06-01T00:00:00Z`
  );
}

function renderGraph(pages: ReturnType<typeof buildRelationship>[][]) {
  const recorder = resourceListRecorder();
  setHttpHandlers(
    authMeSuccess,
    runtimeFake,
    investigationDetailHandler(
      completedInvestigationFixture({ id: INVESTIGATION_ID }),
    ),
    graphRelationshipsHandler({ pages, recorder }),
  );
  renderAtPath(graphEntry());
  return recorder;
}

describe("Relationship Graph workspace", () => {
  it("E-G05/E-G07/E-G11: the accessible edge list carries exact Relationship and Evolution navigation", async () => {
    renderGraph([
      [
        buildRelationship({
          id: "40000000-0000-4000-8000-000000000021",
          source_entity_id: FOCAL,
          target_entity_id: B,
        }),
      ],
    ]);
    // Non-spatial list alternative is always available.
    const list = await screen.findByRole("table", {
      name: "Relationship list (this page)",
    });
    expect(await within(list).findByRole("link", { name: "View" })).toHaveAttribute(
      "href",
      `/investigations/${INVESTIGATION_ID}/relationships?selected=40000000-0000-4000-8000-000000000021`,
    );
    // Edge -> Evolution keeps Investigation + exact entity identity.
    expect(within(list).getByRole("link", { name: "View evolution" })).toHaveAttribute(
      "href",
      `/investigations/${INVESTIGATION_ID}/relationships/evolution?entity_id=${B}`,
    );
    // "Open Relationships table for focal entity" uses the exact server
    // entity_id filter.
    expect(
      screen.getByRole("link", { name: "Open Relationships table for focal entity" }),
    ).toHaveAttribute(
      "href",
      `/investigations/${INVESTIGATION_ID}/relationships?entity_id=${FOCAL}`,
    );
    // Temporal filters are preserved in the URL but do not apply to Graph.
    expect(
      screen.getByText(/apply to Evolution only/i),
    ).toBeInTheDocument();
  });

  it("E-G08: an incomplete neighborhood is honestly labeled", async () => {
    renderGraph([
      [
        buildRelationship({
          id: "40000000-0000-4000-8000-000000000021",
          source_entity_id: FOCAL,
          target_entity_id: B,
        }),
      ],
      [
        buildRelationship({
          id: "40000000-0000-4000-8000-000000000022",
          source_entity_id: FOCAL,
          target_entity_id: "40000000-0000-4000-8000-000000000103",
        }),
      ],
    ]);
    expect(
      await screen.findByText(/Bounded neighborhood; additional relationships exist/),
    ).toBeInTheDocument();
  });

  it("E-G09: no relationships renders an honest empty state via the list", async () => {
    renderGraph([[]]);
    const list = await screen.findByRole("table", {
      name: "Relationship list (this page)",
    });
    // The list is present and empty; no existence claim is made about edges
    // the page could not load (the model itself is bounded to the page).
    expect(within(list).queryByRole("link", { name: "View" })).not.toBeInTheDocument();
  });

  it("the graph query is entity_id-filtered and bounded (limit set)", async () => {
    const recorder = renderGraph([[]]);
    await waitFor(() => {
      const last = recorder.requests.at(-1);
      expect(last?.params.entity_id).toBe(FOCAL);
      expect(last?.params.limit).toBe("25");
    });
  });
});