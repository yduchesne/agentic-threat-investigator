// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Generic Entity details route tests (PR 35-8 Part 6, U36..U41).
//
// The Entity details surface renders the exact canonical Entity
// value/type/ID, never a fabricated value, and its contextual ``< Back``
// restores the exact originating workspace when reached from a focal
// indicator, otherwise a safe canonical Investigation fallback.

import { fireEvent, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildGraphNeighborhood,
  completedInvestigationFixture,
  graphNeighborhoodHandler,
  graphRelationshipsHandler,
  investigationDetailHandler,
  resourceListRecorder,
  runtimeFake,
} from "../test/handlers";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const FOCAL = "40000000-0000-4000-8000-000000000101";
const ENTITY_BASE = `/investigations/${INVESTIGATION_ID}/entities/${FOCAL}`;
const GRAPH_BASE = `/investigations/${INVESTIGATION_ID}/relationships/evolution`;
const REL_BASE = `/investigations/${INVESTIGATION_ID}/relationships`;

function authHandlers() {
  return [
    authMeSuccess,
    runtimeFake,
    investigationDetailHandler(
      completedInvestigationFixture({ id: INVESTIGATION_ID }),
    ),
  ];
}

function entityReadHandler() {
  return graphNeighborhoodHandler({
    neighborhood: buildGraphNeighborhood(),
    recorder: resourceListRecorder(),
  });
}

describe("PR 35-8 generic Entity details", () => {
  it("U36: a valid Entity renders value/type and the canonical copyable ID", async () => {
    setHttpHandlers(...authHandlers(), entityReadHandler());
    renderAtPath(ENTITY_BASE);
    expect(
      await screen.findByRole("heading", { name: "Entity details" }),
    ).toBeInTheDocument();
    expect(await screen.findByText("update-package.test")).toBeInTheDocument();
    expect(screen.getByText("Domain")).toBeInTheDocument();
    expect(screen.getByText("Entity ID")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /Copy ID/ }).length).toBeGreaterThan(0);
  });

  it("U37: graph -> details -> Back returns to the exact graph origin", async () => {
    setHttpHandlers(
      ...authHandlers(),
      entityReadHandler(),
      graphRelationshipsHandler({ pages: [[]], recorder: resourceListRecorder() }),
    );
    const { router } = renderAtPath(
      `${GRAPH_BASE}?entity_id=${FOCAL}&view=graph&graph_scope=known`,
    );
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    await userEvent.click(await screen.findByTestId("focal-entity-value"));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(
        `/investigations/${INVESTIGATION_ID}/entities/${FOCAL}`,
      );
    });
    await screen.findByRole("heading", { name: "Entity details" });
    await userEvent.click(screen.getByTestId("resource-route-detail-back"));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(
        `${GRAPH_BASE}`,
      );
    });
    expect(router.state.location.search).toContain("view=graph");
    expect(router.state.location.search).toContain("graph_scope=known");
  });

  it("U38: focal Relationships -> details -> Back returns to the exact table", async () => {
    setHttpHandlers(
      ...authHandlers(),
      entityReadHandler(),
      graphRelationshipsHandler({ pages: [[]], recorder: resourceListRecorder() }),
    );
    const { router } = renderAtPath(`${REL_BASE}?entity_id=${FOCAL}`);
    await screen.findByTestId("focal-entity-value");
    await userEvent.click(await screen.findByTestId("focal-entity-value"));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(
        `/investigations/${INVESTIGATION_ID}/entities/${FOCAL}`,
      );
    });
    await screen.findByRole("heading", { name: "Entity details" });
    await userEvent.click(screen.getByTestId("resource-route-detail-back"));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(REL_BASE);
    });
    expect(router.state.location.search).toBe(`?entity_id=${FOCAL}`);
  });

  it("U39: graph -> Relationships table -> Back unwinds one navigation level at a time", async () => {
    setHttpHandlers(
      ...authHandlers(),
      entityReadHandler(),
      graphRelationshipsHandler({ pages: [[]], recorder: resourceListRecorder() }),
    );
    const { router } = renderAtPath(
      `${GRAPH_BASE}?entity_id=${FOCAL}&view=graph`,
    );
    await screen.findByRole("table", { name: "Relationship list (this page)" });
    // PR 38-10: the redundant graph-local focal Relationships-table link is
    // gone; the supported path to the Relationships workspace is the focal
    // entity pivot (normal Relationships navigation remains elsewhere).
    expect(
      screen.queryByRole("link", {
        name: "Open Relationships table for focal entity",
      }),
    ).toBeNull();
    fireEvent.click(await screen.findByTestId(`rf__node-n:${FOCAL}`));
    await userEvent.click(
      await screen.findByRole("button", {
        name: "Pivot actions for update-package.test",
      }),
    );
    await userEvent.click(
      await screen.findByRole("link", { name: "Relationships where source" }),
    );
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(REL_BASE);
    });
    expect(router.state.location.search).toContain(`source_entity_id=${FOCAL}`);
    // The contextual Back unwinds exactly one level back to the graph.
    await userEvent.click(await screen.findByRole("button", { name: "< Back" }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe(`${GRAPH_BASE}`);
    });
    expect(router.state.location.search).toContain("view=graph");
  });

  it("U40: a direct details deep link uses the safe canonical Investigation fallback", async () => {
    setHttpHandlers(...authHandlers(), entityReadHandler());
    renderAtPath(ENTITY_BASE);
    const back = await screen.findByTestId("resource-route-detail-back");
    expect(back).toHaveAttribute(
      "href",
      `${REL_BASE}?entity_id=${FOCAL}`,
    );
  });

  it("U41: a malformed Entity ID fails closed with a bounded not-found", async () => {
    setHttpHandlers(...authHandlers());
    renderAtPath(`/investigations/${INVESTIGATION_ID}/entities/not-a-uuid`);
    expect(
      await screen.findByText("Entity not found or not accessible."),
    ).toBeInTheDocument();
    // No Entity read was ever issued for the malformed identity.
    expect(screen.queryByText("update-package.test")).not.toBeInTheDocument();
  });
});
