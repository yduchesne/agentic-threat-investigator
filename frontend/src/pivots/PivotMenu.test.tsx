// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PivotMenu behavior tests (PR 24D §8, §22, §24-§25).
//
// The trigger renders a direct accessible action for one legal target and
// an accessible menu for several; no-op actions against the active step
// are suppressed; at the maximum pivot depth the trigger is omitted; and
// the action pushes a valid URL-backed step that opens the modal.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http } from "msw";
import { describe, expect, it } from "vitest";

import { renderAtPath } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildEvidence,
  buildObservation,
  completedInvestigationFixture,
  investigationDetailHandler,
  jsonResponse,
  pagedResourceHandler,
  resourceListRecorder,
  runtimeFake,
  uuidAt,
} from "../test/handlers";
import { decodeBase64Url, readPivotState, serializePivotState } from "./pivot-url";
import { MAX_PIVOT_STEPS, type PivotStep } from "./pivot-types";

useHttp();

const AUTH = [authMeSuccess, runtimeFake];
const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const BASE = `/investigations/${INVESTIGATION_ID}`;
const ENTITY_ID = uuidAt(101);
const RELATIONSHIP_ID = uuidAt(21);
const EVIDENCE_ID = uuidAt(1);

function workspaceHandler() {
  return investigationDetailHandler(
    completedInvestigationFixture({ id: INVESTIGATION_ID }),
  );
}

function installHandlers() {
  const recorder = resourceListRecorder();
  setHttpHandlers(
    ...AUTH,
    workspaceHandler(),
    http
      .get("*/api/v1/investigations/:id/evidence", () =>
        jsonResponse({ items: [evidenceFixture()], next_cursor: null })),
    pagedResourceHandler({
      path: "*/api/v1/investigations/:id/relationship-observations",
      pages: [[buildObservation({ relationship_id: RELATIONSHIP_ID, evidence_id: EVIDENCE_ID })]],
      recorder,
    }),
  );
  return recorder;
}

function evidenceFixture() {
  return buildEvidence({
    id: EVIDENCE_ID,
    subject_entity_id: ENTITY_ID,
    subject_value: "update-package.test",
  });
}

// The single-action surface: one observation-rendered trigger inside the
// relationship-observations route cell (evidence id cell; single action).
function observationRowRoute(): string {
  return `${BASE}/relationships/observations`;
}

describe("PivotMenu", () => {
  it("renders a direct accessible action for a single legal target", async () => {
    installHandlers();
    renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    // Evidence subject exposes four actions -> a menu trigger.
    const trigger = screen.getByRole("button", { name: "Subject" });
    expect(trigger).toHaveAttribute("aria-haspopup", "menu");
    await userEvent.click(trigger);
    expect(await screen.findByRole("menuitem", { name: "Evidence for this entity" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("menuitem", { name: "Research for this entity" }));
    const dialog = await screen.findByRole("dialog", { name: /Research pivot workspace/i });
    expect(dialog).toBeInTheDocument();
  });

  it("pushes the exact target filters and keeps them reachable in the URL", async () => {
    installHandlers();
    const { router } = renderAtPath(`${BASE}/evidence`);
    await screen.findByText("update-package.test");
    await userEvent.click(screen.getByRole("button", { name: "Subject" }));
    await userEvent.click(await screen.findByRole("menuitem", { name: "Relationships where source" }));
    const state = readPivotState(new URLSearchParams(router.state.location.search));
    expect(state?.steps).toHaveLength(1);
    expect(decodeBase64Url(new URLSearchParams(router.state.location.search).get("pivot") ?? ""))
      .toContain('"source_entity_id"');
  });

  it("suppresses no-op targets matching the active step context", async () => {
    const evidenceStep: PivotStep = {
      resource: "evidence",
      filters: { subject_entity_id: ENTITY_ID },
      selectedId: null,
      label: "update-package.test",
      sourceKind: "table_cell",
    };
    const pivot = serializePivotState({ steps: [evidenceStep] });
    installHandlers();
    renderAtPath(`${BASE}/evidence?pivot=${pivot ?? ""}`);
    await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
    // The active evidence step renders its table; the same-resource no-op
    // actions are suppressed, so no pivot trigger is present at all.
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Subject" })).toBeNull();
      expect(screen.queryByRole("button", { name: "Pivot actions" })).toBeNull();
    });
  });

  it("omits the trigger entirely at the maximum pivot depth", async () => {
    const steps: PivotStep[] = Array.from({ length: MAX_PIVOT_STEPS }, (_, index) =>
      ({
        resource: "evidence",
        filters: { subject_entity_id: uuidAt(100 + index) },
        selectedId: null,
        label: `Entity ${uuidAt(100 + index).slice(0, 8)}`,
        sourceKind: "table_cell",
      }) as PivotStep);
    const pivot = serializePivotState({ steps });
    installHandlers();
    renderAtPath(`${BASE}/evidence?pivot=${pivot ?? ""}`);
    await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
    await waitFor(() => {
      expect(screen.queryByRole("button", { name: "Subject" })).toBeNull();
    });
  });

  it("renders a direct action label for a single observation target", async () => {
    installHandlers();
    renderAtPath(observationRowRoute());
    // Each row cell exposes the two observation actions through an
    // accessible menu trigger; wait for the loaded row first.
    await waitFor(() => {
      expect(screen.queryAllByRole("button", { name: "Evidence" }).length).toBeGreaterThan(0);
    });
    const evidenceCellButton = screen.getAllByRole("button", { name: "Evidence" })[0];
    await userEvent.click(evidenceCellButton);
    expect(await screen.findByRole("menuitem", { name: "Observations for this relationship" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("menuitem", { name: "Open evidence" }));
    await screen.findByRole("dialog", { name: /Evidence pivot workspace/i });
  });
});