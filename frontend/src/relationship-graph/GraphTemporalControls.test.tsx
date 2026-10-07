// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 38-8 temporal-controls contract tests (T-C01..T-C15).
//
// The draft represents each boundary as a required local DATE plus an
// OPTIONAL local TIME; a blank time normalizes to local midnight. A neutral
// draft defaults the end DATE to the browser-local current calendar date
// (never a UTC slice). There is no Time frames selector, no Previous/Next
// frame navigation, and no frame status, and a draft edit never commits.

import { fireEvent, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { describe, expect, it, vi } from "vitest";

import { renderProviders } from "../test/render";
import {
  emptyGraphTemporalContext,
  type GraphTemporalContext,
} from "./graph-temporal";
import {
  GraphTemporalControls,
  graphTemporalBoundaryToIso,
  graphTemporalDraftError,
  graphTemporalDraftFromCommitted,
  graphTemporalDraftToCommitted,
  localToday,
  type GraphTemporalDraft,
} from "./GraphTemporalControls";

/** A fixed instant for deterministic neutral-draft initialization. */
const FIXED_NOW = new Date(2026, 9, 6, 15, 30, 0);

/** One controlled temporal form harness (mirrors useFilterForm semantics). */
function Harness({
  committed = emptyGraphTemporalContext(),
  now = FIXED_NOW,
  onCommit,
}: {
  committed?: GraphTemporalContext;
  now?: Date;
  onCommit: (next: GraphTemporalContext, draft: GraphTemporalDraft) => void;
}): ReturnType<typeof GraphTemporalControls> {
  const { t } = useTranslation("relationshipEvolution");
  const [draft, setDraft] = useState<GraphTemporalDraft>(() =>
    graphTemporalDraftFromCommitted(committed, now),
  );
  const [error, setError] = useState<string | null>(null);
  return (
    <GraphTemporalControls
      t={t as never}
      committed={committed}
      draft={draft}
      error={error}
      onSetDraft={(next) => {
        setDraft(next);
        setError(null);
      }}
      onApply={() => {
        const validation = graphTemporalDraftError(t as never, draft);
        setError(validation);
        if (validation === null) {
          onCommit(graphTemporalDraftToCommitted(draft), draft);
        }
      }}
      onDisable={() => {
        onCommit(emptyGraphTemporalContext(), draft);
      }}
    />
  );
}

function field(label: string): HTMLInputElement {
  return screen.getByLabelText(label, { exact: false }) as HTMLInputElement;
}

describe("PR 38-8 GraphTemporalControls", () => {
  it("T-C01/T-C02/T-C03: neutral draft defaults to blank start and local-today end", () => {
    const draft = graphTemporalDraftFromCommitted(
      emptyGraphTemporalContext(),
      FIXED_NOW,
    );
    expect(draft.temporal).toBe(false);
    expect(draft.startDate).toBe("");
    expect(draft.startTime).toBe("");
    expect(draft.endDate).toBe("2026-10-06");
    expect(draft.endTime).toBe("");
  });

  it("T-C04: a date-only boundary normalizes to local midnight", () => {
    expect(graphTemporalBoundaryToIso("2026-10-06", "")).toBe(
      new Date(2026, 9, 6, 0, 0, 0, 0).toISOString().replace(/\.\d{3}Z$/, "Z"),
    );
  });

  it("T-C05: an explicit non-midnight time is preserved exactly", () => {
    expect(graphTemporalBoundaryToIso("2026-10-06", "13:30")).toBe(
      new Date(2026, 9, 6, 13, 30, 0, 0).toISOString().replace(/\.\d{3}Z$/, "Z"),
    );
  });

  it("T-C06: a missing start date is rejected with localized wording", () => {
    renderProviders(<Harness onCommit={vi.fn()} />);
    fireEvent.click(screen.getByRole("checkbox", { name: "Temporal exploration" }));
    fireEvent.click(screen.getByRole("button", { name: "Apply temporal" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Enter a range start date.",
    );
  });

  it("T-C07: a cleared end date is rejected with localized wording", () => {
    renderProviders(<Harness onCommit={vi.fn()} />);
    fireEvent.click(screen.getByRole("checkbox", { name: "Temporal exploration" }));
    fireEvent.change(field("Range start date"), { target: { value: "2026-10-01" } });
    fireEvent.change(field("Range end date"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply temporal" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter a range end date.");
  });

  it("T-C08: equal normalized bounds are rejected without repair", () => {
    renderProviders(<Harness onCommit={vi.fn()} />);
    fireEvent.click(screen.getByRole("checkbox", { name: "Temporal exploration" }));
    fireEvent.change(field("Range start date"), { target: { value: "2026-10-06" } });
    fireEvent.change(field("Range end date"), { target: { value: "2026-10-06" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply temporal" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Enter a valid observed range with a start before the end.",
    );
  });

  it("T-C09: reversed bounds are rejected without repair", () => {
    renderProviders(<Harness onCommit={vi.fn()} />);
    fireEvent.click(screen.getByRole("checkbox", { name: "Temporal exploration" }));
    fireEvent.change(field("Range start date"), { target: { value: "2026-10-10" } });
    fireEvent.change(field("Range end date"), { target: { value: "2026-10-06" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply temporal" }));
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Enter a valid observed range with a start before the end.",
    );
  });

  it("T-C10: date-only Apply commits exactly one normalized range", () => {
    const onCommit = vi.fn();
    renderProviders(<Harness onCommit={onCommit} />);
    fireEvent.click(screen.getByRole("checkbox", { name: "Temporal exploration" }));
    fireEvent.change(field("Range start date"), { target: { value: "2026-10-01" } });
    fireEvent.change(field("Range end date"), { target: { value: "2026-10-08" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply temporal" }));
    expect(onCommit).toHaveBeenCalledTimes(1);
    const next = onCommit.mock.calls[0][0] as GraphTemporalContext;
    expect(next.temporal).toBe(true);
    expect(next.rangeStart).toBe(graphTemporalBoundaryToIso("2026-10-01", ""));
    expect(next.rangeEnd).toBe(graphTemporalBoundaryToIso("2026-10-08", ""));
  });

  it("T-C11: draft edits never commit", async () => {
    const onCommit = vi.fn();
    renderProviders(<Harness onCommit={onCommit} />);
    await userEvent.click(
      screen.getByRole("checkbox", { name: "Temporal exploration" }),
    );
    fireEvent.change(field("Range start date"), { target: { value: "2026-10-01" } });
    fireEvent.change(field("Range start time"), { target: { value: "09:15" } });
    expect(onCommit).not.toHaveBeenCalled();
  });

  it("T-C12/T-C13: no Time frames or Previous/Next controls render", () => {
    renderProviders(<Harness onCommit={vi.fn()} />);
    expect(screen.queryByText("Time frames")).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Frames" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Previous frame" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Next frame" })).not.toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("T-C14: refresh reconstructs a committed range into date/time fields", () => {
    const committed: GraphTemporalContext = {
      temporal: true,
      rangeStart: graphTemporalBoundaryToIso("2026-10-01", "09:15"),
      rangeEnd: graphTemporalBoundaryToIso("2026-10-08", ""),
    };
    renderProviders(<Harness committed={committed} onCommit={vi.fn()} />);
    expect(field("Range start date").value).toBe("2026-10-01");
    expect(field("Range start time").value).toBe("09:15");
    expect(field("Range end date").value).toBe("2026-10-08");
    expect(field("Range end time").value).toBe("00:00");
  });

  it("T-C15: local-today uses local calendar fields, never a UTC date slice", () => {
    // At a UTC instant whose UTC calendar date (2025-12-31) differs from the
    // local calendar date, the helper must return the LOCAL date.
    const boundaryInstant = {
      getFullYear: () => 2026,
      getMonth: () => 0,
      getDate: () => 1,
      toISOString: () => "2025-12-31T23:30:00.000Z",
    } as unknown as Date;
    expect(localToday(boundaryInstant)).toBe("2026-01-01");
  });
});
