// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared analyst-table component tests (PR 24C T01, T02, T03, T08, T09,
// T12, T13, T18).
//
// Renders the generic table directly with synthetic rows; the API surface
// is not involved here.

import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/errors";
import type { Column } from "./types";
import { AnalystTable, type AnalystTableProps } from "./AnalystTable";
import { renderProviders } from "../test/render";

interface Row {
  id: string;
  label: string;
}

const COLUMNS: Column<Row>[] = [
  {
    id: "label",
    header: "Label",
    render: (row) => row.label,
    exportValue: (row) => row.label,
  },
];

function baseProps(overrides: Partial<AnalystTableProps<Row>> = {}): AnalystTableProps<Row> {
  return {
    columns: COLUMNS,
    rows: [{ id: "row-1", label: "alpha" }, { id: "row-2", label: "beta" }],
    getRowId: (row) => row.id,
    ariaLabel: "Test table",
    isLoading: false,
    error: null,
    errorTitle: "Unable to load",
    onRetry: vi.fn(),
    emptyTitle: "Nothing here",
    emptyMessage: "No rows.",
    hasActiveFilters: false,
    onClearFilters: vi.fn(),
    onView: vi.fn(),
    viewLabel: "View",
    navigation: {
      canGoPrevious: false,
      canGoNext: false,
      onPrevious: vi.fn(),
      onNext: vi.fn(),
    },
    loadingLabel: "Loading…",
    staleErrorTitle: "Stale data",
    onReturnToFirstPage: null,
    ...overrides,
  };
}

describe("AnalystTable", () => {
  it("renders rows with semantic headers (T01)", () => {
    renderProviders(<AnalystTable {...baseProps()} />);
    const table = screen.getByRole("table", { name: "Test table" });
    const headers = table.querySelectorAll("th");
    expect(headers).toHaveLength(2); // Label + actions
    expect(headers[0].getAttribute("scope")).toBe("col");
    expect(screen.getByText("alpha")).toBeInTheDocument();
    expect(screen.getByText("beta")).toBeInTheDocument();
    // No sorting affordances exist (T13).
    expect(screen.queryByRole("button", { name: /sort/i })).not.toBeInTheDocument();
  });

  it("renders loading/empty/error states (T02)", () => {
    renderProviders(
      <AnalystTable {...baseProps({ rows: [], isLoading: true })} />,
    );
    expect(screen.getByText("Loading…")).toBeInTheDocument();

    renderProviders(
      <AnalystTable {...baseProps({ rows: [], isLoading: false })} />,
    );
    expect(screen.getByText("Nothing here")).toBeInTheDocument();

    renderProviders(
      <AnalystTable
        {...baseProps({
          rows: [],
          error: new ApiError("api", 500, "internal_error", "boom"),
        })}
      />,
    );
    expect(screen.getByText("Unable to load")).toBeInTheDocument();
  });

  it("renders the cursor-error recovery action (T08)", () => {
    renderProviders(
      <AnalystTable
        {...baseProps({
          rows: [],
          error: new ApiError("api", 422, "invalid_cursor", "cursor"),
          onReturnToFirstPage: vi.fn(),
        })}
      />,
    );
    expect(
      screen.getByRole("button", { name: "Return to first page" }),
    ).toBeInTheDocument();
  });

  it("enables Next only with a next-cursor and rows (T03)", async () => {
    const onNext = vi.fn();
    renderProviders(
      <AnalystTable
        {...baseProps({
          navigation: {
            canGoPrevious: false,
            canGoNext: true,
            onPrevious: vi.fn(),
            onNext,
          },
        })}
      />,
    );
    const next = screen.getByRole("button", { name: "Next page" });
    expect(next).toBeEnabled();
    await userEvent.click(next);
    expect(onNext).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled();
  });

  it("offers a keyboard-operable View action per row (T09)", async () => {
    const onView = vi.fn();
    renderProviders(<AnalystTable {...baseProps({ onView })} />);
    const button = await screen.findByRole("button", { name: "View row-1" });
    await userEvent.click(button);
    expect(onView).toHaveBeenCalledWith({ id: "row-1", label: "alpha" });
  });

  it("keeps stale rows visible under a warning on transient failure (T12)", () => {
    renderProviders(
      <AnalystTable
        {...baseProps({
          error: new ApiError("api", 500, "internal_error", "boom"),
        })}
      />,
    );
    expect(screen.getByText("Stale data")).toBeInTheDocument();
    expect(screen.getByText("alpha")).toBeInTheDocument();
  });

  it("renders the running freshness notice above the rows (T18)", () => {
    renderProviders(
      <AnalystTable {...baseProps({ notice: <span>Investigation still running</span> })} />,
    );
    expect(screen.getByText("Investigation still running")).toBeInTheDocument();
  });
});