// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation status model tests (PR 24B U53, §17, §15).

import { describe, expect, it } from "vitest";

import {
  INVESTIGATION_STATUSES,
  isTerminalStatus,
  statusLabelKey,
} from "./investigation-status";

describe("investigation status model", () => {
  it("covers exactly the five backend statuses (U53)", () => {
    expect(INVESTIGATION_STATUSES).toEqual([
      "pending",
      "running",
      "completed",
      "partial",
      "failed",
    ]);
  });

  it("maps every status to a label key (U53)", () => {
    for (const status of INVESTIGATION_STATUSES) {
      expect(statusLabelKey(status)).toMatch(/^status\./);
    }
  });

  it("treats completed/partial/failed as terminal (polling stop)", () => {
    expect(isTerminalStatus("completed")).toBe(true);
    expect(isTerminalStatus("partial")).toBe(true);
    expect(isTerminalStatus("failed")).toBe(true);
    expect(isTerminalStatus("pending")).toBe(false);
    expect(isTerminalStatus("running")).toBe(false);
    expect(isTerminalStatus(undefined)).toBe(false);
  });
});