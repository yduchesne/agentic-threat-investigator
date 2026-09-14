// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared Investigation freshness decision (PR 24C §15).
//
// While the Investigation is pending/running, analyst tables show persisted
// rows with a small notice + explicit Refresh; they never poll.

import type { ReactElement } from "react";

import type { InvestigationStatusName } from "../api/schema-types";
import { isTerminalStatus } from "../investigations/investigation-status";
import { RunningNotice } from "./RunningNotice";

/** Whether one status should carry the freshness notice. */
export function isRunningStatus(status: InvestigationStatusName | undefined): boolean {
  return status !== undefined && !isTerminalStatus(status);
}

/** Build the freshness notice when the Investigation is not terminal. */
export function runningNotice(
  status: InvestigationStatusName | undefined,
  onRefresh: () => void,
  text: string,
  refreshLabel: string,
): ReactElement | null {
  if (!isRunningStatus(status)) {
    return null;
  }
  return (
    <RunningNotice text={text} onRefresh={onRefresh} refreshLabel={refreshLabel} />
  );
}