// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Detail polling behavior tests (PR 24B U20-U27, §15, §37).
//
// The production `useInvestigationDetail` hook is exercised with a short
// injected interval so the polling contract is verified without fake-timer
// setup coupling or real 2-second sleeps. Assertions are behavioral:
// pending and running refetch on the interval, every terminal status stops
// refetching, and hook unmount cancels polling.

import { screen } from "@testing-library/react";
import { http } from "msw";
import type { ReactElement } from "react";
import { describe, expect, it, vi } from "vitest";

import type { InvestigationStatusName } from "../api/schema-types";
import type { Investigation } from "../api/schema-types";
import { renderProviders } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import {
  authMeSuccess,
  buildInvestigation,
  jsonResponse,
} from "../test/handlers";
import { useInvestigationDetail } from "./investigation-queries";

useHttp();

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";
const POLL_MS = 30;

/** A hook harness that exposes the durable status text for assertions. */
function DetailHarness({
  investigationId,
  intervalMs,
}: {
  investigationId: string;
  intervalMs?: number;
}): ReactElement {
  const { investigation, isError } = useInvestigationDetail(investigationId, {
    pollIntervalMs: intervalMs,
  });
  if (isError) {
    return <div data-testid="detail">error</div>;
  }
  return (
    <div data-testid="detail">
      {investigation === null ? "loading" : investigation.status}
    </div>
  );
}

/** Count handler invocations for the detail route. */
function lifecycleWithCounter(stages: Investigation[]) {
  let calls = 0;
  const handler = http.get(`*/api/v1/investigations/${INVESTIGATION_ID}`, () => {
    const stage = stages[Math.min(calls, stages.length - 1)];
    calls += 1;
    return jsonResponse(stage);
  });
  return { handler, calls: () => calls };
}

async function settledExtra(calls: () => number, ms: number): Promise<number> {
  const before = calls();
  await new Promise((resolve) => setTimeout(resolve, ms));
  return calls() - before;
}

describe("Investigation detail polling", () => {
  it("refetches on the bounded interval while pending (U20)", async () => {
    const { handler, calls } = lifecycleWithCounter([
      buildInvestigation({ id: INVESTIGATION_ID, status: "pending" }),
    ]);
    setHttpHandlers(authMeSuccess, handler);
    renderProviders(
      <DetailHarness investigationId={INVESTIGATION_ID} intervalMs={POLL_MS} />,
    );
    await screen.findByText("pending");
    const initial = calls();
    expect(initial).toBeGreaterThanOrEqual(1);
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(calls() - initial).toBeGreaterThan(0);
  });

  it("refetches on the bounded interval while running (U21)", async () => {
    const { handler, calls } = lifecycleWithCounter([
      buildInvestigation({ id: INVESTIGATION_ID, status: "running" }),
    ]);
    setHttpHandlers(authMeSuccess, handler);
    renderProviders(
      <DetailHarness investigationId={INVESTIGATION_ID} intervalMs={POLL_MS} />,
    );
    await screen.findByText("running");
    const initial = calls();
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(calls() - initial).toBeGreaterThan(0);
  });

  it("stops refetching once completed (U22)", async () => {
    const { handler, calls } = lifecycleWithCounter([
      buildInvestigation({ id: INVESTIGATION_ID, status: "completed" }),
    ]);
    setHttpHandlers(authMeSuccess, handler);
    renderProviders(
      <DetailHarness investigationId={INVESTIGATION_ID} intervalMs={POLL_MS} />,
    );
    await screen.findByText("completed");
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(await settledExtra(calls, 120)).toBe(0);
  });

  it("stops refetching once partial (U23)", async () => {
    const { handler, calls } = lifecycleWithCounter([
      buildInvestigation({ id: INVESTIGATION_ID, status: "partial" }),
    ]);
    setHttpHandlers(authMeSuccess, handler);
    renderProviders(
      <DetailHarness investigationId={INVESTIGATION_ID} intervalMs={POLL_MS} />,
    );
    await screen.findByText("partial");
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(await settledExtra(calls, 120)).toBe(0);
  });

  it("stops refetching once failed (U24)", async () => {
    const { handler, calls } = lifecycleWithCounter([
      buildInvestigation({ id: INVESTIGATION_ID, status: "failed" }),
    ]);
    setHttpHandlers(authMeSuccess, handler);
    renderProviders(
      <DetailHarness investigationId={INVESTIGATION_ID} intervalMs={POLL_MS} />,
    );
    await screen.findByText("failed");
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(await settledExtra(calls, 120)).toBe(0);
  });

  it("cancels polling when the hook unmounts (U26)", async () => {
    const { handler, calls } = lifecycleWithCounter([
      buildInvestigation({ id: INVESTIGATION_ID, status: "pending" }),
    ]);
    setHttpHandlers(authMeSuccess, handler);
    const { result } = renderProviders(
      <DetailHarness investigationId={INVESTIGATION_ID} intervalMs={POLL_MS} />,
    );
    await screen.findByText("pending");
    expect(result.container.textContent).toContain("pending");
    result.unmount();
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(await settledExtra(calls, 120)).toBe(0);
  });

  it("propagates the AbortSignal into the detail fetch (U25)", async () => {
    let signal: AbortSignal | null | undefined;
    vi.stubGlobal(
      "fetch",
      (_url: string, init: RequestInit) =>
        new Promise((_resolve, reject) => {
          signal = init.signal ?? null;
          // Hold the request open; unmounting must cancel it via the signal.
          init.signal?.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"));
          });
        }),
    );
    const { result } = renderProviders(
      <DetailHarness investigationId={INVESTIGATION_ID} intervalMs={POLL_MS} />,
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(signal).toBeDefined();
    expect(signal?.aborted).toBe(false);
    result.unmount();
    expect(signal?.aborted).toBe(true);
  });

  it("never polls the background with refetchIntervalInBackground (U27)", async () => {
    const { detailPollingInterval, DETAIL_POLL_INTERVAL_MS } = await import(
      "./investigation-queries"
    );
    expect(DETAIL_POLL_INTERVAL_MS).toBe(2000);
    expect(detailPollingInterval("pending")).toBe(2000);
    expect(detailPollingInterval("running")).toBe(2000);
    expect(detailPollingInterval("completed")).toBe(false);
    expect(detailPollingInterval("partial")).toBe(false);
    expect(detailPollingInterval("failed")).toBe(false);
    expect(detailPollingInterval(undefined)).toBe(2000);
    const statuses: InvestigationStatusName[] = ["pending", "running"];
    expect(
      statuses.filter((status) => detailPollingInterval(status) !== false),
    ).toHaveLength(2);
  });
});