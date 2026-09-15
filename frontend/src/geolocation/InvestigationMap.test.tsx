// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// InvestigationMap component tests (PR 25B §49 B-F01..B-F08, §21-§28).
//
// The real Leaflet rendering boundary is mocked (react-leaflet-mock) so
// these tests never perform live tile requests and never depend on a
// layout engine; the real path is exercised by the real-stack E24 spec.

import { render, screen, type RenderResult } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { GeoPrecisionName, InvestigationGeolocation } from "../api/schema-types";
import { resetFakeLeafletMap, fakeLeafletMap } from "../test/react-leaflet-mock";
import { InvestigationMap } from "./InvestigationMap";
import { SINGLE_POINT_ZOOM } from "./geolocation-map-model";
import { TILE_ATTRIBUTION, TILE_URL } from "./map-config";

vi.mock("react-leaflet", () => import("../test/react-leaflet-mock"));

const INVESTIGATION_ID = "20000000-0000-4000-8000-000000000001";

function item(
  index: number,
  overrides: Partial<InvestigationGeolocation> = {},
): InvestigationGeolocation {
  return {
    evidence_id: `40000000-0000-4000-8000-0000000000${String(index).padStart(2, "0")}`,
    entity_id: `50000000-0000-4000-8000-0000000000${String(index).padStart(2, "0")}`,
    ip_address: `203.0.113.${index}`,
    country_code: "US",
    region: "Washington",
    city: "Seattle",
    latitude: 47.6062,
    longitude: -122.3321,
    precision: "city" as GeoPrecisionName,
    provider: "urn:ati:source:dbip_city_lite",
    observed_at: null,
    retrieved_at: "2026-06-01T10:00:00Z",
    ...overrides,
  };
}


/** Render one Map under a router so the popup Explore surface sees the URL. */
function renderMap(children: ReactElement): RenderResult {
  return render(<MemoryRouter>{children}</MemoryRouter>);
}

describe("InvestigationMap (B-F01..B-F08)", () => {
  beforeEach(resetFakeLeafletMap);
  afterEach(() => {
    vi.useRealTimers();
  });

  it("B-F01: one mappable item renders exactly one Marker", () => {
    const onViewEvidence = vi.fn();
    renderMap(
      <InvestigationMap
        investigationId={INVESTIGATION_ID}
        items={[item(1)]}
        onViewEvidence={onViewEvidence}
      />,
    );
    expect(screen.getAllByTestId("ati-marker")).toHaveLength(1);
    const marker = screen.getByTestId("ati-marker");
    expect(marker).toHaveAttribute("data-position", JSON.stringify([47.6062, -122.3321]));
    expect(marker).toHaveAttribute("data-alt", "203.0.113.1");
  });

  it("B-F02: multiple mappable items render one Marker per item", () => {
    renderMap(
      <InvestigationMap
        investigationId={INVESTIGATION_ID}
        items={[item(1), item(2, { latitude: 51.5074, longitude: -0.1278 })]}
        onViewEvidence={vi.fn()}
      />,
    );
    expect(screen.getAllByTestId("ati-marker")).toHaveLength(2);
  });

  it("B-F03: an unlocated item never produces a Marker", () => {
    renderMap(
      <InvestigationMap
        investigationId={INVESTIGATION_ID}
        items={[item(1, { latitude: null, longitude: null })]}
        onViewEvidence={vi.fn()}
      />,
    );
    expect(screen.queryByTestId("ati-marker")).not.toBeInTheDocument();
    expect(screen.queryByTestId("ati-map-container")).not.toBeInTheDocument();
  });

  it("B-F04: the popup carries the exact item and Evidence action", async () => {
    const onViewEvidence = vi.fn();
    const exact = item(1, {
      observed_at: "2026-06-01T09:00:00Z",
      ip_address: "198.51.100.42",
    });
    renderMap(
      <InvestigationMap
        investigationId={INVESTIGATION_ID}
        items={[exact]}
        onViewEvidence={onViewEvidence}
      />,
    );
    // The popup content renders inline in the marker replacement.
    expect(screen.getByText("198.51.100.42")).toBeInTheDocument();
    expect(screen.getByText("Seattle, Washington, US")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "View Evidence" }));
    expect(onViewEvidence).toHaveBeenCalledWith(exact.evidence_id);
  });

  it("B-F05: the tile layer carries the centralized OSM attribution/URL", () => {
    renderMap(
      <InvestigationMap
        investigationId={INVESTIGATION_ID}
        items={[item(1)]}
        onViewEvidence={vi.fn()}
      />,
    );
    const tile = screen.getByTestId("ati-tile-layer");
    expect(tile).toHaveAttribute("data-url", TILE_URL);
    expect(tile).toHaveAttribute("data-attribution", TILE_ATTRIBUTION);
    // No secret-bearing or credential-shaped host (policy check).
    expect(TILE_URL).not.toMatch(/key=|token=|apikey=/i);
  });

  it("B-F06: no fabricated precision/accuracy circle is rendered", () => {
    renderMap(
      <InvestigationMap
        investigationId={INVESTIGATION_ID}
        items={[item(1)]}
        onViewEvidence={vi.fn()}
      />,
    );
    expect(screen.queryByTestId(/circle/i)).not.toBeInTheDocument();
    expect(document.querySelector("path.leaflet-interactive")).toBeNull();
  });

  it("B-F07: no clustering plugin/component is used", () => {
    renderMap(
      <InvestigationMap
        investigationId={INVESTIGATION_ID}
        items={[item(1), item(2)]}
        onViewEvidence={vi.fn()}
      />,
    );
    expect(screen.queryByTestId(/cluster/i)).not.toBeInTheDocument();
    // One item per marker is preserved on render (no aggregation).
    expect(screen.getAllByTestId("ati-marker")).toHaveLength(2);
  });

  it("B-F08: unmount leaves no application-owned timer/listener leak", () => {
    vi.useFakeTimers();
    const { unmount } = renderMap(
      <InvestigationMap
        investigationId={INVESTIGATION_ID}
        items={[item(1)]}
        onViewEvidence={vi.fn()}
      />,
    );
    expect(vi.getTimerCount()).toBe(0);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
    // Unmounting is safe (no owned map lifecycle to tear down ourself).
    expect(() => unmount()).not.toThrow();
  });

  it("single-point viewport issues one exact setView command (B-V02 wiring)", () => {
    renderMap(
      <InvestigationMap
        investigationId={INVESTIGATION_ID}
        items={[item(1, { latitude: 47.6062, longitude: -122.3321 })]}
        onViewEvidence={vi.fn()}
      />,
    );
    expect(fakeLeafletMap.setView).toHaveBeenCalledWith(
      [47.6062, -122.3321],
      SINGLE_POINT_ZOOM,
      { animate: false },
    );
    expect(fakeLeafletMap.fitBounds).not.toHaveBeenCalled();
  });

  it("multi-point viewport issues one fitBounds over all mappable points (B-V03 wiring)", () => {
    renderMap(
      <InvestigationMap
        investigationId={INVESTIGATION_ID}
        items={[item(1, { latitude: 10, longitude: -10 }), item(2, { latitude: 20, longitude: 5 })]}
        onViewEvidence={vi.fn()}
      />,
    );
    expect(fakeLeafletMap.fitBounds).toHaveBeenCalledTimes(1);
    const [bounds, options] = fakeLeafletMap.fitBounds.mock.calls[0] as unknown as [
      unknown,
      { padding: [number, number]; maxZoom: number },
    ];
    expect(bounds).toEqual([
      [10, -10],
      [20, 5],
    ]);
    expect(options.padding).toEqual([24, 24]);
    expect(options.maxZoom).toBe(SINGLE_POINT_ZOOM);
    expect(fakeLeafletMap.setView).not.toHaveBeenCalled();
  });
});