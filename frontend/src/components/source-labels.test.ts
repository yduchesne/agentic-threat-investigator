// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from "vitest";

import { sourceLabel, sourceLabelWithUrn } from "./source-labels";

const labels: Readonly<Record<string, string>> = {
  "sources.threatFox": "ThreatFox",
  "sources.rdap": "RDAP",
  "sources.googlePublicDns": "Google Public DNS",
};

const t = (key: string): string => labels[key] ?? key;

describe("source labels", () => {
  it("localizes known ATI source URNs", () => {
    expect(sourceLabel("urn:ati:source:threatfox", t)).toBe("ThreatFox");
    expect(sourceLabel("urn:ati:source:rdap", t)).toBe("RDAP");
    expect(sourceLabel("urn:ati:source:google_public_dns", t)).toBe("Google Public DNS");
  });

  it("keeps unknown source identifiers as a safe raw fallback", () => {
    expect(sourceLabel("urn:ati:source:future", t)).toBe("urn:ati:source:future");
  });

  it("renders detail sources as localized label followed by the technical URN", () => {
    expect(sourceLabelWithUrn("urn:ati:source:threatfox", t)).toBe(
      "ThreatFox (urn:ati:source:threatfox)",
    );
  });

  it("does not duplicate an unknown source identifier", () => {
    expect(sourceLabelWithUrn("fake-dns", t)).toBe("fake-dns");
  });
});
