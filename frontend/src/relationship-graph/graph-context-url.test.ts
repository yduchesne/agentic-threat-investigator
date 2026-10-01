// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Graph-route context codec tests (PR 31G FE01..FE11, FE37).
//
// The committed graph context (Investigation/Known scope + filters) has one
// authority: the Graph route URL. These tests prove absent scope defaults to
// Investigation, Known/filter values reconstruct, malformed enum/timestamp
// values canonicalize safely, Clear removes optional params, refresh and
// Back/Forward round-trip exactly, unrelated URL params are preserved, and
// the canonical URL stays minimal (Investigation scope is omitted).

import { describe, expect, it } from "vitest";

import {
  applyGraphContext,
  emptyGraphContext,
  graphContextActive,
  graphContextEqual,
  graphContextKey,
  parseGraphContext,
} from "./graph-context-url";

function ps(query: string): URLSearchParams {
  return new URLSearchParams(query);
}

const KNOWN = "urn:ati:relationship:dns:resolves_to";

describe("PR 31G graph context URL codec", () => {
  it("FE01: absent params are Investigation scope with no optional filters", () => {
    const context = parseGraphContext(ps(""));
    expect(context.scope).toBe("investigation");
    expect(context.entityType).toBeUndefined();
    expect(context.relationshipType).toBeUndefined();
    expect(context.source).toBeUndefined();
    expect(context.observedFrom).toBeUndefined();
    expect(context.observedTo).toBeUndefined();
    expect(graphContextActive(context)).toBe(false);
  });

  it("FE02: a Known scope URL reconstructs to Known", () => {
    const context = parseGraphContext(ps("graph_scope=known"));
    expect(context.scope).toBe("known");
    expect(graphContextActive(context)).toBe(false);
  });

  it("FE03: a connected Entity type URL reconstructs", () => {
    const context = parseGraphContext(ps("graph_entity_type=ip_address"));
    expect(context.entityType).toBe("ip_address");
    expect(graphContextActive(context)).toBe(true);
  });

  it("FE04: a Relationship type URL reconstructs", () => {
    const context = parseGraphContext(ps(`graph_relationship_type=${KNOWN}`));
    expect(context.relationshipType).toBe(KNOWN);
  });

  it("FE05: an observation source URL reconstructs", () => {
    const context = parseGraphContext(ps("graph_source=rdap"));
    expect(context.source).toBe("rdap");
  });

  it("FE06: an observed interval URL reconstructs", () => {
    const context = parseGraphContext(
      ps("graph_observed_from=2026-01-01T00:00:00Z&graph_observed_to=2026-02-01T00:00:00Z"),
    );
    expect(context.observedFrom).toBe("2026-01-01T00:00:00Z");
    expect(context.observedTo).toBe("2026-02-01T00:00:00Z");
  });

  it("FE07: malformed enum/timestamp values canonicalize to absence", () => {
    const context = parseGraphContext(
      ps(
        "graph_scope=global&graph_entity_type=wallet&graph_relationship_type=nope:urn" +
          "&graph_source=   &graph_observed_from=not-a-date",
      ),
    );
    expect(context.scope).toBe("investigation");
    expect(context.entityType).toBeUndefined();
    expect(context.relationshipType).toBeUndefined();
    expect(context.source).toBeUndefined();
    expect(context.observedFrom).toBeUndefined();
  });

  it("FE08: Clear produces an empty context and removes owned params", () => {
    const applied = applyGraphContext(
      ps("graph_scope=known&graph_source=rdap&unrelated=keep"),
      emptyGraphContext(),
    );
    expect(applied.get("graph_scope")).toBeNull();
    expect(applied.get("graph_source")).toBeNull();
    // Unrelated parameters are preserved.
    expect(applied.get("unrelated")).toBe("keep");
  });

  it("FE09/FE10: refresh and Back/Forward round-trip exactly", () => {
    const context: ReturnType<typeof parseGraphContext> = {
      scope: "known",
      entityType: "asn",
      relationshipType: KNOWN,
      source: "rdap",
      observedFrom: "2026-01-01T00:00:00Z",
      observedTo: "2026-02-01T00:00:00Z",
    };
    const url = applyGraphContext(ps("unrelated=x"), context);
    const reparsed = parseGraphContext(url);
    expect(graphContextEqual(reparsed, context)).toBe(true);
    expect(url.get("unrelated")).toBe("x");
  });

  it("FE11: unrelated URL parameters are preserved by Apply", () => {
    const applied = applyGraphContext(ps("entity_id=abc&view=graph&cursor=x&selected=y"), {
      scope: "known",
      entityType: undefined,
      relationshipType: undefined,
      source: undefined,
      observedFrom: undefined,
      observedTo: undefined,
    });
    expect(applied.get("entity_id")).toBe("abc");
    expect(applied.get("view")).toBe("graph");
    expect(applied.get("cursor")).toBe("x");
    expect(applied.get("selected")).toBe("y");
    expect(applied.get("graph_scope")).toBe("known");
  });

  it("FE37: the canonical URL omits the default Investigation scope", () => {
    const minimal = applyGraphContext(ps(""), emptyGraphContext());
    expect(minimal.toString()).not.toContain("graph_scope");
    const known = applyGraphContext(ps(""), {
      scope: "known",
      entityType: undefined,
      relationshipType: undefined,
      source: undefined,
      observedFrom: undefined,
      observedTo: undefined,
    });
    expect(known.get("graph_scope")).toBe("known");
    // Re-parsing the minimal URL restores Investigation (converges).
    expect(parseGraphContext(minimal).scope).toBe("investigation");
  });

  it("graphContextKey distinguishes every semantic coordinate", () => {
    const base = emptyGraphContext();
    expect(graphContextKey(base)).not.toBe(
      graphContextKey({ ...base, scope: "known" }),
    );
    expect(graphContextKey(base)).not.toBe(
      graphContextKey({ ...base, entityType: "ip_address" }),
    );
    expect(graphContextKey(base)).not.toBe(
      graphContextKey({ ...base, source: "rdap" }),
    );
  });
});
