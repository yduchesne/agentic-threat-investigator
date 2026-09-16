// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Deterministic versioned pivot URL serializer/parser (PR 24D §1.7, §7,
// §11, §12, §20).
//
// The reserved ``pivot`` search parameter carries a compact base64url
// JSON envelope. Every decoded field is validated before use and unknown
// version/resource/filter/step fields fail closed. The envelope never
// carries Investigation IDs (the route owns them), raw API payloads,
// Report/Research free text, or secrets.
//
// Envelope (v1): { "v": 1, "steps": [ { "r", "f", "s", "l", "k", "c" } ] }
//
//   r  allowlisted target resource
//   f  exact resource-specific allowlisted filters (wire-form keys)
//   s  exact URL-addressable selection id (UUID) or null
//   l  bounded analyst-facing label (breadcrumb identity)
//   k  bounded navigation provenance kind
//   c  bounded opaque cursor (never decoded), omitted when absent
//
// The encoded parameter is capped at 4096 bytes (PR 24D §11), steps are
// capped at MAX_PIVOT_STEPS, and labels/cursors/filter values are bounded.

import type {
  EvidenceTypeName,
  RelationshipDirectionName,
  RelationshipTypeName,
} from "../api/schema-types";
import { isIsoTimestamp, isUuidValue } from "../analyst-table/filters";
import { parseCursorParam } from "../analyst-table/cursor-stack";
import { parseSelectedParam } from "../analyst-table/url-params";
import { EVIDENCE_TYPES } from "../evidence/labels";
import { RELATIONSHIP_DIRECTIONS } from "../relationships/relationships-filters";
import { RELATIONSHIP_TYPES } from "../relationships/labels";
import {
  isPivotResource,
  MAX_PIVOT_CURSOR_CHARS,
  MAX_PIVOT_FILTER_VALUE_CHARS,
  MAX_PIVOT_LABEL_CHARS,
  MAX_PIVOT_STEPS,
  PIVOT_BOOLEAN_FILTER_KEYS,
  PIVOT_FILTER_KEYS,
  PIVOT_SOURCE_KINDS,
  PIVOT_TIMESTAMP_FILTER_KEYS,
  PIVOT_UUID_FILTER_KEYS,
  type PivotFilterSet,
  type PivotResource,
  type PivotSourceKind,
  type PivotState,
  type PivotStep,
} from "./pivot-types";

/** The reserved URL search parameter owning the pivot state. */
export const PIVOT_PARAM = "pivot";

/** The pivot envelope version; unknown versions fail closed. */
export const PIVOT_VERSION = 1;

/** Hard cap on the encoded pivot parameter (PR 24D §11). */
export const MAX_PIVOT_PARAM_BYTES = 4096;

/** Control characters never belong in pivot state values. */
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

/** Opaque cursors are printable ASCII only (never decoded). */
const PRINTABLE_ASCII = /^[\x21-\x7E]+$/;

/** Encode UTF-8 bytes as unpadded base64url (RFC 4648 §5). */
export function encodeBase64Url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode one unpadded base64url value to UTF-8 text; null on any error. */
export function decodeBase64Url(value: string): string | null {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

/** Whether one value is a non-empty bounded free string (source filters). */
function isBoundedString(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= MAX_PIVOT_FILTER_VALUE_CHARS &&
    !CONTROL_CHARS.test(value)
  );
}

/**
 * Parse and validate one resource filter object (allowlisted keys only).
 *
 * UUID, timestamp, and enum keys are validated exactly; unknown keys,
 * empty values, overlong values, and control characters fail closed.
 */
export function parsePivotFilters(
  resource: PivotResource,
  raw: unknown,
): PivotFilterSet | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return null;
  }
  const source = raw as Record<string, unknown>;
  const output: Record<string, string | boolean> = {};
  for (const key of PIVOT_FILTER_KEYS[resource]) {
    const value = source[key];
    if (value === undefined) {
      continue;
    }
    if ((PIVOT_BOOLEAN_FILTER_KEYS[resource] as readonly string[]).includes(key)) {
      if (value === true || value === false) {
        output[key] = value;
        continue;
      }
      return null;
    }
    if (!isBoundedString(value)) {
      return null;
    }
    if ((PIVOT_UUID_FILTER_KEYS[resource] as readonly string[]).includes(key)) {
      if (!isUuidValue(value)) {
        return null;
      }
      output[key] = value.toLowerCase();
      continue;
    }
    if ((PIVOT_TIMESTAMP_FILTER_KEYS[resource] as readonly string[]).includes(key)) {
      if (!isIsoTimestamp(value)) {
        return null;
      }
      output[key] = value;
      continue;
    }
    if (key === "type") {
      if (!(EVIDENCE_TYPES as readonly string[]).includes(value)) {
        return null;
      }
      output[key] = value as EvidenceTypeName;
      continue;
    }
    if (key === "relationship_type") {
      if (!(RELATIONSHIP_TYPES as readonly string[]).includes(value)) {
        return null;
      }
      output[key] = value as RelationshipTypeName;
      continue;
    }
    if (key === "direction") {
      if (!(RELATIONSHIP_DIRECTIONS as readonly string[]).includes(value)) {
        return null;
      }
      output[key] = value as RelationshipDirectionName;
      continue;
    }
    output[key] = value as string;
  }
  // No extra filter keys are ever accepted.
  for (const key of Object.keys(source)) {
    if (!(PIVOT_FILTER_KEYS[resource] as readonly string[]).includes(key)) {
      return null;
    }
  }
  return output as PivotFilterSet;
}

/** Serialize one validated filter set in canonical key order. */
export function serializePivotFilters(
  resource: PivotResource,
  filters: PivotFilterSet,
): Record<string, unknown> {
  const output: Record<string, unknown> = {};
  for (const key of PIVOT_FILTER_KEYS[resource]) {
    const value = (filters as Record<string, unknown>)[key];
    if ((PIVOT_BOOLEAN_FILTER_KEYS[resource] as readonly string[]).includes(key)) {
      if (value === true || value === false) {
        output[key] = value;
      }
      continue;
    }
    if (typeof value === "string" && value !== "") {
      output[key] = value;
    }
  }
  return output;
}

/** Parse and validate one raw envelope step (fail closed). */
export function parsePivotStep(raw: unknown): PivotStep | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return null;
  }
  const source = raw as Record<string, unknown>;
  const allowedKeys = new Set(["r", "f", "s", "l", "k", "c"]);
  for (const key of Object.keys(source)) {
    if (!allowedKeys.has(key)) {
      return null;
    }
  }
  const resourceName = source.r;
  if (typeof resourceName !== "string" || !isPivotResource(resourceName)) {
    return null;
  }
  const resource = resourceName;
  const filters = parsePivotFilters(resource, source.f);
  if (filters === null) {
    return null;
  }
  if (source.s !== null) {
    if (typeof source.s !== "string" || !isUuidValue(source.s)) {
      return null;
    }
  }
  if (
    typeof source.l !== "string" ||
    source.l.length < 1 ||
    source.l.length > MAX_PIVOT_LABEL_CHARS ||
    CONTROL_CHARS.test(source.l)
  ) {
    return null;
  }
  const kind = source.k;
  if (
    typeof kind !== "string" ||
    !(PIVOT_SOURCE_KINDS as readonly string[]).includes(kind)
  ) {
    return null;
  }
  let cursor: string | undefined;
  if (source.c !== undefined && source.c !== null) {
    if (
      typeof source.c !== "string" ||
      source.c.length < 1 ||
      source.c.length > MAX_PIVOT_CURSOR_CHARS ||
      !PRINTABLE_ASCII.test(source.c)
    ) {
      return null;
    }
    cursor = source.c;
  }
  return {
    resource,
    filters,
    selectedId: source.s === null ? null : (source.s as string).toLowerCase(),
    label: source.l,
    sourceKind: kind as PivotSourceKind,
    cursor,
  } as PivotStep;
}

/** Parse and validate the whole envelope (fail closed). */
export function parsePivotState(value: string | null | undefined): PivotState | null {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  if (new TextEncoder().encode(value).length > MAX_PIVOT_PARAM_BYTES) {
    return null;
  }
  const decoded = decodeBase64Url(value);
  if (decoded === null) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  const envelope = parsed as Record<string, unknown>;
  const envelopeKeys = new Set(["v", "steps"]);
  for (const key of Object.keys(envelope)) {
    if (!envelopeKeys.has(key)) {
      return null;
    }
  }
  if (envelope.v !== PIVOT_VERSION || !Array.isArray(envelope.steps)) {
    return null;
  }
  if (
    envelope.steps.length < 1 ||
    envelope.steps.length > MAX_PIVOT_STEPS
  ) {
    return null;
  }
  const steps: PivotStep[] = [];
  for (const rawStep of envelope.steps) {
    const step = parsePivotStep(rawStep);
    if (step === null) {
      return null;
    }
    steps.push(step);
  }
  return { steps };
}

/** Serialize one validated state deterministically (or null when oversized). */
export function serializePivotState(state: PivotState): string | null {
  for (const step of state.steps) {
    if (!isPivotResource(step.resource)) {
      return null;
    }
  }
  const envelope: Record<string, unknown> = {
    v: PIVOT_VERSION,
    steps: state.steps.map((step) => {
      const filters = serializePivotFilters(step.resource, step.filters);
      const entry: Record<string, unknown> = {
        r: step.resource,
        f: filters,
        s: step.selectedId,
        l: step.label,
        k: step.sourceKind,
      };
      if (step.cursor !== undefined && step.cursor !== "") {
        entry.c = step.cursor;
      }
      return entry;
    }),
  };
  const encoded = encodeBase64Url(JSON.stringify(envelope));
  if (new TextEncoder().encode(encoded).length > MAX_PIVOT_PARAM_BYTES) {
    return null;
  }
  return encoded;
}

/** Whether one state serializes within the 4096-byte cap. */
export function pivotStateFits(state: PivotState): boolean {
  return serializePivotState(state) !== null;
}

// Navigation helpers over URLSearchParams --------------------------------

/** Read and validate the pivot state of one parameter set (fail closed). */
export function readPivotState(params: URLSearchParams): PivotState | null {
  const values = params.getAll(PIVOT_PARAM);
  if (values.length !== 1) {
    return null;
  }
  return parsePivotState(values[0]);
}

/** Replace the pivot parameter with one serialized state. */
export function withPivotState(
  params: URLSearchParams,
  state: PivotState,
): URLSearchParams {
  const next = new URLSearchParams(params);
  const serialized = serializePivotState(state);
  if (serialized === null) {
    next.delete(PIVOT_PARAM);
  } else {
    next.set(PIVOT_PARAM, serialized);
  }
  return next;
}

/** Open a pivot by appending one step (or start a new stack). */
export function pushPivotStep(
  params: URLSearchParams,
  step: PivotStep,
): URLSearchParams {
  const state = readPivotState(params);
  const steps = state === null ? [] : [...state.steps];
  if (steps.length >= MAX_PIVOT_STEPS) {
    return params;
  }
  steps.push(step);
  return withPivotState(params, { steps });
}

/** Truncate the pivot stack to ``keep`` steps (1..current length). */
export function truncatePivotSteps(
  params: URLSearchParams,
  keep: number,
): URLSearchParams {
  const state = readPivotState(params);
  if (state === null) {
    return params;
  }
  if (keep <= 0) {
    return clearPivotState(params);
  }
  const next = state.steps.slice(0, Math.min(keep, state.steps.length));
  if (next.length === state.steps.length) {
    return params;
  }
  return withPivotState(params, { steps: next });
}

/** Remove the pivot parameter entirely (modal close). */
export function clearPivotState(params: URLSearchParams): URLSearchParams {
  const next = new URLSearchParams(params);
  next.delete(PIVOT_PARAM);
  return next;
}

// Step <-> search-parameter projection (workspace port) -------------------

/** Project one step onto the resource URLSearchParams surface. */
export function stepToSearchParams(step: PivotStep): URLSearchParams {
  const params = new URLSearchParams();
  for (const key of PIVOT_FILTER_KEYS[step.resource]) {
    const value = (step.filters as Record<string, unknown>)[key];
    if ((PIVOT_BOOLEAN_FILTER_KEYS[step.resource] as readonly string[]).includes(key)) {
      if (value === true) {
        params.set(key, "true");
      }
      continue;
    }
    if (typeof value === "string" && value !== "") {
      params.set(key, value);
    }
  }
  if (step.cursor !== undefined && step.cursor !== "") {
    params.set("cursor", step.cursor);
  }
  if (step.selectedId !== null) {
    params.set("selected", step.selectedId);
  }
  return params;
}

/** Read the validated filter/cursor/selection state off one param set. */
export function stepFromSearchParams(
  step: PivotStep,
  params: URLSearchParams,
): PivotStep {
  const filters = parsePivotFilters(step.resource, filtersFromParams(step.resource, params));
  const cursor = parseCursorParam(params.get("cursor"));
  const selection = parseSelectedParam(params, isUuidValue);
  return {
    ...step,
    filters: filters ?? {},
    cursor,
    selectedId: selection,
  } as PivotStep;
}

/** Extract only the allowlisted resource filter values from one param set. */
export function filtersFromParams(
  resource: PivotResource,
  params: URLSearchParams,
): Record<string, string | boolean> {
  const output: Record<string, string | boolean> = {};
  for (const key of PIVOT_FILTER_KEYS[resource]) {
    const value = params.get(key);
    if (value === null || value === "") {
      continue;
    }
    if ((PIVOT_BOOLEAN_FILTER_KEYS[resource] as readonly string[]).includes(key)) {
      if (value === "true" || value === "1") {
        output[key] = true;
      } else if (value === "false" || value === "0") {
        output[key] = false;
      }
      continue;
    }
    output[key] = value;
  }
  return output;
}