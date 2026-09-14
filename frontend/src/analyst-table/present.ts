// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared analyst presentation helpers (PR 24C §17).
//
// Enum -> human-readable label mapping with a safe unknown fallback, and
// compact UUID rendering. Maps are resource-specific (each resource module
// owns its labels); this module only supplies the mapping mechanics.

/** Resolve one enum value through an exact label map with a safe fallback. */
export function mappedLabel(
  value: string,
  map: Readonly<Record<string, string>>,
): string {
  return map[value] ?? value;
}

/** Bounded visible prefix of one opaque UUID (full value held in tooltip). */
export function shortUuid(id: string): string {
  return id.slice(0, 8);
}

/** Present a nullable timestamp as a bounded dash when absent. */
export function nullableOrDash(
  value: string | null | undefined,
  dash = "—",
): string {
  return value === null || value === undefined || value === "" ? dash : value;
}