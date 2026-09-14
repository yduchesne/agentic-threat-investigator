// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// History labels + public object-type allowlist (PR 24C §12).
//
// The public object-type allowlist mirrors the backend authority
// (``api/history_redaction.py::PUBLIC_HISTORY_OBJECT_TYPES``); browsing any
// other type fails closed server-side. RelationshipObservation is never
// part of generic History — it stays first-class and immutable.

import type { HistoryOperationName } from "../api/schema-types";

/** i18n key per known HistoryOperation value (CREATE/UPDATE/DELETE). */
export const HISTORY_OPERATION_KEYS: Readonly<Record<HistoryOperationName, string>> = {
  CREATE: "operations.create",
  UPDATE: "operations.update",
  DELETE: "operations.delete",
};

/**
 * Resolve one history operation to its i18n key.
 *
 * Unknown values return the raw operation (safe fallback).
 */
export function historyOperationKey(operation: HistoryOperationName | string): string {
  return HISTORY_OPERATION_KEYS[operation as HistoryOperationName] ?? operation;
}

/** The exact backend history operations accepted as list filters. */
export const HISTORY_OPERATIONS: readonly HistoryOperationName[] = [
  "CREATE",
  "UPDATE",
  "DELETE",
];

/**
 * The backend public history object-type allowlist (v0.1).
 *
 * Mirrors ``PUBLIC_HISTORY_OBJECT_TYPES`` in
 * ``src/agentic_threat_investigator/api/history_redaction.py``. Non-listed
 * types are rejected by the API with ``400 invalid_request``; the frontend
 * only offers and presents allowlisted types.
 */
export const PUBLIC_HISTORY_OBJECT_TYPES: readonly string[] = [
  "investigation",
  "entity",
  "relationship",
  "assessment",
  "investigation_report",
];

/** Whether one object type is on the backend public allowlist. */
export function isPublicHistoryObjectType(value: string): boolean {
  return PUBLIC_HISTORY_OBJECT_TYPES.includes(value);
}