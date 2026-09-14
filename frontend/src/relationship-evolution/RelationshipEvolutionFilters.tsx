// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Evolution filter toolbar (PR 24E §12, §13, §20).
//
// Drafts are browser-local until Apply; committing a semantic filter resets
// the cursor. ``Clear filters`` keeps the focal entity (the Evolution scope)
// and resets every semantic filter + cursor.

import { Box, FormControl, InputLabel, MenuItem, Select, TextField } from "@mui/material";
import type { ReactElement } from "react";
import type { TFunction } from "i18next";

import type {
  RelationshipDirectionName,
  RelationshipTypeName,
} from "../api/schema-types";
import { isUuidValue, localDateTimeToIso } from "../analyst-table/filters";
import { RELATIONSHIP_DIRECTIONS } from "../relationships/relationships-filters";
import { RELATIONSHIP_TYPES } from "../relationships/labels";
import { TableToolbar } from "../analyst-table/TableToolbar";
import type { RelationshipEvolutionFilters } from "./relationship-evolution-url";

/** One draft (browser-local until Apply). */
export interface EvolutionDraft {
  direction: RelationshipDirectionName;
  relationshipType: RelationshipTypeName | "";
  counterpartyEntityId: string;
  source: string;
  observedFrom: string;
  observedTo: string;
}

/** Build a draft from the committed filters. */
export function draftFromCommitted(filters: RelationshipEvolutionFilters): EvolutionDraft {
  return {
    direction: filters.direction,
    relationshipType: filters.relationshipType ?? "",
    counterpartyEntityId: filters.counterpartyEntityId ?? "",
    source: filters.source ?? "",
    observedFrom: filters.observedFrom ?? "",
    observedTo: filters.observedTo ?? "",
  };
}

/** Convert one validated draft to the committed filter model. */
export function draftToCommitted(
  entityId: string,
  draft: EvolutionDraft,
): RelationshipEvolutionFilters {
  return {
    entityId,
    direction: draft.direction,
    relationshipType: draft.relationshipType === "" ? undefined : draft.relationshipType,
    counterpartyEntityId: isUuidValue(draft.counterpartyEntityId)
      ? draft.counterpartyEntityId.toLowerCase()
      : undefined,
    source: nonBlank(draft.source),
    observedFrom: localDateTimeToIso(draft.observedFrom),
    observedTo: localDateTimeToIso(draft.observedTo),
  };
}

/** One translated draft validation error, or null when commit-able. */
export function evolutionDraftError(
  t: TFunction,
  draft: EvolutionDraft,
): string | null {
  if (draft.counterpartyEntityId !== "" && !isUuidValue(draft.counterpartyEntityId)) {
    return t("filters.counterparty.invalid");
  }
  for (const value of [draft.observedFrom, draft.observedTo]) {
    if (value !== "" && localDateTimeToIso(value) === undefined) {
      return t("filters.time.invalid");
    }
  }
  return null;
}

/** Whether two committed filter models are identical. */
export function evolutionFiltersEqual(
  a: RelationshipEvolutionFilters,
  b: RelationshipEvolutionFilters,
): boolean {
  return (
    a.entityId === b.entityId &&
    a.direction === b.direction &&
    a.relationshipType === b.relationshipType &&
    a.counterpartyEntityId === b.counterpartyEntityId &&
    a.source === b.source &&
    a.observedFrom === b.observedFrom &&
    a.observedTo === b.observedTo
  );
}

/** The committed-key identity used for draft resync detection. */
export function evolutionFiltersKey(filters: RelationshipEvolutionFilters): string {
  return JSON.stringify([
    filters.entityId,
    filters.direction,
    filters.relationshipType,
    filters.counterpartyEntityId,
    filters.source,
    filters.observedFrom,
    filters.observedTo,
  ]);
}

export interface RelationshipEvolutionFiltersProps {
  t: TFunction;
  tCommon: TFunction;
  draft: EvolutionDraft;
  hasActiveFilters: boolean;
  /** Translate one relationship type URN (relationships namespace). */
  relationshipTypeLabel: (type: RelationshipTypeName) => string;
  onSetDraft: (draft: EvolutionDraft) => void;
  onApply: () => void;
  onClear: () => void;
  /** Export exactly the rows of the currently loaded page (bounded). */
  onExport: () => void;
}

/** The Evolution filter form + toolbar (apply on Apply/Enter, not keystrokes). */
export function RelationshipEvolutionFilters({
  t,
  tCommon,
  draft,
  hasActiveFilters,
  relationshipTypeLabel,
  onSetDraft,
  onApply,
  onClear,
  onExport,
}: RelationshipEvolutionFiltersProps): ReactElement {
  const enter = (event: { key: string }) => {
    if (event.key === "Enter") {
      onApply();
    }
  };
  return (
    <TableToolbar
      filters={
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel id="evolution-direction-label">{t("filters.direction.label")}</InputLabel>
            <Select
              labelId="evolution-direction-label"
              label={t("filters.direction.label")}
              value={draft.direction}
              onChange={(event) =>
                onSetDraft({
                  ...draft,
                  direction: event.target.value as RelationshipDirectionName,
                })}
            >
              {RELATIONSHIP_DIRECTIONS.map((direction) => (
                <MenuItem key={direction} value={direction}>
                  {t(`directions.${direction}`)}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 200 }}>
            <InputLabel id="evolution-type-label">{t("filters.relationshipType.label")}</InputLabel>
            <Select
              labelId="evolution-type-label"
              label={t("filters.relationshipType.label")}
              value={draft.relationshipType}
              onChange={(event) =>
                onSetDraft({
                  ...draft,
                  relationshipType: event.target.value as RelationshipTypeName | "",
                })}
            >
              <MenuItem value="">{tCommon("filters.all")}</MenuItem>
              {RELATIONSHIP_TYPES.map((type) => (
                <MenuItem key={type} value={type}>
                  {relationshipTypeLabel(type)}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <TextField
            size="small"
            label={t("filters.counterparty.label")}
            value={draft.counterpartyEntityId}
            onChange={(event) =>
              onSetDraft({ ...draft, counterpartyEntityId: event.target.value })}
            onKeyDown={enter}
          />
          <TextField
            size="small"
            label={t("filters.source.label")}
            value={draft.source}
            onChange={(event) => onSetDraft({ ...draft, source: event.target.value })}
            onKeyDown={enter}
          />
          <TextField
            size="small"
            type="datetime-local"
            label={t("filters.observedFrom.label")}
            value={draft.observedFrom}
            onChange={(event) => onSetDraft({ ...draft, observedFrom: event.target.value })}
            onKeyDown={enter}
          />
          <TextField
            size="small"
            type="datetime-local"
            label={t("filters.observedTo.label")}
            value={draft.observedTo}
            onChange={(event) => onSetDraft({ ...draft, observedTo: event.target.value })}
            onKeyDown={enter}
          />
        </Box>
      }
      onApply={onApply}
      onClear={onClear}
      onExport={onExport}
      hasActiveFilters={hasActiveFilters}
    />
  );
}

/** Normalize whitespace-only strings to absence. */
function nonBlank(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}