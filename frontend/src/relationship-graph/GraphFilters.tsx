// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Graph context/filter toolbar (PR 31G Part 7).
//
// The committed graph context has exactly one authority: the Graph route
// URL. Drafts are browser-local until Apply/Clear, which perform exactly one
// route commit; text/date edits never issue a graph request before Apply.
// Apply commits the verified draft, Clear restores Investigation scope with
// no optional filters, and external navigation resyncs the draft from the
// committed URL without a write-back effect loop.

import {
  Box,
  Button,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from "@mui/material";
import type { ReactElement } from "react";
import type { TFunction } from "i18next";

import type {
  EntityTypeName,
  GraphScopeName,
  RelationshipTypeName,
} from "../api/schema-types";
import { localDateTimeToIso } from "../analyst-table/filters";
import { RELATIONSHIP_TYPES } from "../relationships/labels";
import {
  GRAPH_ENTITY_TYPES,
  GRAPH_SCOPES,
  type GraphContext,
} from "./graph-context-url";

/** One draft (browser-local until Apply). */
export interface GraphDraft {
  scope: GraphScopeName;
  entityType: EntityTypeName | "";
  relationshipType: RelationshipTypeName | "";
  source: string;
  observedFrom: string;
  observedTo: string;
}

/** Build a draft from the committed graph context. */
export function graphDraftFromCommitted(context: GraphContext): GraphDraft {
  return {
    scope: context.scope,
    entityType: context.entityType ?? "",
    relationshipType: context.relationshipType ?? "",
    source: context.source ?? "",
    observedFrom: context.observedFrom ?? "",
    observedTo: context.observedTo ?? "",
  };
}

/** Convert one validated draft to the committed graph context. */
export function graphDraftToCommitted(draft: GraphDraft): GraphContext {
  return {
    scope: draft.scope,
    entityType: draft.entityType === "" ? undefined : draft.entityType,
    relationshipType:
      draft.relationshipType === "" ? undefined : draft.relationshipType,
    source: nonBlank(draft.source),
    observedFrom: localDateTimeToIso(draft.observedFrom),
    observedTo: localDateTimeToIso(draft.observedTo),
  };
}

/** One translated draft validation error, or null when commit-able. */
export function graphDraftError(
  t: TFunction,
  draft: GraphDraft,
): string | null {
  for (const value of [draft.observedFrom, draft.observedTo]) {
    if (value !== "" && localDateTimeToIso(value) === undefined) {
      return t("graph.filters.time.invalid");
    }
  }
  return null;
}

export interface GraphFiltersProps {
  t: TFunction;
  draft: GraphDraft;
  hasActiveFilters: boolean;
  /** Entity type -> analyst label (exact text, non-color differentiation). */
  entityTypeLabel: (type: string) => string;
  /** Relationship type URN -> analyst label. */
  relationshipTypeLabel: (type: string) => string;
  onSetDraft: (draft: GraphDraft) => void;
  onApply: () => void;
  onClear: () => void;
}

/** The compact graph context + filter region above the graph. */
export function GraphFilters({
  t,
  draft,
  hasActiveFilters,
  entityTypeLabel,
  relationshipTypeLabel,
  onSetDraft,
  onApply,
  onClear,
}: GraphFiltersProps): ReactElement {
  const enter = (event: { key: string }): void => {
    if (event.key === "Enter") {
      onApply();
    }
  };
  const set = (patch: Partial<GraphDraft>): void => {
    onSetDraft({ ...draft, ...patch });
  };
  return (
    <Box
      role="group"
      aria-label={t("graph.filters.aria")}
      sx={(theme) => ({
        display: "flex",
        flexDirection: "column",
        gap: 1,
        p: 1,
        borderRadius: 0.5,
        border: 1,
        borderColor: theme.palette.divider,
        bgcolor: "action.hover",
        mb: 1,
      })}
    >
      <Box sx={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 1 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
          <Typography
            variant="caption"
            component="span"
            id="graph-scope-label"
          >
            {t("graph.filters.scope.label")}
          </Typography>
          <ToggleButtonGroup
            value={draft.scope}
            exclusive
            size="small"
            aria-labelledby="graph-scope-label"
            onChange={(_event, next: GraphScopeName | null) => {
              if (next !== null) {
                set({ scope: next });
              }
            }}
          >
            {GRAPH_SCOPES.map((scope) => (
              <ToggleButton key={scope} value={scope} aria-label={t(`graph.filters.scope.${scope}`)}>
                {t(`graph.filters.scope.${scope}`)}
              </ToggleButton>
            ))}
          </ToggleButtonGroup>
        </Box>
        <FormControl size="small" sx={{ minWidth: 160 }}>
          <InputLabel id="graph-entity-type-label">
            {t("graph.filters.entityType.label")}
          </InputLabel>
          <Select
            labelId="graph-entity-type-label"
            label={t("graph.filters.entityType.label")}
            value={draft.entityType}
            onChange={(event) =>
              set({ entityType: event.target.value as EntityTypeName | "" })
            }
          >
            <MenuItem value="">{t("graph.filters.entityType.all")}</MenuItem>
            {GRAPH_ENTITY_TYPES.map((type) => (
              <MenuItem key={type} value={type}>
                {entityTypeLabel(type)}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 200 }}>
          <InputLabel id="graph-relationship-type-label">
            {t("graph.filters.relationshipType.label")}
          </InputLabel>
          <Select
            labelId="graph-relationship-type-label"
            label={t("graph.filters.relationshipType.label")}
            value={draft.relationshipType}
            onChange={(event) =>
              set({
                relationshipType: event.target.value as RelationshipTypeName | "",
              })
            }
          >
            <MenuItem value="">{t("graph.filters.relationshipType.all")}</MenuItem>
            {RELATIONSHIP_TYPES.map((type) => (
              <MenuItem key={type} value={type}>
                {relationshipTypeLabel(type)}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <TextField
          size="small"
          label={t("graph.filters.source.label")}
          value={draft.source}
          onChange={(event) => set({ source: event.target.value })}
          onKeyDown={enter}
        />
        <TextField
          size="small"
          type="datetime-local"
          slotProps={{ inputLabel: { shrink: true } }}
          label={t("graph.filters.observedFrom.label")}
          value={draft.observedFrom}
          onChange={(event) => set({ observedFrom: event.target.value })}
          onKeyDown={enter}
        />
        <TextField
          size="small"
          type="datetime-local"
          slotProps={{ inputLabel: { shrink: true } }}
          label={t("graph.filters.observedTo.label")}
          value={draft.observedTo}
          onChange={(event) => set({ observedTo: event.target.value })}
          onKeyDown={enter}
        />
        <Button size="small" variant="contained" onClick={onApply} sx={{ textTransform: "none" }}>
          {t("graph.filters.apply")}
        </Button>
        <Button
          size="small"
          variant="outlined"
          disabled={!hasActiveFilters}
          onClick={onClear}
          sx={{ textTransform: "none" }}
        >
          {t("graph.filters.clear")}
        </Button>
      </Box>
      <Typography
        variant="caption"
        component="div"
        role="note"
        aria-label={t(`graph.filters.scope.${draft.scope}Hint`)}
      >
        {t(`graph.filters.scope.${draft.scope}Hint`)}
      </Typography>
    </Box>
  );
}

/** Normalize whitespace-only strings to absence. */
function nonBlank(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}
