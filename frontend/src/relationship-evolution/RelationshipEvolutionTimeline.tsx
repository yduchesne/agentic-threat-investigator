// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// The Relationship Evolution temporal visualization surface (PR 24E §14,
// §15, §18, §19).
//
// A CSS/SVG swimlane view over one loaded page: lanes group by stable
// Relationship, points are accessible controls positioned by ``observed_at``,
// null-observed rows live in an explicit unavailable group, and the
// bounded-page notice is ordinary text whenever ``next_cursor`` exists.
// ``View as table`` is the equivalent non-spatial representation of the
// same loaded page, so no second query and no spatial exploration is ever
// required to reach the data.

import { Alert, Box, Button, IconButton, SvgIcon, Tooltip, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useState } from "react";

import type { RelationshipObservation } from "../api/schema-types";
import { CompactId, copyText } from "../components/CompactId";
import { sourceLabel } from "../components/source-labels";
import { useTranslation } from "react-i18next";
import { Timestamp } from "../components/Timestamp";
import { shortUuid } from "../analyst-table/present";
import {
  edgeDirection,
  type EvolutionModel,
  type EvolutionTimeSpan,
} from "./relationship-evolution-model";
import type { LaneAnnotation } from "./relationship-evolution-derived";
import { RelationshipEvolutionLane } from "./RelationshipEvolutionLane";

export interface EvolutionTimelineLabels {
  heading: string;
  boundedNotice: string;
  unavailableTitle: string;
  unavailableHint: string;
  viewAsTable: string;
  viewAsTimeline: string;
  tableLabel: string;
  tableColumns: {
    observation: string;
    type: string;
    direction: string;
    counterparty: string;
    source: string;
    observedAt: string;
    retrievedAt: string;
    evidence: string;
  };
  lanesHeading: string;
  directionInbound: string;
  directionOutbound: string;
  directionEither: string;
  earliestShown: string;
  empty: string;
}

export interface RelationshipEvolutionTimelineProps {
  /** The focal entity of the loaded page (table direction labels need it). */
  focalEntityId: string;
  model: EvolutionModel;
  span: EvolutionTimeSpan | null;
  /** Page-scoped deterministic annotations per lane (Earliest shown etc.). */
  annotations: ReadonlyMap<string, LaneAnnotation>;
  /** Raw loaded page rows (the table alternative renders the same page). */
  rows: readonly RelationshipObservation[];
  /** Translated labels (including relationshipType via formatter). */
  labels: EvolutionTimelineLabels;
  typeLabel: (type: string) => string;
  /** Translated Entity-type label (unknown values -> raw safe fallback). */
  entityTypeLabel: (type: string) => string;
  hasNext: boolean;
  onActivate: (observationId: string) => void;
}

/**
 * Analyst-facing semantic counterparty text of one lane.
 *
 * Human-readable first: the authoritative Entity type and value when the
 * bounded read projection supplied them; a bare value without a type is
 * still safe; missing metadata falls back to the compact technical identity
 * (never an invented value).
 */
export function counterpartyText(
  entityTypeLabel: (type: string) => string,
  lane: {
    counterpartyEntityType: string | null;
    counterpartyEntityValue: string | null;
    counterpartyEntityId: string | null;
    relationshipId: string;
  },
): string {
  const value =
    lane.counterpartyEntityValue !== null && lane.counterpartyEntityValue.trim() !== ""
      ? lane.counterpartyEntityValue
      : null;
  if (lane.counterpartyEntityType !== null) {
    const typeText = entityTypeLabel(lane.counterpartyEntityType);
    return value === null ? typeText : `${typeText} ${value}`;
  }
  if (value !== null) {
    return value;
  }
  return `Entity ${shortUuid(lane.counterpartyEntityId ?? lane.relationshipId)}`;
}

/**
 * Focal-relative endpoint presentation of one observation row (table path).
 *
 * Mirrors the lane-level :func:`counterpartyText`: authoritative entity
 * type/value first, compact technical identity only as a fallback.
 */
function counterpartyRowText(
  entityTypeLabel: (type: string) => string,
  focalEntityId: string,
  row: RelationshipObservation,
): { text: string; id: string } {
  const sourceId = row.relationship_source_entity_id ?? null;
  const targetId = row.relationship_target_entity_id ?? null;
  const id =
    sourceId !== null && sourceId !== focalEntityId
      ? sourceId
      : targetId !== null && targetId !== focalEntityId
        ? targetId
        : (sourceId ?? targetId ?? row.relationship_id);
  const sourceIsCounterparty = sourceId !== null && sourceId !== focalEntityId;
  const type = sourceIsCounterparty
    ? (row.relationship_source_entity_type ?? null)
    : (row.relationship_target_entity_type ?? null);
  const value = sourceIsCounterparty
    ? (row.relationship_source_entity_value ?? null)
    : (row.relationship_target_entity_value ?? null);
  const cleanValue = value !== null && value.trim() !== "" ? value : null;
  if (type !== null) {
    return { text: cleanValue === null ? entityTypeLabel(type) : `${entityTypeLabel(type)} ${cleanValue}`, id };
  }
  if (cleanValue !== null) {
    return { text: cleanValue, id };
  }
  return { text: `Entity ${shortUuid(id)}`, id };
}

/** The swimlane temporal surface plus an accessible table alternative. */
export function RelationshipEvolutionTimeline({
  focalEntityId,
  model,
  span,
  annotations,
  rows,
  labels,
  typeLabel,
  entityTypeLabel,
  hasNext,
  onActivate,
}: RelationshipEvolutionTimelineProps): ReactElement {
  const [tableView, setTableView] = useState(false);

  const directionLabel = (direction: string): string => {
    if (direction === "target") {
      return labels.directionInbound;
    }
    if (direction === "source") {
      return labels.directionOutbound;
    }
    return labels.directionEither;
  };
  const counterpartyLabel = (lane: {
    counterpartyEntityType: string | null;
    counterpartyEntityValue: string | null;
    counterpartyEntityId: string | null;
    relationshipId: string;
  }): string => counterpartyText(entityTypeLabel, lane);

  return (
    <Box>
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
        <Typography variant="h3">{labels.heading}</Typography>
        <Button
          size="small"
          variant="outlined"
          onClick={() => setTableView((current) => !current)}
          aria-pressed={tableView}
        >
          {tableView ? labels.viewAsTimeline : labels.viewAsTable}
        </Button>
      </Box>
      {hasNext ? (
        <Alert severity="info" role="status" sx={{ mb: 1 }}>
          {labels.boundedNotice}
        </Alert>
      ) : null}
      {tableView ? (
        <ObservationTable
          focalEntityId={focalEntityId}
          rows={rows}
          labels={labels}
          typeLabel={typeLabel}
          entityTypeLabel={entityTypeLabel}
          onActivate={onActivate}
        />
      ) : (
        <Box>
          {model.lanes.length === 0 && model.unavailable.length === 0 ? (
            <Typography variant="body2" sx={{ py: 3, textAlign: "center" }}>
              {labels.empty}
            </Typography>
          ) : null}
          {model.lanes.map((lane) => (
            <RelationshipEvolutionLane
              key={lane.relationshipId}
              lane={lane}
              span={span}
              annotation={annotations.get(lane.relationshipId) ?? null}
              earliestShownLabel={labels.earliestShown}
              directionLabel={directionLabel(lane.direction)}
              typeLabel={
                lane.relationshipType === null ? "—" : typeLabel(lane.relationshipType)
              }
              counterpartyLabel={counterpartyLabel(lane)}
              onActivate={onActivate}
            />
          ))}
          {model.unavailable.length > 0 ? (
            <Box role="region" aria-label={labels.unavailableTitle} sx={{ mt: 2 }}>
              <Typography variant="h4" sx={{ fontWeight: 600 }}>
                {labels.unavailableTitle}
              </Typography>
              <Typography variant="caption" component="div" sx={{ mb: 0.5 }}>
                {labels.unavailableHint}
              </Typography>
              <Box component="ul" sx={{ m: 0, p: 0 }}>
                {model.unavailable.map((point) => (
                  <Box
                    component="li"
                    key={point.observationId}
                    sx={{ listStyle: "none", display: "flex", gap: 1, py: 0.25 }}
                  >
                    <Button
                      size="small"
                      onClick={() => onActivate(point.observationId)}
                      sx={{ textTransform: "none" }}
                    >
                      {typeLabel(point.relationshipType ?? "")} •{" "}
                      <Timestamp iso={point.retrievedAt} />
                    </Button>
                  </Box>
                ))}
              </Box>
            </Box>
          ) : null}
        </Box>
      )}
    </Box>
  );
}

/** The accessible tabular/list equivalent of the loaded page. */
function ObservationTable({
  focalEntityId,
  rows,
  labels,
  typeLabel,
  entityTypeLabel,
  onActivate,
}: {
  focalEntityId: string;
  rows: readonly RelationshipObservation[];
  labels: EvolutionTimelineLabels;
  typeLabel: (type: string) => string;
  entityTypeLabel: (type: string) => string;
  onActivate: (observationId: string) => void;
}): ReactElement {
  const { t: tCommon } = useTranslation("common");
  return (
    <Box sx={{ overflowX: "auto" }}>
      <table aria-label={labels.tableLabel} style={{ borderCollapse: "collapse", width: "100%" }}>
        <thead>
          <tr>
            {[
              labels.tableColumns.observation,
              labels.tableColumns.type,
              labels.tableColumns.direction,
              labels.tableColumns.counterparty,
              labels.tableColumns.source,
              labels.tableColumns.observedAt,
              labels.tableColumns.retrievedAt,
              labels.tableColumns.evidence,
            ].map((header) => (
              <th key={header} scope="col" style={{ textAlign: "left", padding: 6 }}>
                {header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td style={{ padding: 6 }}>
                <Box sx={{ display: "inline-flex", alignItems: "center", gap: 0.25 }}>
                  <Button
                    size="small"
                    onClick={() => onActivate(row.id)}
                    sx={{ textTransform: "none" }}
                  >
                    {shortUuid(row.id)}
                  </Button>
                  <Tooltip title={tCommon("copyId.tooltip")}>
                    <IconButton
                      size="small"
                      onClick={() => void copyText(row.id)}
                      aria-label={tCommon("copyId.action", { id: shortUuid(row.id) })}
                      sx={{ p: 0.25, color: "text.secondary" }}
                    >
                      <SvgIcon fontSize="inherit" aria-hidden="true">
                        <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1Zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2Zm0 16H8V7h11v14Z" />
                      </SvgIcon>
                    </IconButton>
                  </Tooltip>
                </Box>
              </td>
              <td style={{ padding: 6 }}>
                {row.relationship_type === null ? "—" : typeLabel(row.relationship_type ?? "")}
              </td>
              <td style={{ padding: 6 }}>{directionLabelFor(focalEntityId, row)}</td>
              <td style={{ padding: 6 }}>
                <CounterpartyCell
                  entityTypeLabel={entityTypeLabel}
                  focalEntityId={focalEntityId}
                  row={row}
                  counterpartyColumn={labels.tableColumns.counterparty}
                />
              </td>
              <td style={{ padding: 6 }}>{sourceLabel(row.source, tCommon)}</td>
              <td style={{ padding: 6 }}>
                {row.observed_at !== null ? <Timestamp iso={row.observed_at} /> : "—"}
              </td>
              <td style={{ padding: 6 }}>
                <Timestamp iso={row.retrieved_at} />
              </td>
              <td style={{ padding: 6 }}>
                <CompactId id={row.evidence_id} label={labels.tableColumns.evidence} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Box>
  );
}

/** Focal-relative direction of one row (exact edge semantics, labels only). */
function directionLabelFor(
  focalEntityId: string,
  row: RelationshipObservation,
): string {
  if (
    row.relationship_source_entity_id === null ||
    row.relationship_source_entity_id === undefined ||
    row.relationship_target_entity_id === null ||
    row.relationship_target_entity_id === undefined
  ) {
    return "—";
  }
  return edgeDirection(
    focalEntityId,
    row.relationship_source_entity_id ?? null,
    row.relationship_target_entity_id ?? null,
  );
}

/** Semantic counterparty text + canonical identity in one table cell. */
function CounterpartyCell({
  entityTypeLabel,
  focalEntityId,
  row,
  counterpartyColumn,
}: {
  entityTypeLabel: (type: string) => string;
  focalEntityId: string;
  row: RelationshipObservation;
  counterpartyColumn: string;
}): ReactElement {
  const { text, id } = counterpartyRowText(entityTypeLabel, focalEntityId, row);
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
      <Box component="span">{text}</Box>
      <CompactId id={id} label={counterpartyColumn} />
    </Box>
  );
}
