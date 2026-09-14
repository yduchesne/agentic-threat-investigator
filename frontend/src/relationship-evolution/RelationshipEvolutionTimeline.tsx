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

import { Alert, Box, Button, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useState } from "react";

import type { RelationshipObservation } from "../api/schema-types";
import { CompactId } from "../components/CompactId";
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
  tableView: string;
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
  hasNext: boolean;
  onActivate: (observationId: string) => void;
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
    counterpartyEntityId: string | null;
    relationshipId: string;
  }): string => {
    const id = lane.counterpartyEntityId ?? lane.relationshipId;
    return `Entity ${shortUuid(id)}`;
  };

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
          {tableView ? labels.tableView : labels.viewAsTable}
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
  onActivate,
}: {
  focalEntityId: string;
  rows: readonly RelationshipObservation[];
  labels: EvolutionTimelineLabels;
  typeLabel: (type: string) => string;
  onActivate: (observationId: string) => void;
}): ReactElement {
  return (
    <Box sx={{ overflowX: "auto" }}>
      <table aria-label={labels.tableView} style={{ borderCollapse: "collapse", width: "100%" }}>
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
                <Button
                  size="small"
                  onClick={() => onActivate(row.id)}
                  sx={{ textTransform: "none" }}
                >
                  {shortUuid(row.id)}
                </Button>
              </td>
              <td style={{ padding: 6 }}>
                {row.relationship_type === null ? "—" : typeLabel(row.relationship_type ?? "")}
              </td>
              <td style={{ padding: 6 }}>{directionLabelFor(focalEntityId, row)}</td>
              <td style={{ padding: 6 }}>
                <CompactId id={counterpartyIdFor(row)} label="Counterparty" />
              </td>
              <td style={{ padding: 6 }}>{row.source}</td>
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

/** Best-effort counterparty of one row (labels only; may be a compact id). */
function counterpartyIdFor(row: RelationshipObservation): string {
  return row.relationship_target_entity_id ?? row.relationship_id;
}