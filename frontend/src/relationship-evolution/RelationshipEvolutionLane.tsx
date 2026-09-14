// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// One Evolution swimlane (PR 24E §14, §18).
//
// A lane is one stable Relationship as observed on the loaded page: a
// semantic heading (direction, relationship type, counterparty, page
// count) plus a time strip whose points are accessible focusable controls
// positioned deterministically by ``observed_at``. No interval is drawn
// between points and no started/ended/removed inference is made.

import { Box, Typography, useTheme } from "@mui/material";
import type { ReactElement } from "react";

import { CompactId } from "../components/CompactId";
import type { EvolutionLane, EvolutionTimeSpan } from "./relationship-evolution-model";
import type { LaneAnnotation } from "./relationship-evolution-derived";
import { RelationshipObservationPoint, axisTickLabel } from "./RelationshipObservationPoint";

/** Fractional time position of one point on the strip (0..1). */
function xFraction(
  pointIso: string,
  span: EvolutionTimeSpan | null,
): number | null {
  if (span === null) {
    return null;
  }
  if (span.singleInstant) {
    return 0.5;
  }
  const start = new Date(span.minIso).getTime();
  const end = new Date(span.maxIso).getTime();
  const value = new Date(pointIso).getTime();
  if (Number.isNaN(start) || Number.isNaN(end) || end <= start) {
    return 0.5;
  }
  const fraction = (value - start) / (end - start);
  return Math.min(1, Math.max(0, fraction));
}

export interface RelationshipEvolutionLaneProps {
  lane: EvolutionLane;
  span: EvolutionTimeSpan | null;
  /** Page-scoped deterministic annotation, or null when absent. */
  annotation: LaneAnnotation | null;
  /** Translated "Earliest shown" page-scoped label. */
  earliestShownLabel: string;
  /** Translated direction label (Inbound/Outbound/Either). */
  directionLabel: string;
  /** Translated relationship type label (unknown -> raw URN fallback). */
  typeLabel: string;
  /** Bounded analyst-facing counterparty label (value or compact ID). */
  counterpartyLabel: string;
  onActivate: (observationId: string) => void;
}

/** One deterministic swimlane of one loaded page. */
export function RelationshipEvolutionLane({
  lane,
  span,
  annotation,
  earliestShownLabel,
  directionLabel,
  typeLabel,
  counterpartyLabel,
  onActivate,
}: RelationshipEvolutionLaneProps): ReactElement {
  const theme = useTheme();
  const ariaDescription = [
    directionLabel,
    typeLabel,
    `counterparty ${counterpartyLabel}`,
  ].join(", ");
  const timed = lane.points.filter((point) => point.observedAt !== null);
  const untimed = lane.points.filter((point) => point.observedAt === null);

  return (
    <Box component="section" aria-label={ariaDescription} sx={{ mb: 2.5 }}>
      <Typography variant="subtitle1" component="h4" sx={{ fontWeight: 600, mb: 0.5 }}>
        <Box component="span" sx={{ mr: 1, color: "text.secondary" }}>
          {directionLabel}
        </Box>
        <Box component="span" sx={{ mr: 1 }}>
          {typeLabel}
        </Box>
        <CompactId id={lane.counterpartyEntityId ?? lane.relationshipId} label={counterpartyLabel} />
        <Box component="span" sx={{ ml: 1, color: "text.secondary" }}>
          {lane.points.length}
        </Box>
        {annotation !== null && annotation.isEarliestShown ? (
          <Box component="span" sx={{ ml: 1, color: "text.secondary", fontWeight: 400 }}>
            {earliestShownLabel}
          </Box>
        ) : null}
      </Typography>
      <Box sx={{ position: "relative", height: 44, borderBottom: 1, borderColor: "divider" }}>
        <svg
          width="100%"
          height={44}
          aria-hidden="true"
          style={{ position: "absolute", inset: 0, display: "block" }}
        >
          <line
            x1="1%"
            x2="99%"
            y1={22}
            y2={22}
            stroke={theme.palette.divider}
            strokeWidth={2}
          />
          {timed.map((point) => {
            const fraction = xFraction(point.observedAt as string, span);
            if (fraction === null) {
              return null;
            }
            return (
              <circle
                key={point.observationId}
                cx={`${(fraction * 100).toFixed(3)}%`}
                cy={22}
                r={7}
                fill={theme.palette.primary.main}
                opacity={0.3}
              />
            );
          })}
        </svg>
        <Box component="ul" sx={{ position: "absolute", inset: 0, m: 0, p: 0 }}>
          {timed.map((point) => (
            <RelationshipObservationPoint
              key={point.observationId}
              point={point}
              xFraction={xFraction(point.observedAt as string, span)}
              ariaParts={{
                direction: directionLabel,
                type: typeLabel,
                counterparty: counterpartyLabel,
              }}
              onActivate={onActivate}
            />
          ))}
        </Box>
      </Box>
      <Box sx={{ display: "flex", justifyContent: "space-between" }}>
        <Typography variant="caption" sx={{ color: "text.secondary" }}>
          {span === null ? "" : axisTickLabel(span.minIso)}
        </Typography>
        {span !== null && !span.singleInstant ? (
          <Typography variant="caption" sx={{ color: "text.secondary" }}>
            {axisTickLabel(span.maxIso)}
          </Typography>
        ) : null}
      </Box>
      {untimed.length > 0 ? (
        <Typography variant="caption" component="div" role="note" sx={{ mt: 0.5 }}>
          {untimed.length} observation(s) in this lane have no observed time.
        </Typography>
      ) : null}
    </Box>
  );
}