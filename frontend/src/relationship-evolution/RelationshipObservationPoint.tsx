// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// One accessible observation point on the Evolution timeline (PR 24E §17,
// §18).
//
// Every point is a real focusable control (never pointer-only) whose
// accessible label names the counterparty, relationship type, direction,
// observed time and provider. ``retrieved_at`` stays secondary metadata in
// the tooltip and detail surface — it never substitutes for a missing
// observed time on the axis.

import { ButtonBase } from "@mui/material";
import type { ReactElement } from "react";

import type { EvolutionPoint } from "./relationship-evolution-model";

/** Accessible label of one point (counterparty/type/direction/time/provider). */
export function pointLabel(
  labelDirection: string,
  labelType: string,
  counterpartyLabel: string,
  point: EvolutionPoint,
): string {
  const observed = point.observedAt ?? "observed time unavailable";
  return [
    labelDirection,
    labelType,
    counterpartyLabel,
    `observed ${observed}`,
    `provider ${point.source}`,
  ].join(", ");
}

export interface RelationshipObservationPointProps {
  point: EvolutionPoint;
  /** Fractional x position on the time strip (0..1); null when no time. */
  xFraction: number | null;
  /** Translated direction/type/counterparty labels for the aria label. */
  ariaParts: {
    direction: string;
    type: string;
    counterparty: string;
  };
  /** Forwarded to the workspace so activations open the detail surface. */
  onActivate: (observationId: string) => void;
}

/** One focusable observation point on a lane's time strip. */
export function RelationshipObservationPoint({
  point,
  xFraction,
  ariaParts,
  onActivate,
}: RelationshipObservationPointProps): ReactElement {
  const label = pointLabel(
    ariaParts.direction,
    ariaParts.type,
    ariaParts.counterparty,
    point,
  );
  if (xFraction === null) {
    return (
      <li>
        <ButtonBase
          component="span"
          role="button"
          tabIndex={0}
          onClick={() => onActivate(point.observationId)}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              onActivate(point.observationId);
            }
          }}
          aria-label={label}
          title={`retrieved ${point.retrievedAt}`}
          sx={{
            display: "inline-flex",
            borderRadius: "50%",
            width: 20,
            height: 20,
            bgcolor: "primary.main",
            color: "primary.contrastText",
            fontSize: 10,
            lineHeight: 1,
          }}
        >
          •
        </ButtonBase>
      </li>
    );
  }
  return (
    <li
      style={{
        position: "absolute",
        left: `calc(${(xFraction * 100).toFixed(3)}% - 10px)`,
        top: 8,
        listStyle: "none",
      }}
    >
      <ButtonBase
        component="span"
        role="button"
        tabIndex={0}
        onClick={() => onActivate(point.observationId)}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onActivate(point.observationId);
          }
        }}
        aria-label={label}
        title={`retrieved ${point.retrievedAt}`}
        sx={{
          display: "inline-flex",
          borderRadius: "50%",
          width: 20,
          height: 20,
          bgcolor: "primary.main",
          color: "primary.contrastText",
          fontSize: 10,
          lineHeight: 1,
          cursor: "pointer",
        }}
      >
        •
      </ButtonBase>
    </li>
  );
}

/** Short deterministic axis label (date + HH:MM in UTC). */
export function axisTickLabel(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  const pad = (n: number, width = 2): string => String(n).padStart(width, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(
    date.getUTCDate(),
  )} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}`;
}