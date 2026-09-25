// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Deterministic radial one-hop graph layout (PR 24E §25).
//
// Focal entity centered, counterparties evenly spaced on a circle. The
// layout depends only on the sorted counterparty identity order, so it is
// fully deterministic and never persisted (coordinates are presentation
// only; no graph physics for cosmetic effect).

/** One positioned node coordinate (view-space units). */
export interface GraphPosition {
  x: number;
  y: number;
}

const RADIUS = 220;
/** Extra angular offset (radians) so the first counterparty is not stuck
 * exactly at 3 o'clock for every query. */
const START_ANGLE = -Math.PI / 2;

/**
 * Deterministic radial positions for one focal + N counterparties.
 *
 * Positions depend only on the identity set, never on the input order or on
 * server ordering: the counterparty ids are sorted internally before angles
 * are assigned, so the same identities always produce the same initial
 * positions (G31D-M12). A new focal or neighborhood may re-run this layout;
 * the result is presentation-only and never persisted.
 */
export function radialPositions(
  focalId: string,
  counterpartyIds: readonly string[],
): { focal: GraphPosition; counterparties: ReadonlyMap<string, GraphPosition> } {
  const counterparties = new Map<string, GraphPosition>();
  const ordered = [...counterpartyIds].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const count = ordered.length;
  if (count > 0) {
    const step = (2 * Math.PI) / count;
    ordered.forEach((id, index) => {
      const angle = START_ANGLE + step * index;
      counterparties.set(id, {
        x: Math.cos(angle) * RADIUS,
        y: Math.sin(angle) * RADIUS,
      });
    });
  }
  return { focal: { x: 0, y: 0 }, counterparties };
}

/** Approximate canvas size that fits the deterministic layout. */
export function layoutSize(counterpartyCount: number): { width: number; height: number } {
  const diameter = RADIUS * 2 + 240;
  // Grow only mildly with the bounded neighbour count so a packed page
  // never collapses into unusable overlap.
  const spread = Math.min(4, Math.max(0, counterpartyCount - 6)) * 40;
  return {
    width: Math.max(640, diameter + spread),
    height: Math.max(480, diameter + spread),
  };
}
