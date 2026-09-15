// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Map-origin entity exploration actions (PR 25C §6-§8, §10, §28).
//
// One Investigation Map item exposes two independent surfaces: exact
// Evidence provenance (the PR 25A ``evidence_id`` through the existing
// drawer) and entity exploration through the existing PR 24 typed pivot
// capabilities. This component is the Explore surface used identically by
// the marker popup and the non-map row: it registers the exact entity
// actions with the single new ``map_entity`` source kind and keeps the
// exact persisted Entity ID as the pivot identity. The first pivot label is
// the IP display value, never the city/country/coordinates.
//
// No client-side source-OR-target Relationship merge exists; no
// coordinate-derived relationship is ever implied. ``entityActions``
// returns the four independent server-backed filters (Evidence by subject,
// Relationships by source, Relationships by target, Research by subject),
// which is the exact registered capability set every other entity surface
// reuses.

import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type { InvestigationGeolocation } from "../api/schema-types";
import { entityActions, type PivotAction } from "../pivots/pivot-capabilities";
import { PivotMenu } from "../pivots/PivotMenu";

/** The sole new pivot source kind introduced by PR 25C (map-origin). */
export const MAP_ENTITY_SOURCE_KIND = "map_entity";

export interface GeolocationEntityActionsProps {
  /** One returned PR 25A item; the exact ``entity_id`` drives every action. */
  item: InvestigationGeolocation;
}

/**
 * Register the exact Map-origin entity actions of one geolocation item.
 *
 * The IP display value is the analyst-facing label (breadcrumb identity);
 * the Entity ID is the pivot identity; nothing is derived from coordinates.
 */
export function geolocationEntityActions(
  item: InvestigationGeolocation,
): PivotAction[] {
  return entityActions(item.entity_id, item.ip_address, MAP_ENTITY_SOURCE_KIND);
}

/** The accessible Explore trigger for one Map item. */
export function GeolocationEntityActions({
  item,
}: GeolocationEntityActionsProps): ReactElement {
  const { t } = useTranslation("geolocation");
  return (
    <PivotMenu
      actions={geolocationEntityActions(item)}
      triggerLabel={t("explore.trigger")}
      ariaLabel={t("explore.aria", { ip: item.ip_address })}
    />
  );
}