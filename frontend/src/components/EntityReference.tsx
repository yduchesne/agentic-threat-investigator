// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Shared human-readable Entity reference (PR 31F-5 D1/D2/D3/D4).
//
// A no-fetch presentation primitive: the canonical Entity value is primary
// and visually strongest, the translated Entity type sits immediately
// adjacent, and the optional technical identity (canonical UUID) is
// secondary. It never owns Pivot behavior, never fetches, and never
// fabricates a label; missing value/type render their exact localized
// markers and nothing more.

import { Stack, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type { EntityTypeName } from "../api/schema-types";
import { entityTypeLabelKey } from "../relationship-graph/relationship-graph-presentation";
import { CompactId } from "./CompactId";

export interface EntityReferenceProps {
  /** Canonical Entity value (primary text); absent renders the unavailable marker. */
  value: string | null | undefined;
  /** Canonical Entity type (translated, immediately adjacent); optional. */
  type?: EntityTypeName | string | null;
  /** Optional secondary technical identity (canonical UUID). */
  id?: string | null;
  /** Optional accessible description of the reference field. */
  label?: string;
}

/**
 * One human-readable Entity reference: value primary, translated type
 * adjacent, optional secondary technical ID. Presentation only — this
 * component performs no fetch and owns no Pivot/Menu behavior.
 */
export function EntityReference({
  value,
  type,
  id,
  label,
}: EntityReferenceProps): ReactElement {
  const { t } = useTranslation("relationshipEvolution");
  const { t: tEvidence } = useTranslation("evidence");
  const { t: tCommon } = useTranslation("common");
  if (value === null || value === undefined || value === "") {
    return (
      <Typography variant="body2" component="span" color="text.secondary">
        {tEvidence("detail.unavailable")}
      </Typography>
    );
  }
  return (
    <Stack
      direction="row"
      spacing={0.5}
      sx={{ alignItems: "center", gap: 0.5, flexWrap: "wrap", minWidth: 0 }}
    >
      <Typography variant="body2" component="span" sx={{ fontWeight: 600 }}>
        {value}
      </Typography>
      {type !== null && type !== undefined && type !== "" ? (
        <Typography variant="caption" component="span" sx={{ color: "text.secondary" }}>
          {t(entityTypeLabelKey(type))}
        </Typography>
      ) : null}
      {id !== null && id !== undefined && id !== "" ? (
        <CompactId id={id} label={label ?? tCommon("copyId.short")} />
      ) : null}
    </Stack>
  );
}
