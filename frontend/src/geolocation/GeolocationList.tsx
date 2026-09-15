// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Always-available non-map geolocation representation (PR 25B §33-§35).
//
// One accessible compact table of **all** returned PR 25A items, including
// coordinate-less ones, in server order — the authoritative accessibility
// alternative and the tile/network-failure-resilient surface. It is never
// paginated client-side (the server already bounded the collection) and
// carries no filtering/sorting semantics. The coordinate status column only
// states honestly whether a row is plotted; it is not a semantic analysis
// surface.

import { Box, Button, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import type { InvestigationGeolocation } from "../api/schema-types";
import { Timestamp } from "../components/Timestamp";
import {
  geoPrecisionKey,
  isPlottableCoordinate,
  locationLabel,
  providerLabelKey,
} from "./geolocation-map-model";

export interface GeolocationListProps {
  /** Every returned item in PR 25A server order (plotted or not). */
  items: readonly InvestigationGeolocation[];
  /** Exact Evidence provenance action (the exact PR 25A evidence_id). */
  onViewEvidence: (evidenceId: string) => void;
}

/** The always-available compact table of all returned geolocation items. */
export function GeolocationList({
  items,
  onViewEvidence,
}: GeolocationListProps): ReactElement {
  const { t } = useTranslation("geolocation");
  return (
    <Box sx={{ mt: 2 }}>
      <Typography variant="h3">{t("list.title")}</Typography>
      {items.length === 0 ? (
        <Typography variant="body2" sx={{ mt: 0.5 }}>
          {t("list.empty")}
        </Typography>
      ) : (
        <TableContainer component={Box} sx={{ mt: 0.5 }}>
          <Table size="small" aria-label={t("list.ariaLabel")} sx={{ minWidth: 760 }}>
            <TableHead>
              <TableRow>
                <TableCell>{t("list.columns.ip")}</TableCell>
                <TableCell>{t("list.columns.location")}</TableCell>
                <TableCell>{t("list.columns.precision")}</TableCell>
                <TableCell>{t("list.columns.provider")}</TableCell>
                <TableCell>{t("list.columns.retrieved")}</TableCell>
                <TableCell>{t("list.columns.observed")}</TableCell>
                <TableCell>{t("list.columns.status")}</TableCell>
                <TableCell>{t("list.row.view")}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((item) => {
                const providerKey = providerLabelKey(item.provider);
                return (
                  <TableRow key={item.evidence_id} hover>
                    <TableCell component="th" scope="row">
                      {item.ip_address}
                    </TableCell>
                    <TableCell>
                      {locationLabel(item) ?? t("location.unavailable")}
                    </TableCell>
                    <TableCell>{t(geoPrecisionKey(item.precision))}</TableCell>
                    <TableCell>
                      {providerKey !== null ? t(providerKey) : item.provider}
                    </TableCell>
                    <TableCell>
                      <Timestamp iso={item.retrieved_at} />
                    </TableCell>
                    <TableCell>
                      {item.observed_at !== null ? (
                        <Timestamp iso={item.observed_at} />
                      ) : (
                        t("observed.unavailable")
                      )}
                    </TableCell>
                    <TableCell>
                      {isPlottableCoordinate(item.latitude, item.longitude)
                        ? t("list.status.plotted")
                        : t("list.status.unlocated")}
                    </TableCell>
                    <TableCell>
                      <Button
                        size="small"
                        data-evidence-id={item.evidence_id}
                        onClick={() => onViewEvidence(item.evidence_id)}
                        sx={{ textTransform: "none" }}
                      >
                        {t("list.row.view")}
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}