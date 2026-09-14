// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// History detail surface (PR 24C §12).
//
// Shows only public allowlisted fields: object type/id/version, operation,
// occurred_at, actor_id, and the backend-redacted ``state``/``diff``
// projections rendered through the bounded safe JSON viewer. ``View
// versions of this object`` is History-internal navigation via the
// object-scoped endpoint — never a PR 24D pivot and never a generic
// entity explorer.

import { Box, Button, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { DrawerError, DrawerLoading } from "../analyst-table/DetailDrawer";
import { DetailRows, DetailSection } from "../analyst-table/DetailRows";
import { isNotFound404 } from "../analyst-table/detail-error";
import { SafeJsonView } from "../analyst-table/SafeJsonView";
import { Timestamp } from "../components/Timestamp";
import { historyOperationKey } from "./labels";
import { useHistoryVersion, useObjectHistoryPage } from "./history-queries";

export interface HistoryDetailProps {
  investigationId: string;
  objectType: string;
  objectId: string;
  version: number;
}

/**
 * Exact-version detail plus a toggle for the object-scoped version list.
 */
export function HistoryDetail({
  investigationId,
  objectType,
  objectId,
  version,
}: HistoryDetailProps): ReactElement {
  const { t } = useTranslation("history");
  const [showVersions, setShowVersions] = useState(false);
  const exact = useHistoryVersion(
    investigationId,
    objectType,
    objectId,
    showVersions ? version : version,
  );
  void showVersions;

  // Bound the page: exact-version errors render as drawer errors; the
  // versions list loads only after the explicit toggle.
  const versions = useObjectHistoryPage(
    investigationId,
    showVersions ? objectType : null,
    showVersions ? objectId : null,
  );

  const body = (): ReactElement => {
    if (exact.isLoading && exact.record === null) {
      return <DrawerLoading label={t("detail.loading")} />;
    }
    if (exact.isError && exact.record === null) {
      if (exact.error !== null && isNotFound404(exact.error)) {
        return (
          <Box role="status" aria-live="polite" sx={{ py: 2 }}>
            <Typography variant="body1">{t("detail.notFound.title")}</Typography>
          </Box>
        );
      }
      return <DrawerError title={t("detail.loadError.title")} onRetry={exact.refetch} />;
    }
    if (exact.record === null) {
      return <DrawerLoading label={t("detail.loading")} />;
    }
    return renderRecord(t, exact.record);
  };

  return (
    <Box>
      {body()}
      <Button
        size="small"
        variant="outlined"
        onClick={() => setShowVersions((current) => !current)}
        sx={{ mt: 1.5, textTransform: "none" }}
        aria-expanded={showVersions}
      >
        {showVersions ? t("versions.hide") : t("versions.show")}
      </Button>
      {showVersions ? (
        <DetailSection title={t("versions.title")}>
          {versions.isLoading && versions.page === null ? (
            <DrawerLoading label={t("versions.loading")} />
          ) : null}
          {versions.isError && versions.page === null ? (
            <DrawerError title={t("versions.error")} onRetry={versions.refetch} />
          ) : null}
          {versions.page !== null && versions.page.items.length === 0 ? (
            <Typography variant="body2">{t("versions.none")}</Typography>
          ) : null}
          {versions.page !== null && versions.page.items.length > 0 ? (
            <Box role="list" aria-label={t("versions.title")}>
              {versions.page.items.map((record) => (
                <Box
                  key={record.id}
                  role="listitem"
                  sx={{ display: "flex", gap: 1, alignItems: "baseline" }}
                >
                  <Typography variant="body2" sx={{ minWidth: 40 }}>
                    {t("versions.version", { version: String(record.version) })}
                  </Typography>
                  <Typography variant="body2">{t(historyOperationKey(record.operation))}</Typography>
                  <Typography variant="caption" component="span">
                    <Timestamp iso={record.occurred_at} />
                  </Typography>
                </Box>
              ))}
            </Box>
          ) : null}
        </DetailSection>
      ) : null}
    </Box>
  );
}

/** One redacted history record rendered as data, never as markup. */
function renderRecord(
  t: (key: string) => string,
  record: {
    object_type: string;
    object_id: string;
    version: number;
    operation: string;
    occurred_at: string;
    actor_id: string | null;
    state?: Record<string, unknown> | null;
    diff?: Record<string, unknown> | null;
  },
): ReactElement {
  const hasState = record.state !== undefined && record.state !== null && Object.keys(record.state).length > 0;
  const hasDiff = record.diff !== undefined && record.diff !== null && Object.keys(record.diff).length > 0;
  return (
    <Box>
      <DetailRows
        rows={[
          { label: t("detail.objectType"), value: record.object_type },
          { label: t("detail.objectId"), value: record.object_id },
          { label: t("detail.version"), value: String(record.version) },
          { label: t("detail.operation"), value: t(historyOperationKey(record.operation)) },
          { label: t("detail.occurredAt"), value: <Timestamp iso={record.occurred_at} /> },
          {
            label: t("detail.actorId"),
            value: record.actor_id !== null ? record.actor_id : t("detail.nullable"),
          },
        ]}
      />
      {hasState ? (
        <DetailSection title={t("detail.state")}>
          <SafeJsonView data={record.state} label={t("detail.state")} />
        </DetailSection>
      ) : null}
      {hasDiff ? (
        <DetailSection title={t("detail.diff")}>
          <SafeJsonView data={record.diff} label={t("detail.diff")} />
        </DetailSection>
      ) : null}
    </Box>
  );
}