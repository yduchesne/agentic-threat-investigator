// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Graph-native Relationship provenance drill-down (PR 31F).
//
// From the canonical Relationship identity of a selected graph edge, the
// analyst inspects the Investigation-scoped Relationship, browses one
// bounded page of immutable RelationshipObservations, selects an exact
// observation (``RelationshipObservation.id``), and opens the exact
// supporting EvidenceObservation (``observation.evidence_id``) only on an
// explicit action.
//
// Identity chain (PR 31F I01/I03):
//
//   GraphEdge.relationship_id
//     -> Relationship (useRelationshipDetail)
//     -> bounded RelationshipObservations filtered by relationship_id
//     -> exact RelationshipObservation (row on page, else scoped GET)
//     -> exact EvidenceObservation by observation.evidence_id
//
// Everything stays Investigation-scoped and read-only: no global probes,
// no Evidence fan-out, no cursor scanning, no Relationship lifetime
// inference, and no graph-topology mutation. ``observed_at`` and
// ``retrieved_at`` remain distinct and a null ``observed_at`` stays
// unavailable (never replaced by retrieved time). All drill-down state
// (cursor, back stack, selections) is transient browser state, never
// URL-serialized, never persisted, never shared with graph topology.

import { Box, Button, Typography } from "@mui/material";
import type { ReactElement, ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";

import type { Relationship, RelationshipObservation } from "../api/schema-types";
import { DetailRows, DetailSection } from "../analyst-table/DetailRows";
import { DrawerError, DrawerLoading, DrawerNotFound } from "../analyst-table/DetailDrawer";
import { isNotFound404 } from "../analyst-table/detail-error";
import { hasPrevious, popBackStack, pushNextStack } from "../analyst-table/cursor-stack";
import { Timestamp } from "../components/Timestamp";
import { CompactId } from "../components/CompactId";
import { EvidenceDetail } from "../evidence/EvidenceDetail";
import { useEvidenceDetail } from "../evidence/evidence-queries";
import { relationshipTypeKey } from "../relationships/labels";
import {
  useObservationDetail,
  useObservationsPage,
  useRelationshipDetail,
} from "../relationships/relationships-queries";
import { emptyObservationFilters } from "../relationships/relationships-filters";
import { observationDetailRows } from "../relationships/RelationshipObservationsWorkspace";

export interface GraphRelationshipProvenanceProps {
  investigationId: string;
  /** The canonical Relationship identity of the selected graph edge. */
  relationshipId: string;
  /** Hide the provenance surface (graph/expansion state is untouched). */
  onClose: () => void;
}

/** The graph-local Relationship -> observation -> Evidence drill-down. */
export function GraphRelationshipProvenance({
  investigationId,
  relationshipId,
  onClose,
}: GraphRelationshipProvenanceProps): ReactElement {
  const { t } = useTranslation("relationshipEvolution");
  const { t: tRelationships } = useTranslation("relationships");

  // Transient drill-down state (PR 31F §10): the bounded observation
  // cursor, its browser-local back stack, and the exact observation /
  // Evidence selections. Never URL-serialized, never persisted.
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [backStack, setBackStack] = useState<string[]>([]);
  const [selectedObservationId, setSelectedObservationId] = useState<string | null>(null);
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);

  // A new canonical Relationship resets the whole drill-down chain: first
  // bounded page, empty back stack, and no observation/Evidence selection
  // can ever leak provenance from the prior edge (PR 31F U15).
  useEffect(() => {
    setCursor(undefined);
    setBackStack([]);
    setSelectedObservationId(null);
    setSelectedEvidenceId(null);
  }, [relationshipId]);

  // Investigation-scoped exact Relationship read (never a global probe).
  const relationshipDetail = useRelationshipDetail(investigationId, relationshipId);

  // Bounded observation page filtered by the exact relationship_id.
  const observationFilters = useMemo(
    () => ({ ...emptyObservationFilters(), relationshipId }),
    [relationshipId],
  );
  const list = useObservationsPage(investigationId, observationFilters, cursor);

  // Exact observation selection identity is ``observation.id``. Rows
  // already present on the loaded page render from the page; any other
  // selection resolves through the exact Investigation-scoped GET — never
  // a cursor scan, never a reconstructed or substitute observation.
  const selectedRow = useMemo(
    () =>
      list.page?.items.find(
        (observation) => observation.id === selectedObservationId,
      ) ?? null,
    [list.page, selectedObservationId],
  );
  const needsExactObservation =
    selectedObservationId !== null && selectedRow === null;
  const observationDetail = useObservationDetail(
    investigationId,
    needsExactObservation ? selectedObservationId : null,
  );

  // Evidence loads only on an explicit analyst action; listing or selecting
  // observations never fans out Evidence requests (PR 31F I07/U22-U24).
  const evidenceDetail = useEvidenceDetail(investigationId, selectedEvidenceId);

  const goNext = (): void => {
    if (
      list.page === null ||
      list.page.next_cursor === null ||
      list.page.next_cursor === undefined
    ) {
      return;
    }
    setBackStack(pushNextStack(backStack, cursor));
    setCursor(list.page.next_cursor);
  };
  const goPrevious = (): void => {
    const { stack, prior } = popBackStack(backStack);
    setBackStack(stack);
    setCursor(prior);
  };
  const returnToFirstPage = (): void => {
    setBackStack([]);
    setCursor(undefined);
  };

  const selectObservation = (observationId: string): void => {
    setSelectedObservationId(observationId);
    // A new observation always clears the prior Evidence selection (U30).
    setSelectedEvidenceId(null);
  };

  const page = list.page;
  const exactObservation = observationDetail.observation;
  const activeObservation: RelationshipObservation | null =
    selectedRow ?? exactObservation;

  return (
    <Box
      component="section"
      aria-label={t("graph.provenance.heading")}
      sx={{ mt: 1.5, p: 1, border: 1, borderColor: "divider", borderRadius: 1 }}
    >
      <Box
        sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}
      >
        <Typography variant="subtitle2" component="h4">
          {t("graph.provenance.heading")}
        </Typography>
        <Button size="small" onClick={onClose} sx={{ textTransform: "none" }}>
          {t("graph.provenance.close")}
        </Button>
      </Box>

      <DetailSection title={t("graph.provenance.relationship")}>
        {relationshipDetail.isLoading && relationshipDetail.relationship === null ? (
          <DrawerLoading label={t("graph.provenance.loading.relationship")} />
        ) : null}
        {relationshipDetail.isError && relationshipDetail.relationship === null ? (
          isNotFound404(relationshipDetail.error) ? (
            <DrawerNotFound title={t("graph.provenance.notFound.relationship")} />
          ) : (
            <DrawerError
              title={t("graph.provenance.error.relationship")}
              onRetry={relationshipDetail.refetch}
            />
          )
        ) : null}
        {relationshipDetail.relationship !== null ? (
          <DetailRows
            rows={stableRelationshipRows(
              tRelationships as never,
              relationshipDetail.relationship,
            )}
          />
        ) : null}
      </DetailSection>

      <DetailSection title={t("graph.provenance.observations")}>
        {list.isLoading && page === null ? (
          <DrawerLoading label={t("graph.provenance.loading.observations")} />
        ) : null}
        {list.isError && page === null ? (
          <DrawerError
            title={t("graph.provenance.error.observations")}
            onRetry={list.refetch}
          />
        ) : null}
        {page !== null && page.items.length === 0 ? (
          <Typography variant="body2">{t("graph.provenance.empty")}</Typography>
        ) : null}
        {page !== null && page.items.length > 0 ? (
          <Box>
            <Box sx={{ overflowX: "auto" }}>
              <table
                aria-label={t("graph.provenance.aria.observations")}
                style={{ borderCollapse: "collapse", width: "100%" }}
              >
                <thead>
                  <tr>
                    {[
                      tRelationships("columns.source"),
                      tRelationships("columns.observedAt"),
                      tRelationships("columns.retrievedAt"),
                      tRelationships("detail.confidence"),
                      tRelationships("columns.observationId"),
                      tRelationships("columns.evidence"),
                      t("graph.provenance.selectObservation"),
                    ].map((header) => (
                      <th key={header} scope="col" style={{ textAlign: "left", padding: 6 }}>
                        {header}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((observation) => (
                    <tr key={observation.id}>
                      <td style={{ padding: 6 }}>{observation.source}</td>
                      <td style={{ padding: 6 }}>
                        {observation.observed_at !== null ? (
                          <Timestamp iso={observation.observed_at} />
                        ) : (
                          tRelationships("detail.notObserved")
                        )}
                      </td>
                      <td style={{ padding: 6 }}>
                        <Timestamp iso={observation.retrieved_at} />
                      </td>
                      <td style={{ padding: 6 }}>
                        {observation.confidence !== null
                          ? String(observation.confidence)
                          : tRelationships("detail.nullable")}
                      </td>
                      <td style={{ padding: 6 }}>
                        <CompactId
                          id={observation.id}
                          label={tRelationships("columns.observationId")}
                        />
                      </td>
                      <td style={{ padding: 6 }}>
                        <CompactId
                          id={observation.evidence_id}
                          label={tRelationships("columns.evidence")}
                        />
                      </td>
                      <td style={{ padding: 6 }}>
                        <Button
                          size="small"
                          variant="outlined"
                          onClick={() => selectObservation(observation.id)}
                          sx={{ textTransform: "none" }}
                        >
                          {t("graph.provenance.selectObservation")}
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Box>
            <Box
              component="nav"
              aria-label={t("graph.provenance.aria.pagination")}
              sx={{ display: "flex", gap: 1, mt: 1 }}
            >
              <Button
                size="small"
                variant="outlined"
                disabled={!hasPrevious(backStack)}
                onClick={goPrevious}
              >
                {t("pagination.previous")}
              </Button>
              <Button
                size="small"
                variant="outlined"
                disabled={!hasNext(page)}
                onClick={goNext}
              >
                {t("pagination.next")}
              </Button>
              {cursor !== undefined ? (
                <Button size="small" variant="text" onClick={returnToFirstPage}>
                  {t("pagination.first")}
                </Button>
              ) : null}
            </Box>
          </Box>
        ) : null}
      </DetailSection>

      {selectedObservationId !== null ? (
        <DetailSection title={t("graph.provenance.observation")}>
          {activeObservation !== null ? (
            <Box>
              {observationDetailRows(tRelationships as never, activeObservation)}
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 1 }}>
                <Button
                  size="small"
                  variant="outlined"
                  onClick={() => setSelectedEvidenceId(activeObservation.evidence_id)}
                  sx={{ textTransform: "none" }}
                >
                  {t("graph.provenance.viewEvidence")}
                </Button>
              </Box>
            </Box>
          ) : null}
          {activeObservation === null &&
          observationDetail.isLoading &&
          exactObservation === null ? (
            <DrawerLoading label={t("graph.provenance.loading.observation")} />
          ) : null}
          {activeObservation === null &&
          observationDetail.isError &&
          exactObservation === null ? (
            isNotFound404(observationDetail.error) ? (
              <DrawerNotFound title={t("graph.provenance.notFound.observation")} />
            ) : (
              <DrawerError
                title={t("graph.provenance.error.observation")}
                onRetry={observationDetail.refetch}
              />
            )
          ) : null}
          {activeObservation === null &&
          !observationDetail.isLoading &&
          !observationDetail.isError ? (
            <DrawerLoading label={t("graph.provenance.loading.observation")} />
          ) : null}
        </DetailSection>
      ) : null}

      {selectedEvidenceId !== null ? (
        <DetailSection title={t("graph.provenance.evidence")}>
          {evidenceDetail.isLoading && evidenceDetail.evidence === null ? (
            <DrawerLoading label={t("graph.provenance.loading.evidence")} />
          ) : null}
          {evidenceDetail.isError && evidenceDetail.evidence === null ? (
            isNotFound404(evidenceDetail.error) ? (
              <DrawerNotFound title={t("graph.provenance.notFound.evidence")} />
            ) : (
              <DrawerError
                title={t("graph.provenance.error.evidence")}
                onRetry={evidenceDetail.refetch}
              />
            )
          ) : null}
          {evidenceDetail.evidence !== null ? (
            <Box>
              <EvidenceDetail evidence={evidenceDetail.evidence} />
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 1 }}>
                <Button
                  size="small"
                  variant="outlined"
                  onClick={() => setSelectedEvidenceId(null)}
                  sx={{ textTransform: "none" }}
                >
                  {t("graph.provenance.backToObservation")}
                </Button>
              </Box>
            </Box>
          ) : null}
        </DetailSection>
      ) : null}
    </Box>
  );
}

/** Whether the backend observation page offers a next page. */
export function hasNext(page: { next_cursor?: string | null } | null): boolean {
  return page !== null && page.next_cursor !== null && page.next_cursor !== undefined;
}

/**
 * The canonical stable Relationship fields (PR 31F Step 3).
 *
 * Presented with the existing DetailRows layout and exact labels; no
 * observation preview is fetched here, so the graph's own bounded
 * observation page is the single observation query for this Relationship.
 */
function stableRelationshipRows(
  t: TFunction,
  relationship: Relationship,
): {
  label: string;
  value: ReactNode;
}[] {
  return [
    {
      label: t("detail.sourceEntity"),
      value: (
        <CompactId
          id={relationship.source_entity_id}
          label={t("detail.sourceEntity")}
        />
      ),
    },
    {
      label: t("detail.relationshipType"),
      value: t(relationshipTypeKey(relationship.type)),
    },
    {
      label: t("detail.targetEntity"),
      value: (
        <CompactId
          id={relationship.target_entity_id}
          label={t("detail.targetEntity")}
        />
      ),
    },
    {
      label: t("detail.relationshipId"),
      value: <CompactId id={relationship.id} label={t("detail.relationshipId")} />,
    },
  ];
}
