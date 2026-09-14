// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Evolution + Graph workspace (PR 24E §9, §13, §20, §28).
//
// Route-independent first-class entity-centric surface. The focal entity
// must be present in the URL; without it the workspace renders an
// instructional empty state and never queries observations. Evolution is a
// bounded server-scoped view of RelationshipObservation rows joined to
// their stable Relationship; Graph is a bounded one-hop neighborhood of the
// Relationships collection. ``view`` switches the workspace without losing
// entity/filter context; observed-range filters stay in the URL while
// Graph (correctly) does not apply them to stable edges. Cursor is opaque
// and bound to the exact filter context; changing any semantic filter
// resets it. No infinite recursion, no client-side global history.

import {
  Alert,
  Box,
  Button,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from "@mui/material";
import type { ReactElement } from "react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router";

import type { Investigation, RelationshipObservation } from "../api/schema-types";
import { DetailDrawer } from "../analyst-table/DetailDrawer";
import { DetailRows } from "../analyst-table/DetailRows";
import { isUuidValue } from "../analyst-table/filters";
import { useFilterForm } from "../analyst-table/filter-form";
import {
  clearSelectedParam,
  setSelectedParam,
  SELECTED_PARAM,
} from "../analyst-table/url-params";
import {
  hasPrevious,
  initialBackStack,
  popBackStack,
  pushNextStack,
} from "../analyst-table/cursor-stack";
import { runningNotice } from "../analyst-table/running";
import { buildCsv, downloadCsv, exportFilename } from "../analyst-table/export";
import { Timestamp } from "../components/Timestamp";
import { CompactId } from "../components/CompactId";
import { PivotMenu } from "../pivots/PivotMenu";
import { observationActions } from "../pivots/pivot-capabilities";
import { relationshipTypeKey } from "../relationships/labels";
import { useObservationsPage, useRelationshipsPage } from "../relationships/relationships-queries";
import {
  emptyObservationFilters,
  emptyRelationshipFilters,
  type RelationshipFilters,
} from "../relationships/relationships-filters";
import { RelationshipGraph } from "../relationship-graph/RelationshipGraph";
import { buildGraphModel } from "../relationship-graph/relationship-graph-model";
import { RelationshipEvolutionTimeline } from "./RelationshipEvolutionTimeline";
import {
  RelationshipEvolutionFilters as RelationshipEvolutionFiltersToolbar,
  draftFromCommitted,
  draftToCommitted,
  evolutionDraftError,
  evolutionFiltersKey,
  type EvolutionDraft,
} from "./RelationshipEvolutionFilters";
import {
  applyEvolutionFilters,
  emptyEvolutionFilters,
  evolutionFiltersActive,
  evolutionFiltersToObservationFilters,
  parseEvolutionCursor,
  parseEvolutionParams,
  parseViewParam,
  setEvolutionCursor,
  setEvolutionView,
  type EvolutionWorkspaceView,
  type RelationshipEvolutionFilters,
} from "./relationship-evolution-url";
import {
  buildEvolutionModel,
  edgeDirection,
  evolutionTimeSpan,
} from "./relationship-evolution-model";
import { earliestPagePoint, annotateLanes } from "./relationship-evolution-derived";

export interface RelationshipEvolutionWorkspaceProps {
  investigationId: string;
  investigation: Investigation | null;
}

/** The Evolution|Graph entity-centric workspace. */
export function RelationshipEvolutionWorkspace({
  investigationId,
  investigation,
}: RelationshipEvolutionWorkspaceProps): ReactElement {
  const { t } = useTranslation("relationshipEvolution");
  const { t: tCommon } = useTranslation("common");
  const { t: tRelationships } = useTranslation("relationships");
  const [searchParams, setSearchParams] = useSearchParams();

  const filters = parseEvolutionParams(searchParams);
  const view = parseViewParam(searchParams);
  const cursor = parseEvolutionCursor(searchParams);
  const selectionRaw = searchParams.get(SELECTED_PARAM);
  const selectedId =
    selectionRaw !== null && isUuidValue(selectionRaw) ? selectionRaw.toLowerCase() : null;
  const [backStack, setBackStack] = useState<string[]>(() => initialBackStack(cursor));

  // All hooks run unconditionally; null-filter safety happens in the query
  // hooks (enabled=false) and in the render tree below.
  const observationFilters = useMemo(
    () =>
      filters === null ? null : evolutionFiltersToObservationFilters(filters),
    [filters],
  );
  const observations = useObservationsPage(
    investigationId,
    observationFilters ?? emptyObservationFilters(),
    cursor,
    view === "evolution" && observationFilters !== null,
  );

  const graphFilters: RelationshipFilters | null = useMemo(() => {
    if (filters === null) {
      return null;
    }
    return {
      ...emptyRelationshipFilters(),
      entityId: filters.entityId,
      relationshipType: filters.relationshipType,
    };
  }, [filters]);
  const graphRelationships = useRelationshipsPage(
    investigationId,
    graphFilters ?? emptyRelationshipFilters(),
    undefined,
    view === "graph" && graphFilters !== null,
  );

  const graphModel = useMemo(
    () =>
      filters === null
        ? null
        : buildGraphModel(filters.entityId, graphRelationships.page?.items ?? []),
    [filters, graphRelationships.page],
  );
  const evolutionModel = useMemo(
    () =>
      filters === null
        ? null
        : buildEvolutionModel(filters.entityId, observations.page?.items ?? []),
    [filters, observations.page],
  );
  const span = useMemo(
    () =>
      evolutionModel === null
        ? null
        : evolutionTimeSpan(evolutionModel.lanes.flatMap((lane) => lane.points)),
    [evolutionModel],
  );
  const annotations = useMemo(
    () =>
      evolutionModel === null
        ? new Map<string, { pageObservationCount: number; isEarliestShown: boolean }>()
        : annotateLanes(
            evolutionModel.lanes,
            earliestPagePoint(evolutionModel.lanes.flatMap((lane) => lane.points)),
          ),
    [evolutionModel],
  );

  const committed = filters ?? emptyEvolutionFilters("");
  const filterForm = useFilterForm<typeof committed, EvolutionDraft>({
    committed,
    buildDraft: draftFromCommitted,
    toFilters: (draft) => draftToCommitted(committed.entityId, draft),
    validateDraft: (draft) => evolutionDraftError(t as never, draft),
    onApply: applyFilters,
    onClear: () => applyFilters(emptyEvolutionFilters(committed.entityId)),
    emptyDraft: draftFromCommitted(emptyEvolutionFilters(committed.entityId)),
    committedKey: evolutionFiltersKey(committed),
  });

  const commit = (next: URLSearchParams): void => {
    setSearchParams(next, { replace: false });
  };

  function applyFilters(next: RelationshipEvolutionFilters): void {
    setBackStack([]);
    commit(applyEvolutionFilters(searchParams, next));
  }

  const goNext = (): void => {
    const page = observations.page;
    if (page === null || page.next_cursor === null || page.next_cursor === undefined) {
      return;
    }
    setBackStack(pushNextStack(backStack, cursor));
    commit(setEvolutionCursor(searchParams, page.next_cursor));
  };

  const goPrevious = (): void => {
    const { stack, prior } = popBackStack(backStack);
    setBackStack(stack);
    commit(setEvolutionCursor(searchParams, prior));
  };

  const returnToFirstPage = (): void => {
    setBackStack([]);
    commit(setEvolutionCursor(searchParams, undefined));
  };

  const exportCurrentPage = (): void => {
    const page = observations.page;
    if (page === null || filters === null) {
      return;
    }
    const header = [
      t("timeline.table.observation"),
      t("timeline.table.type"),
      t("timeline.table.direction"),
      t("timeline.table.counterparty"),
      t("timeline.table.source"),
      t("timeline.table.observedAt"),
      t("timeline.table.retrievedAt"),
      t("timeline.table.evidence"),
    ];
    const rows = page.items.map((observation) => [
      observation.id,
      observation.relationship_type ?? "",
      edgeDirectionName(filters.entityId, observation),
      counterpartyIdOf(filters.entityId, observation),
      observation.source,
      observation.observed_at ?? "",
      observation.retrieved_at,
      observation.evidence_id,
    ]);
    downloadCsv(
      exportFilename("relationship-evolution", investigationId),
      buildCsv(header, rows),
    );
  };

  const switchView = (_event: unknown, nextView: EvolutionWorkspaceView | null): void => {
    if (nextView === null) {
      return;
    }
    commit(setEvolutionView(searchParams, nextView));
  };

  const openSelection = (id: string): void => {
    commit(setSelectedParam(searchParams, id));
  };
  const closeSelection = (): void => {
    commit(clearSelectedParam(searchParams));
  };

  // No focal entity: instructional empty state, never a query (E-U01).
  if (filters === null) {
    return (
      <Box>
        <WorkspaceTitle investigationId={investigationId} t={t} />
        <Typography variant="h4" sx={{ py: 3, textAlign: "center", fontWeight: 600 }}>
          {t("empty.entity.title")}
        </Typography>
        <Typography variant="body2" sx={{ textAlign: "center" }}>
          {t("empty.entity.message")}
        </Typography>
      </Box>
    );
  }

  const hasActive = evolutionFiltersActive(filters);
  const selectedObservation: RelationshipObservation | null =
    selectedId === null
      ? null
      : observations.page?.items.find((row) => row.id === selectedId) ?? null;
  const drawerOpen = selectedId !== null && view === "evolution";
  const hasNext =
    observations.page !== null &&
    observations.page.next_cursor !== null &&
    observations.page.next_cursor !== undefined;

  return (
    <Box>
      {runningNotice(
        investigation?.status,
        observations.refetch,
        t("running.notice"),
        tCommon("table.refresh"),
      )}
      <WorkspaceTitle investigationId={investigationId} t={t} />
      <Box sx={{ mb: 1 }}>
        <ToggleButtonGroup
          value={view}
          exclusive
          onChange={switchView}
          size="small"
          aria-label={t("view.switchAria")}
        >
          <ToggleButton value="evolution">{t("view.evolution")}</ToggleButton>
          <ToggleButton value="graph">{t("view.graph")}</ToggleButton>
        </ToggleButtonGroup>
        {view === "graph" ? (
          <Typography variant="caption" component="div" sx={{ mt: 0.5 }}>
            {t("graph.temporalHint")}
          </Typography>
        ) : null}
      </Box>

      {view === "evolution" ? (
        <Box>
          <RelationshipEvolutionFiltersToolbar
            t={t as never}
            tCommon={tCommon as never}
            draft={filterForm.draft}
            hasActiveFilters={hasActive}
            relationshipTypeLabel={(type) => tRelationships(relationshipTypeKey(type))}
            onSetDraft={filterForm.setDraft}
            onApply={filterForm.apply}
            onClear={filterForm.clear}
            onExport={exportCurrentPage}
          />
          {filterForm.error !== null ? (
            <Typography
              variant="caption"
              role="alert"
              color="error"
              sx={{ display: "block", mb: 0.5 }}
            >
              {filterForm.error}
            </Typography>
          ) : null}
          {observations.isLoading && observations.page === null ? (
            <Alert severity="info" role="status" sx={{ mt: 1 }}>
              {t("loading")}
            </Alert>
          ) : null}
          {observations.error !== null && observations.page === null ? (
            <Box sx={{ mt: 1 }}>
              <Alert severity="error" role="alert">
                {t("error.message")}
              </Alert>
              <Box sx={{ display: "flex", gap: 1, mt: 1 }}>
                <Button size="small" variant="outlined" onClick={() => observations.refetch()}>
                  {t("error.retry")}
                </Button>
                <Button size="small" variant="outlined" onClick={returnToFirstPage}>
                  {t("error.firstPage")}
                </Button>
              </Box>
            </Box>
          ) : null}
          {observations.page !== null && evolutionModel !== null ? (
            <Box sx={{ mt: 1 }}>
              <RelationshipEvolutionTimeline
                focalEntityId={filters.entityId}
                model={evolutionModel}
                span={span}
                annotations={annotations}
                rows={observations.page.items}
                labels={{
                  heading: t("timeline.heading"),
                  boundedNotice: t("timeline.boundedNotice"),
                  unavailableTitle: t("timeline.unavailable.title"),
                  unavailableHint: t("timeline.unavailable.hint"),
                  viewAsTable: t("timeline.table.viewAs"),
                  tableView: t("timeline.table.heading"),
                  tableColumns: {
                    observation: t("timeline.table.observation"),
                    type: t("timeline.table.type"),
                    direction: t("timeline.table.direction"),
                    counterparty: t("timeline.table.counterparty"),
                    source: t("timeline.table.source"),
                    observedAt: t("timeline.table.observedAt"),
                    retrievedAt: t("timeline.table.retrievedAt"),
                    evidence: t("timeline.table.evidence"),
                  },
                  lanesHeading: t("timeline.heading"),
                  directionInbound: t("directions.inbound"),
                  directionOutbound: t("directions.outbound"),
                  directionEither: t("directions.either"),
                  earliestShown: t("timeline.earliestShown"),
                  empty: hasActive
                    ? t("empty.filtered.title")
                    : t("empty.observations.title"),
                }}
                typeLabel={(type) => tRelationships(relationshipTypeKey(type))}
                hasNext={hasNext}
                onActivate={openSelection}
              />
              <Box
                component="nav"
                aria-label={t("pagination.label")}
                sx={{ display: "flex", gap: 1, mt: 1.5 }}
              >
                <Button
                  size="small"
                  variant="outlined"
                  disabled={!hasPrevious(backStack)}
                  onClick={goPrevious}
                >
                  {t("pagination.previous")}
                </Button>
                <Button size="small" variant="outlined" disabled={!hasNext} onClick={goNext}>
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
        </Box>
      ) : (
        <Box>
          {graphModel !== null ? (
            <RelationshipGraph
              investigationId={investigationId}
              focalEntityId={filters.entityId}
              model={graphModel}
              rows={graphRelationships.page?.items ?? []}
              hasNext={
                graphRelationships.page !== null &&
                graphRelationships.page.next_cursor !== null &&
                graphRelationships.page.next_cursor !== undefined
              }
              typeLabel={(type) => tRelationships(relationshipTypeKey(type))}
            />
          ) : null}
          {graphRelationships.error !== null && graphRelationships.page === null ? (
            <Box sx={{ mt: 1 }}>
              <Alert severity="error" role="alert">
                {t("error.message")}
              </Alert>
              <Box sx={{ display: "flex", gap: 1, mt: 1 }}>
                <Button
                  size="small"
                  variant="outlined"
                  onClick={() => graphRelationships.refetch()}
                >
                  {t("error.retry")}
                </Button>
              </Box>
            </Box>
          ) : null}
        </Box>
      )}

      <DetailDrawer open={drawerOpen} title={t("detail.title")} onClose={closeSelection}>
        {drawerOpen ? (
          selectedObservation !== null ? (
            <ObservationDetailBody
              t={t as never}
              investigationId={investigationId}
              observation={selectedObservation}
            />
          ) : (
            <Box role="status" sx={{ py: 2, textAlign: "center" }}>
              <Typography variant="body1">{t("detail.notOnPage.title")}</Typography>
              <Typography variant="caption" component="div" sx={{ mt: 0.5 }}>
                {t("detail.notOnPage.message")}
              </Typography>
            </Box>
          )
        ) : null}
      </DetailDrawer>
    </Box>
  );
}

/** The workspace heading + regression-safe breadcrumb to Relationships. */
function WorkspaceTitle({
  investigationId,
  t,
}: {
  investigationId: string;
  t: (key: string) => string;
}): ReactElement {
  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
      <Typography variant="h2">{t("title")}</Typography>
      <Typography variant="body2" component="span" role="navigation" aria-label={t("nav.label")}>
        <Link to={`/investigations/${investigationId}/relationships`} style={{ textDecoration: "none" }}>
          {t("nav.relationships")}
        </Link>
      </Typography>
    </Box>
  );
}

/** The observation detail surface (PR 24E §17). */
function ObservationDetailBody({
  t,
  investigationId,
  observation,
}: {
  t: (key: string) => string;
  investigationId: string;
  observation: RelationshipObservation;
}): ReactElement {
  return (
    <Box>
      <DetailRows
        rows={[
          {
            label: t("detail.relationshipId"),
            value: <CompactId id={observation.relationship_id} label={t("detail.relationshipId")} />,
          },
          {
            label: t("detail.sourceEntity"),
            value: (
              <CompactId
                id={observation.relationship_source_entity_id ?? observation.relationship_id}
                label={t("detail.sourceEntity")}
              />
            ),
          },
          {
            label: t("detail.targetEntity"),
            value: (
              <CompactId
                id={observation.relationship_target_entity_id ?? observation.relationship_id}
                label={t("detail.targetEntity")}
              />
            ),
          },
          {
            label: t("detail.relationshipType"),
            value: typeLabel(t as never, observation.relationship_type ?? null),
          },
          { label: t("detail.source"), value: observation.source },
          {
            label: t("detail.observedAt"),
            value:
              observation.observed_at !== null
                ? <Timestamp iso={observation.observed_at} />
                : t("detail.notObserved"),
          },
          { label: t("detail.retrievedAt"), value: <Timestamp iso={observation.retrieved_at} /> },
          {
            label: t("detail.evidenceId"),
            value: <CompactId id={observation.evidence_id} label={t("detail.evidenceId")} />,
          },
          {
            label: t("detail.observationId"),
            value: <CompactId id={observation.id} label={t("detail.observationId")} />,
          },
        ]}
      />
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 1 }}>
        <PivotMenu
          actions={observationActions(observation, "detail_field")}
          ariaLabel={t("detail.provenanceAria")}
        />
        <Button
          size="small"
          component="a"
          href={`/investigations/${investigationId}/relationships?selected=${observation.relationship_id}`}
          sx={{ textTransform: "none" }}
        >
          {t("detail.viewRelationship")}
        </Button>
      </Box>
      {observation.relationship_source_entity_id !== null ||
      observation.relationship_target_entity_id !== null ? (
        <Box sx={{ mt: 1 }}>
          <Typography variant="caption" component="div" sx={{ fontWeight: 600 }}>
            {t("detail.evolutionHeading")}
          </Typography>
          {observation.relationship_source_entity_id !== null ? (
            <Typography variant="caption" component="div">
              <Link
                to={`/investigations/${investigationId}/relationships/evolution?entity_id=${observation.relationship_source_entity_id}`}
                style={{ textDecoration: "none" }}
              >
                {t("detail.evolutionSource")}
              </Link>
            </Typography>
          ) : null}
          {observation.relationship_target_entity_id !== null ? (
            <Typography variant="caption" component="div">
              <Link
                to={`/investigations/${investigationId}/relationships/evolution?entity_id=${observation.relationship_target_entity_id}`}
                style={{ textDecoration: "none" }}
              >
                {t("detail.evolutionTarget")}
              </Link>
            </Typography>
          ) : null}
        </Box>
      ) : null}
    </Box>
  );
}

/** Translate one relationship type URN (raw fallback for unknown values). */
function typeLabel(
  tRelationships: (key: string) => string,
  type: string | null,
): string {
  return type === null ? "—" : tRelationships(relationshipTypeKey(type));
}

/** Focal-relative direction of one row (exact edge semantics). */
function edgeDirectionName(
  focalEntityId: string,
  observation: RelationshipObservation,
): string {
  return edgeDirection(
    focalEntityId,
    observation.relationship_source_entity_id ?? null,
    observation.relationship_target_entity_id ?? null,
  );
}

/** The counterparty of one row (focal-relative; self edges stay self). */
function counterpartyIdOf(
  focalEntityId: string,
  observation: RelationshipObservation,
): string {
  const source = observation.relationship_source_entity_id ?? null;
  const target = observation.relationship_target_entity_id ?? null;
  if (source !== null && source !== focalEntityId) {
    return source;
  }
  if (target !== null && target !== focalEntityId) {
    return target;
  }
  return source ?? target ?? observation.relationship_id;
}