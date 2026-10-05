// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Relationship Evolution + Graph workspace (PR 24E §9, §13, §20, §28; 31D).
//
// Route-independent first-class entity-centric surface. The focal entity
// must be present in the URL; without it the workspace renders an
// instructional empty state and never queries observations. Evolution is a
// bounded server-scoped view of RelationshipObservation rows joined to
// their stable Relationship; Graph is a bounded one-hop neighborhood from
// the canonical PR 31C graph endpoint (never the Relationships page).
// ``view`` switches the workspace without losing entity/filter context;
// observed-range/source/counterparty filters stay in the URL while Graph
// (correctly) sends only entity/direction/relationship type. Cursor is
// opaque and bound to the exact filter context; changing any semantic
// filter resets it. No infinite recursion, no client-side global history.

import { Alert, Box, Button, ToggleButton, ToggleButtonGroup, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router";

import type { Investigation, RelationshipObservation } from "../api/schema-types";
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
import { ResourceDetailView } from "../analyst-table/ResourceDetailView";
import { runningNotice } from "../analyst-table/running";
import { buildCsv, downloadCsv, exportFilename } from "../analyst-table/export";
import { Timestamp } from "../components/Timestamp";
import { CompactId } from "../components/CompactId";
import { PivotMenu } from "../pivots/PivotMenu";
import { observationActions } from "../pivots/pivot-capabilities";
import { relationshipTypeKey } from "../relationships/labels";
import { useObservationsPage } from "../relationships/relationships-queries";
import {
  emptyObservationFilters,
} from "../relationships/relationships-filters";
import { RelationshipGraph } from "../relationship-graph/RelationshipGraph";
import { GraphActionPanel } from "../relationship-graph/GraphActionPanel";
import {
  GraphFilters,
  graphDraftError,
  graphDraftFromCommitted,
  graphDraftToCommitted,
  type GraphDraft,
} from "../relationship-graph/GraphFilters";
import { useGraphNeighborhood, useGraphPaths, useGraphTraversal } from "../relationship-graph/graph-queries";
import {
  GRAPH_PATH_DEFAULT_MAX_DEPTH,
  GRAPH_PATH_DEFAULT_MAX_PATHS,
} from "../relationship-graph/graph-api";
import {
  buildGraphModel,
  buildGraphModelFromAccumulated,
} from "../relationship-graph/relationship-graph-model";
import {
  GraphPathModeToolbar,
  GraphPathResultPanel,
  GraphPathStatus,
  type GraphPathPanelProps,
} from "../relationship-graph/GraphPathPanel";
import { useGraphExpansion } from "../relationship-graph/use-graph-expansion";
import {
  GraphTemporalControls,
  graphTemporalDraftError,
  graphTemporalDraftFromCommitted,
  graphTemporalDraftToCommitted,
  type GraphTemporalDraft,
} from "../relationship-graph/GraphTemporalControls";
import {
  applyGraphTemporal,
  emptyGraphTemporalContext,
  graphTemporalActive,
  graphTemporalEffectiveBounds,
  graphTemporalHasNext,
  graphTemporalHasPrevious,
  graphTemporalKey,
  parseGraphTemporal,
  shiftGraphTemporalFrame,
  type GraphTemporalContext,
} from "../relationship-graph/graph-temporal";
import {
  applyGraphContext,
  emptyGraphContext,
  graphContextActive,
  graphContextKey,
  graphDepthActive,
  parseGraphContext,
  type GraphContext,
} from "../relationship-graph/graph-context-url";
import { entityTypeLabelKey } from "../relationship-graph/relationship-graph-presentation";
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
  const location = useLocation();
  const navigate = useNavigate();
  const returnTo = typeof (location.state as { returnTo?: unknown } | null)?.returnTo === "string"
    ? (location.state as { returnTo: string }).returnTo
    : null;

  const filters = parseEvolutionParams(searchParams);
  const view = parseViewParam(searchParams);
  const cursor = parseEvolutionCursor(searchParams);
  // PR 31G: the committed graph context (scope + filters) is URL-backed and
  // independent of the Evolution observation filters.
  const graphContext = parseGraphContext(searchParams);
  // PR 31J: the committed temporal tuple (observed range partitioned into
  // 4/8/12/24 half-open frames) is equally URL-backed; the active frame
  // overrides ONLY ``graphContext.observedFrom/observedTo`` per request.
  const graphTemporal = parseGraphTemporal(searchParams);
  // PR 31J A2: ONE effective request context per commit — the active frame's
  // half-open bounds override the ordinary committed observed bounds while
  // scope/entity type/relationship type/source/depth stay authoritative.
  // Every graph operation below consumes this same effective context, so
  // root topology, explicit expansion and path finding can never run against
  // different observed ranges.
  const effectiveGraphContext = useMemo(
    () => ({
      ...graphContext,
      ...graphTemporalEffectiveBounds(graphContext, graphTemporal),
    }),
    [graphContext, graphTemporal],
  );
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

  // PR 31H: the committed graph depth selects exactly ONE server operation.
  // Depth 1 keeps the one-hop neighborhood endpoint; depth 2/3 use the
  // bounded traversal endpoint. Only one hook is enabled at a time so the two
  // can never race or share a cache entry, and a depth/context change issues
  // a fresh request through its distinct TanStack Query key.
  const useOneHop = graphContext.depth === 1;
  const graphNeighborhood = useGraphNeighborhood(
    investigationId,
    filters === null ? undefined : filters.entityId,
    filters === null ? "either" : filters.direction,
    effectiveGraphContext,
    view === "graph" && filters !== null && useOneHop,
  );
  const graphTraversal = useGraphTraversal(
    investigationId,
    filters === null ? undefined : filters.entityId,
    filters === null ? "either" : filters.direction,
    effectiveGraphContext,
    view === "graph" && filters !== null && !useOneHop,
  );
  const graphResult = useOneHop ? graphNeighborhood : graphTraversal;

  // PR 31E: accumulated expansion state is owned by this controller; the
  // root neighborhood seeds it and every explicit expansion reuses the
  // same PR 31C one-hop endpoint. Root changes (including any graph
  // scope/filter change) reset it; every expansion inherits the complete
  // committed graph context.
  const graphExpansion = useGraphExpansion({
    investigationId,
    rootEntityId: filters === null ? undefined : filters.entityId,
    rootDirection: filters === null ? "either" : filters.direction,
    scope: effectiveGraphContext.scope,
    depth: effectiveGraphContext.depth,
    entityType: effectiveGraphContext.entityType,
    relationshipType: effectiveGraphContext.relationshipType,
    source: effectiveGraphContext.source,
    observedFrom: effectiveGraphContext.observedFrom,
    observedTo: effectiveGraphContext.observedTo,
    rootNeighborhood: graphResult.neighborhood,
  });

  // PR 31I: path-finding is transient workbench state (never durable, never
  // URL-backed, never a second graph context). Endpoint selection issues no
  // request; only the explicit Find commit enables the dedicated TanStack
  // path query, whose key contains the endpoints, the committed graph context
  // and the path-owned bounds, so any committed context change can never be
  // served a stale prior-context result.
  //
  // PR 31K: ``selectedActionEntityId`` is the transient analyst selection of
  // one canonical graph Entity for the bounded investigation action. It is
  // browser-local workbench state (never URL-backed, never persisted), it is
  // cleared when path mode is entered and when the committed graph context
  // (including an active temporal frame) changes, so a stale selection can
  // never be submitted against a topology that no longer represents it.
  const [pathMode, setPathMode] = useState(false);
  const [pathEndpoints, setPathEndpoints] = useState<{
    source: string | null;
    target: string | null;
  }>({ source: null, target: null });
  const [pathMaxDepth, setPathMaxDepth] = useState<number>(
    GRAPH_PATH_DEFAULT_MAX_DEPTH,
  );
  const [pathMaxPaths, setPathMaxPaths] = useState<number>(
    GRAPH_PATH_DEFAULT_MAX_PATHS,
  );
  const [selectedActionEntityId, setSelectedActionEntityId] = useState<
    string | null
  >(null);
  const [pathSelected, setPathSelected] = useState<number | "all">("all");
  const [pathRequest, setPathRequest] = useState<{
    source: string;
    target: string;
  } | null>(null);
  const pathQuery = useGraphPaths(
    investigationId,
    pathRequest?.source,
    pathRequest?.target,
    filters === null ? "either" : filters.direction,
    effectiveGraphContext,
    pathMaxDepth,
    pathMaxPaths,
    pathRequest !== null,
  );
  const pathResult = pathRequest !== null ? pathQuery.paths : null;

  // A committed graph-context change resets path state deterministically:
  // the displayed path result is cleared and both endpoint selections are
  // cleared (the simple option the PR 31I plan explicitly allows), so a stale
  // prior-context result can never render. PR 31J A4: the effective context
  // (active-frame bounds) participates in this identity, so a frame
  // transition is a real semantic graph-context transition for the path
  // workbench and expansion/key identity.
  const committedGraphKey = graphContextKey(effectiveGraphContext);
  useEffect(() => {
    setPathRequest(null);
    setPathEndpoints({ source: null, target: null });
    setPathSelected("all");
    setSelectedActionEntityId(null);
  }, [committedGraphKey]);

  const choosePathEndpoint = (entityId: string): void => {
    setPathRequest(null);
    setPathSelected("all");
    setPathEndpoints((previous) => {
      if (previous.source === null) {
        return { ...previous, source: entityId };
      }
      if (previous.target === null) {
        if (entityId === previous.source) {
          return { ...previous, source: null };
        }
        return { ...previous, target: entityId };
      }
      if (entityId === previous.source) {
        return { ...previous, source: null };
      }
      if (entityId === previous.target) {
        return { ...previous, target: null };
      }
      return { ...previous, target: entityId };
    });
  };

  const findPaths = (): void => {
    if (pathEndpoints.source === null || pathEndpoints.target === null) {
      return;
    }
    setPathSelected("all");
    setPathRequest({
      source: pathEndpoints.source,
      target: pathEndpoints.target,
    });
  };

  const exitPathMode = (): void => {
    setPathMode(false);
    setPathEndpoints({ source: null, target: null });
    setPathRequest(null);
    setPathSelected("all");
  };

  // PR 31K: a path-mode click never selects an action (path mode owns the
  // click); selecting a canonical Entity is derived from the currently
  // rendered model so a free-form/stale identity can never open the panel.
  const selectActionEntity = (entityId: string): void => {
    if (pathMode) {
      return;
    }
    setSelectedActionEntityId(entityId);
  };
  const clearActionEntity = (): void => {
    setSelectedActionEntityId(null);
  };

  const pathHighlight = useMemo(() => {
    if (pathRequest === null || pathResult === null) {
      return null;
    }
    const relationshipIds = new Set<string>();
    const entityIds = new Set<string>();
    if (pathSelected === "all") {
      for (const path of pathResult.paths) {
        path.relationship_ids.forEach((id) => relationshipIds.add(id));
        path.entity_ids.forEach((id) => entityIds.add(id));
      }
    } else {
      const path = pathResult.paths[pathSelected];
      if (path === undefined) {
        return null;
      }
      path.relationship_ids.forEach((id) => relationshipIds.add(id));
      path.entity_ids.forEach((id) => entityIds.add(id));
    }
    return { relationshipIds, entityIds };
  }, [pathRequest, pathResult, pathSelected]);

  const graphModel = useMemo(() => {
    if (pathRequest !== null && pathResult !== null) {
      return buildGraphModel(pathRequest.source, pathResult);
    }
    return graphExpansion.graph === null
      ? null
      : buildGraphModelFromAccumulated(graphExpansion.graph);
  }, [pathRequest, pathResult, graphExpansion.graph]);

  // PR 31K: the action target is always the canonical Entity currently
  // rendered in the model; presentation metadata (type/value) is derived from
  // that canonical node, never from graph label text or arbitrary input. If
  // the node disappears from the model, the selection is not actionable.
  const selectedActionEntity = useMemo(() => {
    if (selectedActionEntityId === null) {
      return null;
    }
    const node =
      graphModel === null
        ? undefined
        : graphModel.nodes.find(
            (candidate) => candidate.entityId === selectedActionEntityId,
          );
    if (node === undefined) {
      return null;
    }
    return {
      entityId: node.entityId,
      entityType: node.entityType,
      entityValue: node.value,
    };
  }, [selectedActionEntityId, graphModel]);

  const sourcePathLabel =
    graphModel === null || pathEndpoints.source === null
      ? null
      : (graphModel.nodes.find(
          (node) => node.entityId === pathEndpoints.source,
        )?.label ?? null);
  const targetPathLabel =
    graphModel === null || pathEndpoints.target === null
      ? null
      : (graphModel.nodes.find(
          (node) => node.entityId === pathEndpoints.target,
        )?.label ?? null);

  const pathPanelProps: GraphPathPanelProps = {
    t: t as never,
    pathMode,
    endpoints: pathEndpoints,
    sourceLabel: sourcePathLabel,
    targetLabel: targetPathLabel,
    maxDepth: pathMaxDepth,
    maxPaths: pathMaxPaths,
    result: pathRequest !== null ? pathResult : null,
    loading: pathRequest !== null && pathQuery.isLoading,
    error: pathRequest !== null && pathQuery.error !== null,
    selected: pathSelected,
    resultEndpoints: pathRequest,
    onEnter: () => {
      setPathMode(true);
      setSelectedActionEntityId(null);
    },
    onExit: exitPathMode,
    onFind: findPaths,
    onEndpointsChanged: () => {
      setPathEndpoints({ source: null, target: null });
      setPathRequest(null);
      setPathSelected("all");
    },
    onDepthChange: (value) => {
      setPathMaxDepth(value);
      setPathRequest(null);
      setPathSelected("all");
    },
    onPathsChange: (value) => {
      setPathMaxPaths(value);
      setPathRequest(null);
      setPathSelected("all");
    },
    onSelect: setPathSelected,
    onRetry: () => pathQuery.refetch(),
  };
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

  // PR 31G: the graph filter form is a local draft that commits exactly one
  // URL transition (no direct graph/query-cache/expansion reset in the same
  // handler); the committed graph context derives from the route URL.
  const graphFilterForm = useFilterForm<GraphContext, GraphDraft>({
    committed: graphContext,
    buildDraft: graphDraftFromCommitted,
    toFilters: graphDraftToCommitted,
    validateDraft: (draft) => graphDraftError(t as never, draft),
    onApply: (next) => commit(applyGraphContext(searchParams, next)),
    onClear: () => commit(applyGraphContext(searchParams, emptyGraphContext())),
    emptyDraft: graphDraftFromCommitted(emptyGraphContext()),
    committedKey: graphContextKey(graphContext),
  });

  // PR 31J B4/B5/C2: the temporal form owns ONE browser-local draft; Apply
  // commits the validated tuple in one URL transition (always starting at
  // frame 0), Disable removes the temporal-owned parameters, and Previous/
  // Next change only the committed frame index through the same URL codec.
  // Frame navigation therefore goes through browser Back/Forward normally
  // and never keeps a second committed temporal store.
  const graphTemporalForm = useFilterForm<GraphTemporalContext, GraphTemporalDraft>({
    committed: graphTemporal,
    buildDraft: graphTemporalDraftFromCommitted,
    toFilters: graphTemporalDraftToCommitted,
    validateDraft: (draft) => graphTemporalDraftError(t as never, draft),
    onApply: (next) => commit(applyGraphTemporal(searchParams, next)),
    onClear: () => commit(applyGraphTemporal(searchParams, emptyGraphTemporalContext())),
    emptyDraft: graphTemporalDraftFromCommitted(emptyGraphTemporalContext()),
    committedKey: graphTemporalKey(graphTemporal),
  });

  const previousGraphTemporalFrame = (): void => {
    if (!graphTemporalHasPrevious(graphTemporal)) {
      return;
    }
    commit(applyGraphTemporal(searchParams, shiftGraphTemporalFrame(graphTemporal, -1)));
  };
  const nextGraphTemporalFrame = (): void => {
    if (!graphTemporalHasNext(graphTemporal)) {
      return;
    }
    commit(applyGraphTemporal(searchParams, shiftGraphTemporalFrame(graphTemporal, 1)));
  };

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
      t("timeline.table.counterpartyType"),
      t("timeline.table.counterpartyValue"),
      t("timeline.table.counterpartyId"),
      t("timeline.table.source"),
      t("timeline.table.observedAt"),
      t("timeline.table.retrievedAt"),
      t("timeline.table.evidence"),
    ];
    const rows = page.items.map((observation) => {
      const counterparty = counterpartyOfRow(filters.entityId, observation);
      return [
        observation.id,
        observation.relationship_type ?? "",
        edgeDirectionName(filters.entityId, observation),
        counterparty.semantic,
        counterparty.type ?? "",
        counterparty.value ?? "",
        counterparty.id,
        observation.source,
        observation.observed_at ?? "",
        observation.retrieved_at,
        observation.evidence_id,
      ];
    });
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

  // Stable label functions: the graph keeps its own local node state, and an
  // unstable label identity would reset dragged positions on unrelated
  // re-renders.
  const relationshipTypeLabel = useCallback(
    (type: string) => tRelationships(relationshipTypeKey(type)),
    [tRelationships],
  );
  const graphEntityTypeLabel = useCallback(
    (type: string) => t(entityTypeLabelKey(type)),
    [t],
  );

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
  const inspectorOpen = selectedId !== null && view === "evolution";
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
          <Box sx={{ mb: 1 }}>
            <GraphFilters
              t={t as never}
              draft={graphFilterForm.draft}
              hasActiveFilters={
                graphContextActive(graphContext) || graphDepthActive(graphContext)
              }
              entityTypeLabel={graphEntityTypeLabel}
              relationshipTypeLabel={relationshipTypeLabel}
              onSetDraft={graphFilterForm.setDraft}
              onApply={graphFilterForm.apply}
              onClear={graphFilterForm.clear}
            />
            {graphFilterForm.error !== null ? (
              <Typography
                variant="caption"
                role="alert"
                color="error"
                sx={{ display: "block", mb: 0.5 }}
              >
                {graphFilterForm.error}
              </Typography>
            ) : null}
            <GraphTemporalControls
              t={t as never}
              committed={graphTemporal}
              draft={graphTemporalForm.draft}
              error={graphTemporalForm.error}
              canPrevious={graphTemporalHasPrevious(graphTemporal)}
              canNext={graphTemporalHasNext(graphTemporal)}
              onSetDraft={graphTemporalForm.setDraft}
              onApply={graphTemporalForm.apply}
              onDisable={graphTemporalForm.clear}
              onPrevious={previousGraphTemporalFrame}
              onNext={nextGraphTemporalFrame}
            />
            <GraphPathModeToolbar {...pathPanelProps} />
            <GraphPathStatus {...pathPanelProps} />
            <GraphPathResultPanel {...pathPanelProps} />
          </Box>
        ) : null}
      </Box>

      {view === "evolution" && inspectorOpen ? (
        <ResourceDetailView
          backLabel={tCommon("backToList", { resource: t("title") })}
          heading={t("detail.title")}
          onBack={closeSelection}
        >
          {selectedObservation !== null ? (
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
          )}
        </ResourceDetailView>
      ) : (
        <>
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
                  viewAsTimeline: t("timeline.table.viewAsTimeline"),
                  tableLabel: t("timeline.table.heading"),
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
                entityTypeLabel={graphEntityTypeLabel}
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
            {graphResult.isLoading && graphResult.neighborhood === null ? (
            <Alert severity="info" role="status" sx={{ mt: 1 }}>
              {t("graph.loading")}
            </Alert>
          ) : null}
          {graphResult.error !== null && graphResult.neighborhood === null ? (
            <Box sx={{ mt: 1 }}>
              <Alert severity="error" role="alert">
                {t("graph.error.message")}
              </Alert>
              <Box sx={{ display: "flex", gap: 1, mt: 1 }}>
                <Button
                  size="small"
                  variant="outlined"
                  onClick={() => graphResult.refetch()}
                >
                  {t("error.retry")}
                </Button>
              </Box>
            </Box>
          ) : null}
            {graphModel !== null ? (
              <RelationshipGraph
                investigationId={investigationId}
                rootGraphKey={`${investigationId}:${filters.entityId}:${filters.direction}:${graphContextKey(effectiveGraphContext)}:${graphTemporalKey(graphTemporal)}`}
                focalEntityId={pathRequest !== null ? pathRequest.source : filters.entityId}
                model={graphModel}
                multiHop={graphContext.depth > 1}
                typeLabel={relationshipTypeLabel}
                entityTypeLabel={graphEntityTypeLabel}
                expansion={graphExpansion}
                pathMode={pathMode}
                pathEndpoints={pathMode ? pathEndpoints : null}
                onPathEndpointClick={pathMode ? choosePathEndpoint : undefined}
                onActionSelect={pathMode ? undefined : selectActionEntity}
                pathHighlight={
                  pathRequest !== null && pathResult !== null
                    ? pathHighlight
                    : null
                }
                emptyMessage={
                  graphTemporalActive(graphTemporal) && graphModel.edges.length === 0
                    ? t("graph.temporal.empty")
                    : undefined
                }
              />
            ) : null}
            {selectedActionEntity !== null && !pathMode ? (
              <GraphActionPanel
                key={selectedActionEntity.entityId}
                selection={selectedActionEntity}
                entityTypeLabel={graphEntityTypeLabel}
                onCancel={clearActionEntity}
              />
            ) : null}
          </Box>
        )}
        </>
      )}
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

/**
 * One row's focal-relative counterparty: semantic type/value when the
 * bounded projection supplied them, plus the canonical identity.
 *
 * ``semantic`` is the analyst-facing text (type + value, value, or the
 * compact technical identity fallback); ``type``/``value`` carry the raw
 * endpoint presentation fields for spreadsheets and ``id`` is the canonical
 * counterparty UUID so no identity is lost in the export.
 */
function counterpartyOfRow(
  focalEntityId: string,
  observation: RelationshipObservation,
): { id: string; type: string | null; value: string | null; semantic: string } {
  const id = counterpartyIdOf(focalEntityId, observation);
  const source = observation.relationship_source_entity_id ?? null;
  const sourceIsCounterparty = source !== null && source !== focalEntityId;
  const type = sourceIsCounterparty
    ? (observation.relationship_source_entity_type ?? null)
    : (observation.relationship_target_entity_type ?? null);
  const value = sourceIsCounterparty
    ? (observation.relationship_source_entity_value ?? null)
    : (observation.relationship_target_entity_value ?? null);
  if (type !== null && value !== null && value.trim() !== "") {
    return { id, type, value, semantic: `${type} ${value}` };
  }
  if (type !== null) {
    return { id, type, value, semantic: type };
  }
  if (value !== null && value.trim() !== "") {
    return { id, type, value, semantic: value };
  }
  return { id, type, value, semantic: id };
}
