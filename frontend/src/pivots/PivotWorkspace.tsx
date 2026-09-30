// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// In-flow Pivot workbench (PR 24D §1.4, §1.5, §9, §13, §16, §20;
// PR 31F-6 amendment 5).
//
// When the URL-backed pivot stack is non-empty, this workbench is the
// investigation's PRIMARY content: breadcrumbs + Close + the active step's
// resource list OR resource detail, all ordinary in-flow document
// content. The route owner (InvestigationWorkspace) renders the normal
// Investigation workbench OR this workbench — never both.
//
// Nested pivots replace the active content in the same workbench — they
// never stack surfaces. Only the active step is mounted; earlier steps
// are serialized state. Browser Back/Forward, refresh, breadcrumb
// truncation and Close all operate through React Router search-param
// navigation: the bounded ``pivot`` URL state is the only authority and no
// durable ``pivotOpen``/``showPivotWorkspace`` state exists.
//
// There is no Portal, fixed viewport positioning, backdrop, modal/dialog
// semantics, ``aria-modal``, focus trap, body scroll lock, body-child
// ``aria-hidden``, document pointer/click-away filtering, anchor geometry
// or z-index competition with the underlying Investigation content (the
// normal workbench is unmounted while this one is active). The proven
// next-macrotask deferred navigation boundaries are preserved; there is no
// modal-only Escape handler (Escape existed solely to dismiss the removed
// overlay).

import { Alert, Box, IconButton, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";

import type { ResourceFilterCodec } from "../analyst-table/resource-page";
import { useResourceTable } from "../analyst-table/resource-page";
import { DetailError, DetailLoading } from "../analyst-table/ResourceDetailView";
import { EmptyState } from "../components/AsyncState";
import type { Investigation } from "../api/schema-types";
import { EvidenceWorkspace } from "../evidence/EvidenceWorkspace";
import {
  emptyEvidenceFilters,
  evidenceFiltersToParams,
  parseEvidenceFilters,
  type EvidenceFilters,
} from "../evidence/evidence-filters";
import { EntityGeointView } from "../geoint/EntityGeointView";
import {
  emptyGeointEntityFilters,
  emptyGeointLocationFilters,
  geointEntityFiltersToParams,
  geointLocationFiltersToParams,
  parseGeointEntityFilters,
  parseGeointLocationFilters,
  type GeointEntityFilters,
  type GeointLocationFilters,
} from "../geoint/geoint-filters";
import { LocationEntitiesView, LocationObservationsView } from "../geoint/LocationViews";
import { GeointObservationDetailBody } from "../geoint/GeointObservationDetail";
import { useGeointObservation } from "../geoint/geoint-queries";
import {
  emptyObservationFilters,
  observationFiltersToParams,
  parseObservationFilters,
  type ObservationFilters,
} from "../relationships/relationships-filters";
import { RelationshipObservationsWorkspace } from "../relationships/RelationshipObservationsWorkspace";
import {
  emptyRelationshipFilters,
  parseRelationshipFilters,
  relationshipFiltersToParams,
  type RelationshipFilters,
} from "../relationships/relationships-filters";
import { RelationshipsWorkspace } from "../relationships/RelationshipsWorkspace";
import { ResearchWorkspace } from "../research/ResearchWorkspace";
import {
  emptyResearchFilters,
  parseResearchFilters,
  researchFiltersToParams,
  type ResearchFilters,
} from "../research/research-filters";
import { createPivotStatePort } from "./pivot-port";
import {
  MAX_PIVOT_STEPS,
  type PivotStep,
} from "./pivot-types";
import {
  clearPivotState,
  readPivotState,
  truncatePivotSteps,
  withPivotState,
} from "./pivot-url";
import { PivotBreadcrumbs, pivotResourceLabelKey } from "./PivotBreadcrumbs";

/** Close glyph without a second icon dependency (PR 24C convention). */
function CloseGlyph(): ReactElement {
  return <span aria-hidden="true">✕</span>;
}

export interface PivotWorkspaceProps {
  investigationId: string;
  investigation: Investigation | null;
}

/**
 * The in-flow Pivot workbench. Renders nothing when no valid pivot
 * state is present; malformed state never breaks the base route (the
 * parameter is simply ignored, matching PR 24D §20).
 */
export function PivotWorkspace({
  investigationId,
  investigation,
}: PivotWorkspaceProps): ReactElement | null {
  const { t } = useTranslation("pivots");
  const [searchParams, setSearchParams] = useSearchParams();
  const titleId = useId();
  const state = readPivotState(searchParams);
  if (state === null) {
    return null;
  }
  const active = state.steps[state.steps.length - 1];

  const close = (): void => {
    // PR 31F-6: the workbench close navigation runs AFTER the native
    // pointer event completes (next macrotask) — see resource-page commit().
    window.setTimeout(() => {
      setSearchParams(clearPivotState(searchParams), { replace: false });
    }, 0);
  };
  const truncate = (keep: number): void => {
    window.setTimeout(() => {
      setSearchParams(truncatePivotSteps(searchParams, keep), { replace: false });
    }, 0);
  };
  const commit = (next: PivotStep, replace: boolean): void => {
    const steps = [...state.steps];
    steps[steps.length - 1] = next;
    // PR 31F-6: the in-workbench step commit also runs after the native
    // pointer event completes.
    window.setTimeout(() => {
      setSearchParams(withPivotState(searchParams, { steps }), { replace });
    }, 0);
  };

  return (
    <Box
      component="section"
      aria-labelledby={titleId}
      data-ati-pivot="1"
      data-testid="pivot-workbench"
      sx={{ minWidth: 0, mt: 2 }}
    >
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
        <Typography id={titleId} variant="h2">
          {t("modal.title", { resource: t(pivotResourceLabelKey(active.resource)) })}
        </Typography>
        <IconButton
          onClick={close}
          aria-label={t("modal.close")}
          size="small"
        >
          <CloseGlyph />
        </IconButton>
      </Box>
      <Box sx={{ mb: 1 }}>
        <PivotBreadcrumbs steps={state.steps} onNavigate={truncate} />
        {state.steps.length >= MAX_PIVOT_STEPS ? (
          <Alert severity="info" role="status" sx={{ mt: 1 }}>
            {t("depthLimit.message")}
          </Alert>
        ) : null}
      </Box>
      <PivotStepHost
        key={active.resource}
        step={active}
        onCommitStep={commit}
        investigationId={investigationId}
        investigation={investigation}
      />
    </Box>
  );
}

/** Mount only the active step's resource workspace (PR 24D §9, §30). */
function PivotStepHost({
  step,
  onCommitStep,
  investigationId,
  investigation,
}: {
  step: PivotStep;
  onCommitStep: (next: PivotStep, replace: boolean) => void;
  investigationId: string;
  investigation: Investigation | null;
}): ReactElement {
  switch (step.resource) {
    case "evidence":
      return (
        <EvidencePivotStep
          step={step}
          onCommitStep={onCommitStep}
          investigationId={investigationId}
          investigation={investigation}
        />
      );
    case "relationships":
      return (
        <RelationshipsPivotStep
          step={step}
          onCommitStep={onCommitStep}
          investigationId={investigationId}
          investigation={investigation}
        />
      );
    case "relationship-observations":
      return (
        <ObservationsPivotStep
          step={step}
          onCommitStep={onCommitStep}
          investigationId={investigationId}
          investigation={investigation}
        />
      );
    case "geoint-entity":
      return (
        <GeointEntityPivotStep
          step={step}
          onCommitStep={onCommitStep}
          investigationId={investigationId}
        />
      );
    case "geoint-location-entities":
      return (
        <GeointLocationPivotStep
          step={step}
          onCommitStep={onCommitStep}
          investigationId={investigationId}
          view="entities"
        />
      );
    case "geoint-location-observations":
      return (
        <GeointLocationPivotStep
          step={step}
          onCommitStep={onCommitStep}
          investigationId={investigationId}
          view="observations"
        />
      );
    case "geoint-observation":
      return (
        <GeointObservationPivotStep
          step={step}
          investigationId={investigationId}
        />
      );
    case "research":
      return (
        <ResearchPivotStep
          step={step}
          onCommitStep={onCommitStep}
          investigationId={investigationId}
          investigation={investigation}
        />
      );
  }
}

/** Evidence step adapter: one table, one detail stack over the step port. */
function EvidencePivotStep({
  step,
  onCommitStep,
  investigationId,
  investigation,
}: {
  step: PivotStep;
  onCommitStep: (next: PivotStep, replace: boolean) => void;
  investigationId: string;
  investigation: Investigation | null;
}): ReactElement {
  const codec: ResourceFilterCodec<EvidenceFilters> = {
    parse: parseEvidenceFilters,
    toParams: evidenceFiltersToParams,
    empty: emptyEvidenceFilters,
  };
  const table = useResourceTable(
    codec,
    createPivotStatePort(step, codec, onCommitStep),
  );
  return (
    <EvidenceWorkspace
      investigationId={investigationId}
      investigation={investigation}
      table={table}
      embedded
    />
  );
}

/** Relationships step adapter over the pivot step port. */
function RelationshipsPivotStep({
  step,
  onCommitStep,
  investigationId,
  investigation,
}: {
  step: PivotStep;
  onCommitStep: (next: PivotStep, replace: boolean) => void;
  investigationId: string;
  investigation: Investigation | null;
}): ReactElement {
  const codec: ResourceFilterCodec<RelationshipFilters> = {
    parse: parseRelationshipFilters,
    toParams: relationshipFiltersToParams,
    empty: emptyRelationshipFilters,
  };
  const table = useResourceTable(
    codec,
    createPivotStatePort(step, codec, onCommitStep),
  );
  return (
    <RelationshipsWorkspace
      investigationId={investigationId}
      investigation={investigation}
      table={table}
      embedded
    />
  );
}

/** RelationshipObservations step adapter over the pivot step port. */
function ObservationsPivotStep({
  step,
  onCommitStep,
  investigationId,
  investigation,
}: {
  step: PivotStep;
  onCommitStep: (next: PivotStep, replace: boolean) => void;
  investigationId: string;
  investigation: Investigation | null;
}): ReactElement {
  const codec: ResourceFilterCodec<ObservationFilters> = {
    parse: parseObservationFilters,
    toParams: observationFiltersToParams,
    empty: emptyObservationFilters,
  };
  const table = useResourceTable(
    codec,
    createPivotStatePort(step, codec, onCommitStep),
  );
  return (
    <RelationshipObservationsWorkspace
      investigationId={investigationId}
      investigation={investigation}
      table={table}
      embedded
    />
  );
}

/** Research step adapter over the pivot step port. */
function ResearchPivotStep({
  step,
  onCommitStep,
  investigationId,
  investigation,
}: {
  step: PivotStep;
  onCommitStep: (next: PivotStep, replace: boolean) => void;
  investigationId: string;
  investigation: Investigation | null;
}): ReactElement {
  const codec: ResourceFilterCodec<ResearchFilters> = {
    parse: parseResearchFilters,
    toParams: researchFiltersToParams,
    empty: emptyResearchFilters,
  };
  const table = useResourceTable(
    codec,
    createPivotStatePort(step, codec, onCommitStep),
  );
  return (
    <ResearchWorkspace
      investigationId={investigationId}
      investigation={investigation}
      table={table}
      embedded
    />
  );
}

/** GEOINT Entity step adapter over the pivot step port (current + history). */
function GeointEntityPivotStep({
  step,
  onCommitStep,
  investigationId,
}: {
  step: PivotStep;
  onCommitStep: (next: PivotStep, replace: boolean) => void;
  investigationId: string;
}): ReactElement {
  const codec: ResourceFilterCodec<GeointEntityFilters> = {
    parse: parseGeointEntityFilters,
    toParams: geointEntityFiltersToParams,
    empty: emptyGeointEntityFilters,
  };
  const table = useResourceTable(
    codec,
    createPivotStatePort(step, codec, onCommitStep),
  );
  return (
    <EntityGeointView
      investigationId={investigationId}
      table={table}
    />
  );
}

/** GEOINT Location step adapter (Entities or observations surface). */
function GeointLocationPivotStep({
  step,
  onCommitStep,
  investigationId,
  view,
}: {
  step: PivotStep;
  onCommitStep: (next: PivotStep, replace: boolean) => void;
  investigationId: string;
  view: "entities" | "observations";
}): ReactElement {
  const codec: ResourceFilterCodec<GeointLocationFilters> = {
    parse: parseGeointLocationFilters,
    toParams: geointLocationFiltersToParams,
    empty: emptyGeointLocationFilters,
  };
  const table = useResourceTable(
    codec,
    createPivotStatePort(step, codec, onCommitStep),
  );
  return view === "entities" ? (
    <LocationEntitiesView investigationId={investigationId} table={table} />
  ) : (
    <LocationObservationsView investigationId={investigationId} table={table} />
  );
}

/** GEOINT exact observation detail step (no list/pagination surface). */
function GeointObservationPivotStep({
  step,
  investigationId,
}: {
  step: PivotStep;
  investigationId: string;
}): ReactElement {
  const observationId =
    step.resource === "geoint-observation"
      ? (step.filters.observation_id ?? null)
      : null;
  return <ObservationPivotBody investigationId={investigationId} observationId={observationId} />;
}

/** The observation detail body with its bounded states. */
function ObservationPivotBody({
  investigationId,
  observationId,
}: {
  investigationId: string;
  observationId: string | null;
}): ReactElement {
  const { t } = useTranslation("geoint");
  const { detail, isLoading, isError, error, refetch } = useGeointObservation(
    investigationId,
    observationId,
  );
  if (observationId === null) {
    return <EmptyState title={t("detail.observation.missing.title")} />;
  }
  if (isLoading && detail === null) {
    return <DetailLoading label={t("detail.observation.loading")} />;
  }
  if (isError && detail === null && error !== null) {
    if (error.kind === "api" && error.status === 404) {
      return <Alert severity="info" role="status">{t("detail.observation.notFound.title")}</Alert>;
    }
    return <DetailError title={t("detail.observation.loadError.title")} onRetry={refetch} />;
  }
  if (detail === null) {
    return <DetailLoading label={t("detail.observation.loading")} />;
  }
  return <GeointObservationDetailBody detail={detail} />;
}
