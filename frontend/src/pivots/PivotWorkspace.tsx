// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// One modal pivot workspace (PR 24D §1.4, §1.5, §9, §13, §16, §20).
//
// The active pivot step renders inside one large modal workspace. Nested
// pivots replace the active content in the same workspace — they never
// stack dialogs — and PR 24C detail drawers open inside this one modal.
// Only the active step is mounted; earlier steps are serialized state.
// Browser Back/Forward, refresh, breadcrumb truncation, and Close all
// operate through React Router search-param navigation: the URL is the
// only owned state. Target/network errors surface inside the embedded
// workspace while the breadcrumb/modal context stays intact.
//
// The modal is implemented with Material UI primitives (fixed-position
// paper + backdrop) rather than the MUI Dialog/Modal chain. In this
// material-ui 7 release the Modal focus trap, when the custom detail
// drawer mounts inside it, races the drawer's unmount on an in-drawer
// pivot click (a focused node dies under an active trap) and permanently
// spins/crashes the Chromium main thread — reproduced on the real stack
// (PR 24D E2E). The component contract (accessible dialog semantics,
// backdrop close, Escape close, aria labels, body scroll lock) is
// identical; jsdom and browser behavior agree.

import { Alert, Box, IconButton, Portal, Typography } from "@mui/material";
import { useMediaQuery } from "@mui/material";
import type { ReactElement } from "react";
import { useEffect, useId, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";

import type { ResourceFilterCodec } from "../analyst-table/resource-page";
import { useResourceTable } from "../analyst-table/resource-page";
import type { Investigation } from "../api/schema-types";
import { EvidenceWorkspace } from "../evidence/EvidenceWorkspace";
import {
  emptyEvidenceFilters,
  evidenceFiltersToParams,
  parseEvidenceFilters,
  type EvidenceFilters,
} from "../evidence/evidence-filters";
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
 * The single pivot workspace modal. Renders nothing when no valid pivot
 * state is present; malformed state never breaks the base route (the
 * parameter is simply ignored, matching PR 24D §20).
 */
export function PivotWorkspace({
  investigationId,
  investigation,
}: PivotWorkspaceProps): ReactElement | null {
  const { t } = useTranslation("pivots");
  const [searchParams, setSearchParams] = useSearchParams();
  // Hooks stay unconditional; the state check happens after all hooks.
  const fullScreen = useMediaQuery("(max-width: 899px)");
  const titleId = useId();
  const rootRef = useRef<HTMLElement | null>(null);
  // Modal hygiene while open: scroll-lock the body and aria-hide the
  // underlying page from assistive tech (MUI ModalManager equivalent),
  // restoring both on unmount.
  const state = readPivotState(searchParams);
  const open = state !== null;
  // Modal hygiene while open: scroll-lock the body and aria-hide the
  // underlying page from assistive tech (MUI ModalManager equivalent),
  // restoring both on close. The portal root identifies itself with a
  // data attribute because the ref is not resolved before the effect.
  useEffect(() => {
    if (!open) {
      return;
    }
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const hidden: Array<Element> = [];
    [].forEach.call(document.body.children, (child: Element) => {
      if (
        child.getAttribute("data-ati-pivot") === "1" ||
        child.getAttribute("aria-hidden") === "true"
      ) {
        return;
      }
      child.setAttribute("aria-hidden", "true");
      hidden.push(child);
    });
    return () => {
      document.body.style.overflow = previousOverflow;
      hidden.forEach((element) => element.removeAttribute("aria-hidden"));
    };
  }, [open]);
  if (state === null) {
    return null;
  }
  const active = state.steps[state.steps.length - 1];

  const close = (): void => {
    setSearchParams(clearPivotState(searchParams), { replace: false });
  };
  const truncate = (keep: number): void => {
    setSearchParams(truncatePivotSteps(searchParams, keep), { replace: false });
  };
  const commit = (next: PivotStep, replace: boolean): void => {
    const steps = [...state.steps];
    steps[steps.length - 1] = next;
    setSearchParams(withPivotState(searchParams, { steps }), { replace });
  };

  const handleKeyDown = (event: { key: string }): void => {
    if (event.key === "Escape") {
      close();
    }
  };
  return (
    <Portal>
      <Box ref={(node) => { rootRef.current = node as HTMLElement | null; }} data-ati-pivot="1" sx={{ minHeight: 0 }}>
        <Box
          aria-hidden="true"
          tabIndex={-1}
          onClick={close}
          sx={{
            position: "fixed",
            inset: 0,
            bgcolor: "rgba(0, 0, 0, 0.32)",
            zIndex: 1249,
          }}
        />
        <Box
          role="dialog"
          aria-modal="true"
          aria-labelledby={titleId}
          onKeyDown={handleKeyDown}
          sx={(theme) => ({
            position: "fixed",
            ...(fullScreen
              ? { inset: 0 }
              : { top: 24, right: 24, bottom: 24, left: 24 }),
            maxWidth: fullScreen ? "none" : "calc(100% - 48px)",
            zIndex: 1250,
            bgcolor: "background.paper",
            border: 1,
            borderColor: theme.palette.divider,
            boxShadow: "0px 4px 16px rgba(0, 0, 0, 0.24)",
            overflowY: "auto",
          })}
        >
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", p: 1.25 }}>
            <Typography id={titleId} variant="h2">
              {t("modal.title", { resource: t(pivotResourceLabelKey(active.resource)) })}
            </Typography>
            <IconButton
              onClick={close}
              autoFocus
              aria-label={t("modal.close")}
              size="small"
            >
              <CloseGlyph />
            </IconButton>
          </Box>
          <Box sx={{ p: 1.25 }}>
            <PivotBreadcrumbs steps={state.steps} onNavigate={truncate} />
            {state.steps.length >= MAX_PIVOT_STEPS ? (
              <Alert severity="info" role="status" sx={{ mb: 1 }}>
                {t("depthLimit.message")}
              </Alert>
            ) : null}
            <PivotStepHost
              key={active.resource}
              step={active}
              onCommitStep={commit}
              investigationId={investigationId}
              investigation={investigation}
            />
          </Box>
        </Box>
      </Box>
    </Portal>
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