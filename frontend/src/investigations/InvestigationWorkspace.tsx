// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Investigation workspace (PR 24B §14, §15, §17, §18; PR 24C §12;
// PR 31F-6 amendment 5; PR 31F-8 §9).
//
// The workspace route owns the authoritative Investigation detail query
// (with bounded polling), the persistent header, the Investigation
// navigation, and ONE routed content surface through the child
// ``<Outlet>`` (PR 31F-8): every resource is mounted as an explicit
// routed page, never through the retired generic PivotWorkspace host.
// Legacy ``?pivot=`` URLs are handled deterministically (see
// ``LegacyPivotRedirect``): a representable stack redirects once to its
// canonical route; malformed/ignored state is removed without breaking
// the current route. No durable ``pivotOpen`` state exists anywhere.

import { Box, Button, Link } from "@mui/material";
import type { ReactElement } from "react";
import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Navigate,
  Outlet,
  Link as RouterLink,
  useLocation,
  useParams,
  useSearchParams,
} from "react-router";

import type { ApiError } from "../api/errors";
import type { Investigation } from "../api/schema-types";
import { LoadingState } from "../components/AsyncState";
import { EmptyState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import { useInvestigationDetail } from "./investigation-queries";
import { InvestigationHeader } from "./InvestigationHeader";
import { InvestigationTabs } from "./InvestigationTabs";
import { PIVOT_PARAM, readPivotState } from "../pivots/pivot-url";
import { pivotTargetToRoute } from "../pivots/pivot-route";
import type { PivotStep } from "../pivots/pivot-types";

/** Detail state shared with workspace child routes via the outlet. */
export interface WorkspaceOutletContext {
  investigation: Investigation | null;
  detailIsLoading: boolean;
  detailError: ApiError | null;
  refetchDetail: () => void;
}

/** Whether one error is the scoped 404 contract (no enumeration). */
export function isInvestigationNotFound(error: ApiError): boolean {
  return error.kind === "api" && error.status === 404;
}

/**
 * Secondary workspace navigation (PR 24C §12; PR 31F-7).
 *
 * History is not a primary tab. PR 31F-7 replaces the former fixed-Portal
 * MUI Menu with this conservative in-flow disclosure: ordinary DOM layout
 * only — no Portal, no MUI Menu/Popover/Modal, no backdrop, focus trap,
 * body lock or document-global dismissal listener. The disclosure owns only
 * transient local open state (never URL/global/server state); the sole
 * destination is the History route, preserved verbatim as a semantic link,
 * with an explicit Close affordance. Keyboard behavior is native: Tab
 * reaches the trigger and the region entries, Enter/Space toggles the
 * trigger, and Tab can always leave the region (no trap). The navigation
 * path itself is unchanged from the replaced menu (react-router Link).
 */
function MoreNavigation({ investigationId }: { investigationId: string }): ReactElement {
  const { t } = useTranslation("investigations");
  const [moreOpen, setMoreOpen] = useState(false);
  const close = (): void => setMoreOpen(false);
  return (
    <Box component="span" sx={{ display: "inline-block" }}>
      <Button
        size="small"
        variant="text"
        onClick={() => setMoreOpen((open) => !open)}
        aria-expanded={moreOpen}
        aria-controls={moreOpen ? "investigation-more-region" : undefined}
        sx={{ textTransform: "none", mr: 1 }}
      >
        {t("more.label")}
      </Button>
      {moreOpen ? (
        <Box
          component="nav"
          id="investigation-more-region"
          aria-label={t("more.navigationLabel")}
          sx={{
            display: "inline-flex",
            alignItems: "center",
            gap: 0.5,
            px: 1,
            py: 0.25,
            border: 1,
            borderColor: "divider",
            borderRadius: 1,
            bgcolor: "background.paper",
          }}
        >
          <Link
            component={RouterLink}
            to={`/investigations/${investigationId}/history`}
            onClick={close}
            sx={{ fontSize: "0.8125rem", fontWeight: 600 }}
          >
            {t("more.history")}
          </Link>
          <Button
            size="small"
            onClick={close}
            sx={{ textTransform: "none", minWidth: 0, ml: 0.5 }}
          >
            {t("more.close")}
          </Button>
        </Box>
      ) : null}
    </Box>
  );
}

/**
 * The deterministic legacy ``?pivot=`` destination (PR 31F-8 §4.1, N03/N04).
 *
 * Returns null when no pivot parameter is present. A valid legacy pivot
 * stack maps to the canonical route of its active step through the same
 * exhaustive mapper used by live navigation; malformed/unrepresentable
 * state maps to the current canonical route with the pivot parameter
 * removed. The result is a one-time replace destination — no second
 * navigation architecture survives and no pivot state is retained.
 */
export function legacyPivotDestination(
  investigationId: string,
  searchParams: URLSearchParams,
  pathname: string,
): string | null {
  if (searchParams.getAll(PIVOT_PARAM).length === 0) {
    return null;
  }
  const state = readPivotState(searchParams);
  if (state !== null && state.steps.length > 0) {
    const last = state.steps[state.steps.length - 1];
    const route = pivotTargetToRoute(investigationId, stepAsTarget(last));
    if (route !== null) {
      return route.search === undefined
        ? route.pathname
        : `${route.pathname}?${route.search}`;
    }
  }
  const next = new URLSearchParams(searchParams);
  next.delete(PIVOT_PARAM);
  const cleaned = next.toString();
  return cleaned === "" ? pathname : `${pathname}?${cleaned}`;
}

/**
 * Legacy ``?pivot=`` URL handling inside the mounted workspace (PR 31F-8).
 *
 * Non-index Investigation routes (e.g. ``/evidence?pivot=…``) apply the
 * same one-time deterministic policy via a declarative Navigate so no
 * sibling navigation can race it; the index route redirects through the
 * shared destination helper (see routes.tsx).
 */
function LegacyPivotRedirect({
  investigationId,
}: {
  investigationId: string;
}): ReactElement | null {
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const destination = legacyPivotDestination(
    investigationId,
    searchParams,
    location.pathname,
  );
  if (destination === null) {
    return null;
  }
  return <Navigate to={destination} replace />;
}

/** The index redirect: Overview unless a legacy pivot URL redirects first. */
export function WorkspaceIndexRedirect(): ReactElement | null {
  const { investigationId = "" } = useParams();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const destination = legacyPivotDestination(
    investigationId,
    searchParams,
    location.pathname,
  );
  if (destination !== null) {
    return <Navigate to={destination} replace />;
  }
  return <Navigate to="overview" replace />;
}

/** One pivot step as its canonical capability target (labels stay bounded). */
function stepAsTarget(step: PivotStep): {
  resource: PivotStep["resource"];
  filters: PivotStep["filters"];
  selectedId: PivotStep["selectedId"];
  label: string;
} {
  return {
    resource: step.resource,
    filters: step.filters,
    selectedId: step.selectedId,
    label: step.label,
  };
}

/** The Investigation workspace. */
export function InvestigationWorkspace(): ReactElement {
  const { t } = useTranslation("investigations");
  const { investigationId = "" } = useParams();
  const { investigation, isLoading, isError, error, refetch } =
    useInvestigationDetail(investigationId);

  const outletContext = useMemo<WorkspaceOutletContext>(
    () => ({
      investigation,
      detailIsLoading: isLoading,
      detailError: error,
      refetchDetail: refetch,
    }),
    [investigation, isLoading, error, refetch],
  );

  // Initial load (no previous data yet).
  if (isLoading && investigation === null) {
    return <LoadingState label={t("detail.loading")} />;
  }

  // Detail failure without previous data: scoped 404 or bounded error.
  if (isError && investigation === null) {
    if (error !== null && isInvestigationNotFound(error)) {
      return (
        <EmptyState
          title={t("detail.notFound.title")}
          message={t("detail.notFound.message")}
        />
      );
    }
    return (
      <ErrorNotice
        title={t("detail.loadError.title")}
        onRetry={refetch}
      />
    );
  }

  return (
    <Box sx={{ mx: "auto", maxWidth: 1024, py: 2 }}>
      <LegacyPivotRedirect investigationId={investigationId} />
      {isError ? (
        <Box sx={{ mb: 1 }}>
          <ErrorNotice
            severity="warning"
            title={t("poll.error.title")}
            message={t("poll.error.message")}
            onRetry={refetch}
          />
        </Box>
      ) : null}
      <InvestigationHeader investigation={investigation} />
      <Box sx={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 0.5 }}>
        <InvestigationTabs investigationId={investigationId} />
        <MoreNavigation investigationId={investigationId} />
      </Box>
      <Box component="section" sx={{ mt: 2 }}>
        <Outlet context={outletContext} />
      </Box>
    </Box>
  );
}
