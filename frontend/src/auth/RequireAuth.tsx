// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Authenticated route guard (PR 24A).
//
// `/auth/me` is the authentication authority. Protected content never
// renders before auth state resolves, 401 means "sign in", and auth
// service failures render a bounded error surface instead of silently
// treating the user as logged out.

import { Box } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, Outlet, useLocation } from "react-router";

import { LoadingState } from "../components/AsyncState";
import { ErrorNotice } from "../components/ErrorNotice";
import { isUnauthenticated, type ApiError } from "../api/errors";
import { useMeQuery } from "./auth-queries";

/** Full-page session-check surface shown before auth state resolves. */
function SessionChecking(): ReactElement {
  const { t } = useTranslation("shell");
  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
      role="main"
    >
      <LoadingState label={t("loading.session")} />
    </Box>
  );
}

/** Bounded recoverable surface when auth state cannot be verified. */
function SessionError({ error, onRetry }: { error: ApiError; onRetry: () => void }): ReactElement {
  const { t } = useTranslation("common");
  const message = error.kind === "api" ? error.message : null;
  const supportText =
    error.requestId !== null ? t("supportReference", { requestId: error.requestId }) : null;
  return (
    <Box sx={{ py: 6, mx: "auto", maxWidth: 640 }}>
      <ErrorNotice
        title={t("session.title")}
        message={message}
        supportText={supportText}
        onRetry={onRetry}
        retryLabel={t("retry")}
      />
    </Box>
  );
}

/** Route-guard layout: emits the protected children only when authenticated. */
export function RequireAuth(): ReactElement {
  const me = useMeQuery();
  const location = useLocation();

  if (me.state === "loading") {
    return <SessionChecking />;
  }
  if (me.state === "authenticated") {
    return <Outlet />;
  }
  if (me.error !== null && !isUnauthenticated(me.error)) {
    return <SessionError error={me.error} onRetry={me.refetch} />;
  }
  // Unauthenticated: hand off to /login with a safe internal return path.
  return (
    <Navigate
      to="/login"
      replace
      state={{ returnTo: `${location.pathname}${location.search}` }}
    />
  );
}