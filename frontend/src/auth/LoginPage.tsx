// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Minimal professional Material UI login page (PR 24A).
//
// Username + password only (no remember-me, no password reset: no backend
// contract exists). Invalid credentials stay generic; rate limiting is
// distinguishable; the bounded request ID stays available for support.
// The password is never logged and never stored.

import { Alert, Box, Button, Card, CardContent, CircularProgress, TextField, Typography } from "@mui/material";
import type { FormEvent } from "react";
import { useState, type ReactElement } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useLocation, useNavigate } from "react-router";

import { CSRF_MISSING_CODE, type ApiError } from "../api/errors";
import { useLoginMutation, useMeQuery } from "./auth-queries";

/** Safe internal post-login destination; rejects external/protocol URLs. */
export function normalizeReturnTo(candidate: unknown): string {
  if (typeof candidate !== "string") {
    return "/investigations";
  }
  const trimmed = candidate.trim();
  if (!trimmed.startsWith("/") || trimmed.startsWith("//")) {
    return "/investigations";
  }
  // Bounded to a single internal path; control and backslash characters
  // are never accepted as navigation targets.
  if (/[\u0000-\u001f\u007f\\]/.test(trimmed)) {
    return "/investigations";
  }
  return trimmed;
}

interface LoginFailure {
  message: string;
  supportRequestId: string | null;
}

/** Map typed API failures to generic, bounded user-facing text. */
function describeLoginError(error: ApiError): LoginFailure {
  switch (error.kind) {
    case "api":
      if (error.status === 429 || error.code === "rate_limited") {
        return { message: "rateLimited", supportRequestId: null };
      }
      if (error.status === 401) {
        return { message: "invalidCredentials", supportRequestId: null };
      }
      if (error.status >= 500) {
        return { message: "serviceUnavailable", supportRequestId: null };
      }
      return { message: "unexpected", supportRequestId: error.requestId };
    case "transport":
      return { message: "serviceUnavailable", supportRequestId: null };
    case "csrf":
      return {
        message: error.code === CSRF_MISSING_CODE ? "csrf" : "unexpected",
        supportRequestId: null,
      };
    case "unexpected-response":
    default:
      return { message: "unexpected", supportRequestId: null };
  }
}

/**
 * The `/login` route: redirects authenticated analysts to
 * `/investigations`, otherwise renders the sign-in form.
 */
export function LoginRoute(): ReactElement {
  const me = useMeQuery();
  if (me.state === "authenticated") {
    return <Navigate to="/investigations" replace />;
  }
  return <LoginPage />;
}

/** The sign-in form. */
export function LoginPage(): ReactElement {
  const { t } = useTranslation("auth");
  const { t: tc } = useTranslation("common");
  const location = useLocation();
  const navigate = useNavigate();
  const returnTo = normalizeReturnTo(location.state?.returnTo);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  const { run, isPending, error } = useLoginMutation((_user) => {
    navigate(returnTo);
  });

  const failure = error !== null ? describeLoginError(error) : null;
  const supportRequestId = failure?.supportRequestId ?? null;

  function handleSubmit(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const normalizedUsername = username.trim();
    if (isPending || normalizedUsername.length === 0 || password.length === 0) {
      return;
    }
    run({ username: normalizedUsername, password });
    setPassword("");
  }

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        bgcolor: "background.default",
        px: 1,
        py: 4,
      }}
    >
      <Card raised variant="outlined" sx={{ width: 420, maxWidth: "100%" }}>
        <CardContent sx={{ p: 2.5 }}>
          <Typography variant="h3" component="h1" sx={{ mb: 0.25 }}>
            {t("title")}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {t("subtitle")}
          </Typography>

          <Box component="form" onSubmit={handleSubmit} sx={{ mt: 2 }}>
            <TextField
              id="username"
              label={t("username")}
              name="username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              slotProps={{ input: { autoComplete: "username" } }}
              fullWidth
              autoFocus
              sx={{ mb: 1.5 }}
              required
            />
            <TextField
              id="password"
              label={t("password")}
              name="password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              slotProps={{ input: { autoComplete: "current-password" } }}
              fullWidth
              sx={{ mb: 1.5 }}
              required
            />
            <Button
              type="submit"
              variant="contained"
              size="large"
              disabled={isPending}
              fullWidth
              sx={{ textTransform: "none", mt: 0.5 }}
            >
              {isPending ? <CircularProgress size={20} aria-label={t("submitting")} /> : t("submit")}
            </Button>
          </Box>

          {failure !== null ? (
            <Alert severity="error" role="alert" sx={{ mt: 1.5 }}>
              <Typography variant="body2">{t(`errors.${failure.message}`)}</Typography>
              {supportRequestId !== null ? (
                <Typography variant="caption" sx={{ display: "block", mt: 0.25 }}>
                  {tc("supportReference", { requestId: supportRequestId })}
                </Typography>
              ) : null}
            </Alert>
          ) : null}
        </CardContent>
      </Card>
    </Box>
  );
}