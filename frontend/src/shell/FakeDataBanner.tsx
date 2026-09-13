// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Runtime-mode FAKE DATA indicator (PR 24A / PR 23D contract).
//
// The operating mode always comes from authenticated GET /api/v1/runtime.
// `fake` renders a persistent, high-visibility textual indicator; the
// text, not color alone, carries the meaning and it cannot be dismissed.
// Runtime lookup failure renders a bounded warning — the shell never
// silently assumes production.

import { Alert, Box, Button, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import { useRuntimeQuery } from "../runtime/runtime-queries";

/** Persistent non-dismissible fake-mode surface. */
function FakeDataSurface(): ReactElement {
  const { t } = useTranslation("shell");
  return (
    <Box
      role="status"
      sx={{
        width: "100%",
        bgcolor: "#fff3d6",
        borderTop: "3px solid",
        borderTopColor: "#8a5b00",
        color: "#5c3d00",
        px: 1.5,
        py: 0.75,
        display: "flex",
        alignItems: "center",
        gap: 1,
      }}
    >
      <Typography variant="overline" component="span" sx={{ fontWeight: 800, letterSpacing: "0.08em" }}>
        {t("fakeData.title")}
      </Typography>
      <Typography variant="body2" component="span" sx={{ fontWeight: 600 }}>
        {t("fakeData.message")}
      </Typography>
    </Box>
  );
}

/** Bounded warning shown when runtime metadata cannot be determined. */
function RuntimeUnavailableSurface({ onRetry }: { onRetry: () => void }): ReactElement {
  const { t } = useTranslation("common");
  return (
    <Alert severity="warning" role="alert" sx={{ width: "100%" }}>
      <Typography variant="body2">{t("runtimeUnavailable.title")}</Typography>
      <Typography variant="caption" sx={{ display: "block", mt: 0.25 }}>
        {t("runtimeUnavailable.message")}
      </Typography>
      <Button size="small" variant="outlined" onClick={onRetry} sx={{ mt: 0.5, textTransform: "none" }}>
        {t("retry")}
      </Button>
    </Alert>
  );
}

/**
 * Renders the runtime-mode indicator; only ever mounted inside the
 * authenticated shell, so metadata never loads before authentication.
 */
export function FakeDataBanner(): ReactElement | null {
  const { runtime, error, refetch } = useRuntimeQuery();

  if (runtime !== null && runtime.operating_mode === "production") {
    return null;
  }
  if (runtime !== null && runtime.operating_mode === "fake") {
    return <FakeDataSurface />;
  }
  if (error !== null) {
    return <RuntimeUnavailableSurface onRetry={refetch} />;
  }
  return null;
}