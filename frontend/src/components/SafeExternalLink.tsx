// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Safe external link (PR 24C §17, §19).
//
// Only explicit ``http``/``https`` URLs become clickable links with safe
// external attributes; anything else (javascript:, data:, file:, opaque
// provider values) renders as plain escaped text. Browser auto-fetch of
// external content never happens — a link is only a link.

import { Typography } from "@mui/material";
import type { ReactElement } from "react";

/** Whether one value is an explicit HTTP(S) absolute URL. */
export function isSafeHttpUrl(value: string | null | undefined): boolean {
  if (value === null || value === undefined || value === "") {
    return false;
  }
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

export interface SafeExternalLinkProps {
  /** The untrusted source URL value. */
  url: string | null | undefined;
  /** Optional visible text; defaults to the URL itself (escaped). */
  label?: string;
  /** Optional accessible name override when the URL text is opaque. */
  ariaLabel?: string;
}

/**
 * Render one source URL as a safe external link or escaped plain text.
 *
 * All content is React-rendered text — never raw HTML — and the target
 * opens in a new tab with ``noreferrer`` so provider hosts learn nothing.
 */
export function SafeExternalLink({
  url,
  label,
  ariaLabel,
}: SafeExternalLinkProps): ReactElement {
  if (isSafeHttpUrl(url) && url !== null && url !== undefined) {
    return (
      <Typography
        variant="body2"
        component="a"
        href={url}
        target="_blank"
        rel="noreferrer"
        aria-label={ariaLabel}
        sx={{ fontFamily: "monospace", wordBreak: "break-all" }}
      >
        {label ?? url}
      </Typography>
    );
  }
  return (
    <Typography variant="body2" component="span" aria-label={ariaLabel} sx={{ wordBreak: "break-all" }}>
      {label ?? nullableText(url)}
    </Typography>
  );
}

/** Render null/undefined source URLs as a bounded dash (already-scoped). */
function nullableText(url: string | null | undefined): string {
  return url === null || url === undefined ? "—" : url;
}