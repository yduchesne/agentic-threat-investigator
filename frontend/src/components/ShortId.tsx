// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Compact opaque identifier presentation (PR 24B §24).
//
// UUID support references are truncated for bounded rows; the full value
// stays available in the title tooltip and is never decoded or re-typed.

import type { ReactElement } from "react";

/** Return the bounded visible prefix of one opaque UUID. */
export function shortId(id: string): string {
  return id.slice(0, 8);
}

export interface ShortIdProps {
  id: string;
}

/** Render a bounded visible identifier with the full value in the title. */
export function ShortId({ id }: ShortIdProps): ReactElement {
  return (
    <code title={id} data-testid={`short-id-${shortId(id)}`}>
      {shortId(id)}
    </code>
  );
}