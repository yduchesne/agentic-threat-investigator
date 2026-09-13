// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Bounded workspace placeholder routes (PR 24B §18).
//
// Evidence/Relationships/Research/Timeline routes exist only to anchor the
// workspace layout and header for PR 24C; they render a bounded notice and
// never issue collection queries.

import type { ReactElement } from "react";
import { useTranslation } from "react-i18next";

import { EmptyState } from "../components/AsyncState";

export type WorkspacePlaceholderKind =
  | "evidence"
  | "relationships"
  | "research"
  | "timeline";

export interface WorkspacePlaceholderPageProps {
  kind: WorkspacePlaceholderKind;
}

/** A bounded placeholder that never queries its collection. */
export function WorkspacePlaceholderPage({
  kind,
}: WorkspacePlaceholderPageProps): ReactElement {
  const { t } = useTranslation("investigations");
  return (
    <EmptyState
      title={t(`tabs.${kind}`)}
      message={t("placeholder.message", {
        surface: t(`tabs.${kind}`).toLowerCase(),
      })}
    />
  );
}