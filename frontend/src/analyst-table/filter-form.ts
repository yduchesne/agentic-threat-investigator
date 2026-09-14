// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Draft filter form controller (PR 24C §14).
//
// Text/date inputs apply only on explicit Apply or Enter — never on every
// keystroke; the draft stays in component state while the committed model
// lives in the URL. Invalid values surface as localized validation errors
// instead of silently altering backend semantics. Commit resets the
// cursor/back stack through the table controller.

import { useRef, useState } from "react";

export interface FilterFormOptions<F, D> {
  /** The committed (URL-backed) filter model. */
  committed: F;
  /** Build a draft from the committed model (init/resync). */
  buildDraft: (filters: F) => D;
  /** Convert a validated draft to the committed model. */
  toFilters: (draft: D) => F;
  /** Localized validation error, or null when the draft is commit-able. */
  validateDraft: (draft: D) => string | null;
  /** Commit one filter model (resets cursor/back stack). */
  onApply: (filters: F) => void;
  /** Reset to the neutral filter state. */
  onClear: () => void;
  /** The neutral draft (``Clear filters`` target). */
  emptyDraft: D;
  /** Canonical identity of the committed model (URL resync detection). */
  committedKey: string;
}

export interface FilterForm<D> {
  draft: D;
  setDraft: (next: D) => void;
  /** Localized validation error of the current draft. */
  error: string | null;
  /** Validate and commit the draft. */
  apply: () => void;
  /** Clear to the neutral state (draft + committed). */
  clear: () => void;
}

/** One draft/commit filter form bound to URL-backed filters. */
export function useFilterForm<F, D>({
  committed,
  buildDraft,
  toFilters,
  validateDraft,
  onApply,
  onClear,
  emptyDraft,
  committedKey,
}: FilterFormOptions<F, D>): FilterForm<D> {
  const [draft, setDraftState] = useState<D>(() => buildDraft(committed));
  const [error, setError] = useState<string | null>(null);
  const lastCommitted = useRef(committedKey);
  if (lastCommitted.current !== committedKey) {
    // The URL-backed filter state changed outside this form (browser
    // navigation, deep link); resync the draft during render.
    lastCommitted.current = committedKey;
    setDraftState(buildDraft(committed));
  }

  const setDraft = (next: D): void => {
    setDraftState(next);
    setError(null);
  };

  const apply = (): void => {
    const validation = validateDraft(draft);
    if (validation !== null) {
      setError(validation);
      return;
    }
    setError(null);
    onApply(toFilters(draft));
  };

  const clear = (): void => {
    setError(null);
    setDraftState(emptyDraft);
    onClear();
  };

  return { draft, setDraft, error, apply, clear };
}