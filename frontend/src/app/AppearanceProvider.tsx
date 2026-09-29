// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Appearance provider (PR 31F-4).
//
// A deliberately narrow presentation-state provider: it owns the committed
// appearance plus exactly the operations the Preferences dialog needs —
// preview, commit and cancel. There is no generic settings infrastructure,
// no global state library, and no backend/auth coupling. The persisted
// preference is read synchronously during state initialization so the very
// first render already uses the committed appearance (no theme flash), and
// any storage failure falls back to Light without crashing.

import { createContext, useContext, useState } from "react";
import type { ReactElement, ReactNode } from "react";

import {
  readAppearancePreference,
  writeAppearancePreference,
  type AppearancePreference,
  type AppearanceStorage,
} from "./appearance";

/** The appearance operations exposed to Preferences surfaces. */
export interface AppearanceContextValue {
  /** The appearance currently presented (preview when one is active). */
  appearance: AppearancePreference;
  /** The committed (persisted) appearance, unchanged by previews. */
  committed: AppearancePreference;
  /** True while a preview (unsaved selection) is active. */
  previewing: boolean;
  /** Live-preview a choice without persisting. */
  previewAppearance(value: AppearancePreference): void;
  /** Persist the active preview as the committed appearance. */
  commitAppearance(): void;
  /** Discard any preview and restore the committed appearance. */
  cancelPreview(): void;
}

const AppearanceContext = createContext<AppearanceContextValue | null>(null);

export interface AppearanceProviderProps {
  children: ReactNode;
  /**
   * Test seam: injected storage for deterministic component tests.
   * Production leaves it null and reads ``globalThis.localStorage``.
   */
  storage?: AppearanceStorage | null;
}

/**
 * Owns the committed appearance and preview lifecycle.
 *
 * The persisted preference is read lazily during state initialization —
 * before the first render commits to a theme — so storage failures cannot
 * flash a wrong appearance and cannot crash the boot path.
 */
export function AppearanceProvider({
  children,
  storage = null,
}: AppearanceProviderProps): ReactElement {
  // Synchronous lazy read during state initialization: the first render
  // already carries the persisted appearance (no flash), and failures
  // fall back to Light before any theme is derived.
  const [committed, setCommitted] = useState<AppearancePreference>(() =>
    readAppearancePreference(storage),
  );
  const [preview, setPreview] = useState<AppearancePreference | null>(null);

  const value: AppearanceContextValue = {
    appearance: preview ?? committed,
    committed,
    previewing: preview !== null,
    previewAppearance: (next) => setPreview(next),
    commitAppearance: () => {
      const next = preview;
      if (next !== null) {
        writeAppearancePreference(next, storage);
        setCommitted(next);
      }
      setPreview(null);
    },
    cancelPreview: () => setPreview(null),
  };

  return (
    <AppearanceContext.Provider value={value}>{children}</AppearanceContext.Provider>
  );
}

/**
 * Read the appearance context.
 *
 * Only valid inside ``AppearanceProvider`` (which the application
 * ``AppProviders`` composition guarantees).
 */
export function useAppearance(): AppearanceContextValue {
  const value = useContext(AppearanceContext);
  if (value === null) {
    throw new Error("useAppearance() used outside AppearanceProvider.");
  }
  return value;
}
