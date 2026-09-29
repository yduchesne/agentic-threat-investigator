// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Appearance preference contract (PR 31F-4).
//
// A deliberately bounded, finite frontend model for the analyst-workbench
// appearance. Appearance is presentation-only local browser state: it is
// not an Investigation/Tenant/Organization model, not backend or
// PostgreSQL state, not authorization, and never part of the environment-
// variable configuration precedence. The module stays independent of
// React and of any persistence infrastructure: only the exact ATI
// appearance key is ever read/written, and any storage failure falls back
// to Light without crashing the workbench.

/** One bounded analyst-workbench appearance. */
type AppearanceValue =
  | "light"
  | "dark"
  | "wargames"
  | "control-room";

/** The finite set of analyst workbench appearances. */
export type AppearancePreference = AppearanceValue;

/** The exact supported set, kept as one runtime source of truth. */
const APPEARANCE_VALUES: readonly AppearanceValue[] = [
  "light",
  "dark",
  "wargames",
  "control-room",
];

/** The finite set of analyst workbench appearances (runtime list). */
export const APPEARANCE_PREFERENCES: readonly AppearancePreference[] =
  APPEARANCE_VALUES;

/** Canonical default appearance (Light). */
export const DEFAULT_APPEARANCE: AppearancePreference = "light";

/** Stable ATI-owned browser-local storage key for the appearance. */
export const APPEARANCE_STORAGE_KEY = "ati.appearance";

/**
 * Runtime validator/type guard.
 *
 * Unknown, malformed, or future values are rejected so no arbitrary theme
 * name can ever reach the theme registry.
 */
export function isAppearancePreference(value: unknown): value is AppearancePreference {
  return (
    typeof value === "string" &&
    APPEARANCE_PREFERENCES.includes(value as AppearancePreference)
  );
}

/**
 * The minimal browser-storage boundary used by the appearance adapter.
 *
 * Kept deliberately narrow (get/set item) so tests can inject absent or
 * failing stores without a generic persistence abstraction.
 */
export interface AppearanceStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/**
 * Resolve the active browser storage, tolerating environments where even
 * touching `globalThis.localStorage` throws (blocked cookies, sandboxed
 * iframes, disabled storage). Returns null instead of throwing.
 */
export function resolveAppearanceStorage(): AppearanceStorage | null {
  try {
    // `globalThis.localStorage` access itself can throw (SecurityError in
    // some contexts), which is why the access lives inside the guard.
    const storage = globalThis.localStorage as AppearanceStorage | undefined;
    if (
      storage === undefined ||
      typeof storage.getItem !== "function" ||
      typeof storage.setItem !== "function"
    ) {
      return null;
    }
    return storage;
  } catch {
    return null;
  }
}

/**
 * Read and validate the persisted appearance preference.
 *
 * | Case            | Result |
 * |-----------------|--------|
 * | key absent      | Light  |
 * | valid value     | it     |
 * | unknown/malformed | Light |
 * | read throws     | Light, no crash |
 * | no storage      | Light  |
 */
export function readAppearancePreference(
  storage: AppearanceStorage | null | undefined = null,
): AppearancePreference {
  const active = storage ?? resolveAppearanceStorage();
  if (active === null) {
    return DEFAULT_APPEARANCE;
  }
  try {
    const stored = active.getItem(APPEARANCE_STORAGE_KEY);
    return isAppearancePreference(stored) ? stored : DEFAULT_APPEARANCE;
  } catch {
    return DEFAULT_APPEARANCE;
  }
}

/**
 * Persist the appearance preference under the exact ATI key only.
 *
 * Write failures are swallowed: the in-memory appearance remains usable
 * and the analyst keeps a fully functional workbench. Only
 * ``APPEARANCE_STORAGE_KEY`` is ever written — never ``clear()`` and
 * never any unrelated storage key.
 */
export function writeAppearancePreference(
  value: AppearancePreference,
  storage: AppearanceStorage | null | undefined = null,
): void {
  const active = storage ?? resolveAppearanceStorage();
  if (active === null) {
    return;
  }
  try {
    active.setItem(APPEARANCE_STORAGE_KEY, value);
  } catch {
    // Deliberately silent: a full storage failure (quota, private mode,
    // permissions) must never crash or degrade the running workbench.
  }
}
