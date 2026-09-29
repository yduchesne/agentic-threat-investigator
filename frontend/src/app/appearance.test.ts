// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Appearance preference contract + safe storage adapter (PR 31F-4 A01..A10).
//
// Covers the bounded model and the fail-safe browser-local persistence
// rules: absent/unknown/throwing storage resolves to Light; writes only
// ever touch the exact ATI appearance key; the supported set is exactly
// four appearances with Light as the canonical default.

import { afterEach, describe, expect, it } from "vitest";

import {
  APPEARANCE_PREFERENCES,
  APPEARANCE_STORAGE_KEY,
  DEFAULT_APPEARANCE,
  isAppearancePreference,
  readAppearancePreference,
  writeAppearancePreference,
  type AppearanceStorage,
} from "./appearance";

/** In-memory storage double with inspectable contents. */
function memoryStorage(initial: Record<string, string> = {}): AppearanceStorage & {
  contents: Record<string, string>;
} {
  const contents = { ...initial };
  return {
    contents,
    getItem(key: string): string | null {
      return key in contents ? contents[key] : null;
    },
    setItem(key: string, value: string): void {
      contents[key] = value;
    },
  };
}

afterEach(() => {
  // jsdom localStorage is shared within the test file; keep every test
  // starting from an empty ATI key.
  try {
    globalThis.localStorage.removeItem(APPEARANCE_STORAGE_KEY);
  } catch {
    // Storage may be unavailable in this environment; tests above pass an
    // explicit storage double anyway.
  }
});

describe("Appearance model (A10, default)", () => {
  it("A10: exposes exactly the four supported appearances", () => {
    expect(APPEARANCE_PREFERENCES).toEqual(["light", "dark", "wargames", "control-room"]);
    expect(APPEARANCE_PREFERENCES).toHaveLength(4);
  });

  it("A10: canonical default is Light", () => {
    expect(DEFAULT_APPEARANCE).toBe("light");
  });

  it("A10: validator accepts exactly the four supported values", () => {
    for (const preference of APPEARANCE_PREFERENCES) {
      expect(isAppearancePreference(preference)).toBe(true);
    }
    for (const invalid of ["", "midnight", "light ", "Light", "solarized", 7, null, undefined, {}]) {
      expect(isAppearancePreference(invalid)).toBe(false);
    }
  });
});

describe("readAppearancePreference (A01..A07)", () => {
  it("A01: a store without the key resolves to Light", () => {
    expect(readAppearancePreference(memoryStorage())).toBe("light");
    expect(readAppearancePreference(memoryStorage({ other: "keep-me" }))).toBe("light");
  });

  it("A02: a stored light preference is returned", () => {
    expect(
      readAppearancePreference(memoryStorage({ [APPEARANCE_STORAGE_KEY]: "light" })),
    ).toBe("light");
  });

  it("A03: a stored dark preference is returned", () => {
    expect(
      readAppearancePreference(memoryStorage({ [APPEARANCE_STORAGE_KEY]: "dark" })),
    ).toBe("dark");
  });

  it("A04: a stored wargames preference is returned", () => {
    expect(
      readAppearancePreference(memoryStorage({ [APPEARANCE_STORAGE_KEY]: "wargames" })),
    ).toBe("wargames");
  });

  it("A05: a stored control-room preference is returned", () => {
    expect(
      readAppearancePreference(memoryStorage({ [APPEARANCE_STORAGE_KEY]: "control-room" })),
    ).toBe("control-room");
  });

  it("A06: an unknown/malformed stored value resolves to Light", () => {
    for (const stored of ["vaporwave", "midnight", "", "DARK", " light"]) {
      expect(
        readAppearancePreference(memoryStorage({ [APPEARANCE_STORAGE_KEY]: stored })),
      ).toBe("light");
    }
  });

  it("A07: a throwing read resolves to Light without crashing", () => {
    const throwing: AppearanceStorage = {
      getItem() {
        throw new Error("read blocked");
      },
      setItem() {},
    };
    expect(readAppearancePreference(throwing)).toBe("light");
  });

  it("A07: a null store (unavailable storage) resolves to Light", () => {
    expect(readAppearancePreference(null)).toBe("light");
  });
});

describe("writeAppearancePreference (A08, A09)", () => {
  it("A09: a save writes exactly the ATI appearance key and nothing else", () => {
    const storage = memoryStorage({ "unrelated.pref": "keep" });
    writeAppearancePreference("dark", storage);
    expect(storage.contents).toEqual({
      "unrelated.pref": "keep",
      [APPEARANCE_STORAGE_KEY]: "dark",
    });
  });

  it("A09: a save for every supported value round-trips through read", () => {
    for (const preference of APPEARANCE_PREFERENCES) {
      const storage = memoryStorage();
      writeAppearancePreference(preference, storage);
      expect(readAppearancePreference(storage)).toBe(preference);
    }
  });

  it("A08: a throwing write never crashes and leaves read safe", () => {
    const storage: AppearanceStorage = {
      getItem() {
        return "dark";
      },
      setItem() {
        throw new Error("write blocked");
      },
    };
    writeAppearancePreference("control-room", storage);
    // The in-memory view stays fully usable after the failed write.
    expect(readAppearancePreference(storage)).toBe("dark");
  });

  it("A08: write with unavailable browser storage is a safe no-op", () => {
    const original = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
    const restore = () => {
      if (original !== undefined) {
        Object.defineProperty(globalThis, "localStorage", original);
      } else {
        delete (globalThis as { localStorage?: unknown }).localStorage;
      }
    };
    // Accessing localStorage itself throws (blocked cookies); the adapter
    // must degrade to an in-memory-only workbench instead of crashing.
    Object.defineProperty(globalThis, "localStorage", {
      configurable: true,
      get() {
        throw new Error("storage blocked");
      },
    });
    try {
      writeAppearancePreference("dark");
      expect(readAppearancePreference()).toBe("light");
    } finally {
      restore();
    }
  });

  it("never clears unrelated storage", () => {
    const storage = memoryStorage({ "unrelated.pref": "keep", other: "value" });
    writeAppearancePreference("wargames", storage);
    expect(storage.contents["unrelated.pref"]).toBe("keep");
    expect(storage.contents["other"]).toBe("value");
    expect(Object.keys(storage.contents).sort()).toEqual(
      [APPEARANCE_STORAGE_KEY, "unrelated.pref", "other"].sort(),
    );
  });
});
