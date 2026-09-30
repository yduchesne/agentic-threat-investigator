// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Preferences gear + dialog (PR 31F-4 P01..P11).
//
// Accessible gear beside the authenticated user controls; a modal MUI
// Dialog (never a route) with four human-readable appearance choices,
// live preview, Save persisting locally, Cancel/Escape restoring the
// committed appearance, and focus returning to the gear. All labels are
// i18next-backed; no raw translation keys reach the analyst.

import { Box, Button } from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useAppearance } from "../app/AppearanceProvider";
import { APPEARANCE_STORAGE_KEY } from "../app/appearance";
import { renderAtPath, renderProviders } from "../test/render";
import { setHttpHandlers, useHttp } from "../test/server";
import { ANALYST_USER, authMeSuccess, investigationsListHandler, runtimeFake } from "../test/handlers";
import { PreferencesDialog } from "./PreferencesDialog";

useHttp();

/** Probe reporting the active appearance from the shared context. */
function Probe(): ReactElement {
  const { appearance } = useAppearance();
  return <span data-testid="active-appearance">{appearance}</span>;
}

/** Open/close harness: the Preferences dialog plus a context probe. */
function Harness(): ReactElement {
  const [open, setOpen] = useState(false);
  return (
    <Box>
      <Button onClick={() => setOpen(true)}>open preferences</Button>
      <PreferencesDialog open={open} onClose={() => setOpen(false)} />
      <Probe />
    </Box>
  );
}

/** Wait for the modal dialog to leave the DOM. */
function expectDialogGone(): Promise<void> {
  return waitFor(() => {
    expect(screen.queryByRole("dialog", { name: "Preferences" })).not.toBeInTheDocument();
  });
}

afterEach(() => {
  try {
    globalThis.localStorage.removeItem(APPEARANCE_STORAGE_KEY);
  } catch {
    // Storage may be unavailable; the adapter degrades safely.
  }
});

describe("Preferences gear in the authenticated header (P01..P03, P09)", () => {
  async function renderShell(): Promise<ReturnType<typeof renderAtPath>["result"]> {
    setHttpHandlers(authMeSuccess, runtimeFake, investigationsListHandler([]));
    const { result } = renderAtPath("/investigations");
    await screen.findByRole("button", { name: "Preferences" });
    return result;
  }

  async function gear(): Promise<HTMLElement> {
    return screen.getByRole("button", { name: "Preferences" });
  }

  it("P01: the authenticated header exposes an accessible Preferences gear", async () => {
    await renderShell();
    const theGear = await gear();
    expect(theGear).toBeInTheDocument();
    expect(theGear).toHaveAttribute("aria-haspopup", "dialog");
    expect(screen.getByText(ANALYST_USER.alias)).toBeInTheDocument();
  });

  it("P02: clicking the gear opens the Preferences dialog without navigating", async () => {
    const user = userEvent.setup();
    await renderShell();
    const urlBefore = window.location.href;
    await user.click(await gear());
    const dialog = await screen.findByRole("dialog", { name: "Preferences" });
    expect(dialog).toBeInTheDocument();
    expect(window.location.href).toBe(urlBefore);
  });

  it("P03: keyboard activation opens the dialog", async () => {
    const user = userEvent.setup();
    await renderShell();
    (await gear()).focus();
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("dialog", { name: "Preferences" })).toBeInTheDocument();
  });

  it("P09: closing the dialog restores focus to the gear", async () => {
    const user = userEvent.setup();
    await renderShell();
    const theGear = await gear();
    await user.click(theGear);
    await screen.findByRole("dialog", { name: "Preferences" });
    await user.keyboard("{Escape}");
    await expectDialogGone();
    expect(theGear).toHaveFocus();
  });
});

describe("Preferences dialog behavior (P04..P08, P10, P11)", () => {
  it("P04: choosing Dark previews immediately without saving", async () => {
    const user = userEvent.setup();
    globalThis.localStorage.setItem(APPEARANCE_STORAGE_KEY, "light");
    renderProviders(<Harness />);
    await user.click(screen.getByRole("button", { name: "open preferences" }));
    await screen.findByRole("dialog", { name: "Preferences" });

    await user.click(screen.getByRole("radio", { name: "Dark" }));
    expect(screen.getByTestId("active-appearance").textContent).toBe("dark");
    expect(globalThis.localStorage.getItem(APPEARANCE_STORAGE_KEY)).toBe("light");
  });

  it("P05: Save commits Dark to local persistence and closes", async () => {
    const user = userEvent.setup();
    renderProviders(<Harness />);
    await user.click(screen.getByRole("button", { name: "open preferences" }));
    await screen.findByRole("dialog", { name: "Preferences" });

    await user.click(screen.getByRole("radio", { name: "Dark" }));
    await user.click(screen.getByRole("button", { name: "Save" }));
    await expectDialogGone();
    expect(screen.getByTestId("active-appearance").textContent).toBe("dark");
    expect(globalThis.localStorage.getItem(APPEARANCE_STORAGE_KEY)).toBe("dark");
  });

  it("P06: reopening reflects the committed preference", async () => {
    const user = userEvent.setup();
    globalThis.localStorage.setItem(APPEARANCE_STORAGE_KEY, "dark");
    renderProviders(<Harness />);
    await user.click(screen.getByRole("button", { name: "open preferences" }));
    const dialog = await screen.findByRole("dialog", { name: "Preferences" });
    expect(within(dialog).getByRole("radio", { name: "Dark" })).toBeChecked();
    expect(within(dialog).getByRole("radio", { name: "Wargames" })).not.toBeChecked();
  });

  it("P07: previewing Wargames then Cancel restores the committed Dark", async () => {
    const user = userEvent.setup();
    globalThis.localStorage.setItem(APPEARANCE_STORAGE_KEY, "dark");
    renderProviders(<Harness />);
    await user.click(screen.getByRole("button", { name: "open preferences" }));
    await screen.findByRole("dialog", { name: "Preferences" });

    await user.click(screen.getByRole("radio", { name: "Wargames" }));
    expect(screen.getByTestId("active-appearance").textContent).toBe("wargames");
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await expectDialogGone();
    expect(screen.getByTestId("active-appearance").textContent).toBe("dark");
    expect(globalThis.localStorage.getItem(APPEARANCE_STORAGE_KEY)).toBe("dark");
  });

  it("P08: previewing Control Room then Escape restores the committed Dark", async () => {
    const user = userEvent.setup();
    globalThis.localStorage.setItem(APPEARANCE_STORAGE_KEY, "dark");
    renderProviders(<Harness />);
    await user.click(screen.getByRole("button", { name: "open preferences" }));
    await screen.findByRole("dialog", { name: "Preferences" });

    await user.click(screen.getByRole("radio", { name: "Control Room" }));
    expect(screen.getByTestId("active-appearance").textContent).toBe("control-room");
    await user.keyboard("{Escape}");
    await expectDialogGone();
    expect(screen.getByTestId("active-appearance").textContent).toBe("dark");
  });

  it("P10: a storage write failure leaves the dialog fully usable", async () => {
    const user = userEvent.setup();
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("quota exceeded");
    });
    try {
      renderProviders(<Harness />);
      await user.click(screen.getByRole("button", { name: "open preferences" }));
      const dialog = await screen.findByRole("dialog", { name: "Preferences" });
      await user.click(within(dialog).getByRole("radio", { name: "Wargames" }));
      await user.click(within(dialog).getByRole("button", { name: "Save" }));
      await expectDialogGone();
      // In-memory appearance stays committed and the UI never crashes.
      expect(screen.getByTestId("active-appearance").textContent).toBe("wargames");
    } finally {
      vi.restoreAllMocks();
    }
  });

  it("P11: every label is translated; no raw i18n keys reach the DOM", async () => {
    const user = userEvent.setup();
    renderProviders(<Harness />);
    await user.click(screen.getByRole("button", { name: "open preferences" }));
    const dialog = await screen.findByRole("dialog", { name: "Preferences" });

    for (const label of [
      "Appearance",
      "Light",
      "Dark",
      "Wargames",
      "Control Room",
      "Save",
      "Cancel",
    ]) {
      expect(within(dialog).getByText(label)).toBeInTheDocument();
    }
    const text = (document.body as HTMLElement).textContent ?? "";
    expect(text).not.toContain("preferences.");
    expect(text).not.toContain("APPEARANCE_LABEL_KEY");
  });
});

describe("Appearance lifecycle over a rendered application surface (PR 31F-7 AP01..AP12)", () => {
  /**
   * Semantic rendered-surface probe: applies the active theme's paper
   * token to a real element and exposes the resolved token value. The
   * assertions prove the presentation surface re-themes, never just the
   * provider/radio state (PR 31F-7 §10: "assert a rendered application
   * surface/computed token"). The same tokens are asserted end-to-end by
   * the real-browser computed-style probes.
   */
  function ThemeSurface(): ReactElement {
    const theme = useTheme();
    return <div data-testid="theme-surface" data-paper={theme.palette.background.paper} />;
  }

  function SurfaceHarness(): ReactElement {
    const [open, setOpen] = useState(true);
    return (
      <Box>
        <PreferencesDialog open={open} onClose={() => setOpen(false)} />
        <ThemeSurface />
      </Box>
    );
  }

  function surfacePaper(): string | null {
    return screen.getByTestId("theme-surface").getAttribute("data-paper");
  }

  it("AP01/AP06: every supported appearance live-previews the rendered surface before Save, and A->B switches immediately", async () => {
    const user = userEvent.setup();
    renderProviders(<SurfaceHarness />);
    const dialog = await screen.findByRole("dialog", { name: "Preferences" });
    expect(surfacePaper()).toBe("#ffffff"); // Light baseline

    await user.click(within(dialog).getByRole("radio", { name: "Dark" }));
    expect(surfacePaper()).toBe("#1c2026");
    await user.click(within(dialog).getByRole("radio", { name: "Wargames" }));
    expect(surfacePaper()).toBe("#10150f");
    await user.click(within(dialog).getByRole("radio", { name: "Control Room" }));
    expect(surfacePaper()).toBe("#0f1a2c");
    await user.click(within(dialog).getByRole("radio", { name: "Light" }));
    expect(surfacePaper()).toBe("#ffffff");
    // Previews never persist.
    expect(globalThis.localStorage.getItem(APPEARANCE_STORAGE_KEY)).toBeNull();
  });

  it("AP02/AP07: Cancel after a preview restores the committed rendered surface", async () => {
    const user = userEvent.setup();
    globalThis.localStorage.setItem(APPEARANCE_STORAGE_KEY, "dark");
    renderProviders(<SurfaceHarness />);
    const dialog = await screen.findByRole("dialog", { name: "Preferences" });
    expect(surfacePaper()).toBe("#1c2026");

    await user.click(within(dialog).getByRole("radio", { name: "Wargames" }));
    expect(surfacePaper()).toBe("#10150f");
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await expectDialogGone();
    expect(surfacePaper()).toBe("#1c2026");
    expect(globalThis.localStorage.getItem(APPEARANCE_STORAGE_KEY)).toBe("dark");
  });

  it("AP03/AP09: Save keeps the selected theme active, persists it, and never navigates", async () => {
    const user = userEvent.setup();
    const urlBefore = window.location.href;
    renderProviders(<SurfaceHarness />);
    const dialog = await screen.findByRole("dialog", { name: "Preferences" });
    await user.click(within(dialog).getByRole("radio", { name: "Control Room" }));
    expect(surfacePaper()).toBe("#0f1a2c");
    await user.click(within(dialog).getByRole("button", { name: "Save" }));
    await expectDialogGone();
    expect(surfacePaper()).toBe("#0f1a2c");
    expect(globalThis.localStorage.getItem(APPEARANCE_STORAGE_KEY)).toBe("control-room");
    expect(window.location.href).toBe(urlBefore);
  });

  it("AP04/AP05: after Save+reload the saved appearance is restored and the reopened dialog selects it", async () => {
    globalThis.localStorage.setItem(APPEARANCE_STORAGE_KEY, "wargames");
    renderProviders(<SurfaceHarness />);
    const dialog = await screen.findByRole("dialog", { name: "Preferences" });
    expect(surfacePaper()).toBe("#10150f");
    expect(within(dialog).getByRole("radio", { name: "Wargames" })).toBeChecked();
    expect(within(dialog).getByRole("radio", { name: "Dark" })).not.toBeChecked();
  });

  it("AP08: open/close with no selection is a persistence no-op", async () => {
    const user = userEvent.setup();
    globalThis.localStorage.setItem(APPEARANCE_STORAGE_KEY, "dark");
    renderProviders(<SurfaceHarness />);
    const dialog = await screen.findByRole("dialog", { name: "Preferences" });
    await user.click(within(dialog).getByRole("button", { name: "Save" }));
    await expectDialogGone();
    expect(globalThis.localStorage.getItem(APPEARANCE_STORAGE_KEY)).toBe("dark");
    expect(surfacePaper()).toBe("#1c2026");
  });

  it("AP11: repeated open/preview/cancel cycles leave no stale state", async () => {
    const user = userEvent.setup();
    globalThis.localStorage.setItem(APPEARANCE_STORAGE_KEY, "light");
    function CycledHarness(): ReactElement {
      const [open, setOpen] = useState(true);
      return (
        <Box>
          <Button onClick={() => setOpen(true)}>open preferences</Button>
          <PreferencesDialog open={open} onClose={() => setOpen(false)} />
          <ThemeSurface />
        </Box>
      );
    }
    renderProviders(<CycledHarness />);
    for (const [label, token] of [
      ["Dark", "#1c2026"],
      ["Wargames", "#10150f"],
      ["Control Room", "#0f1a2c"],
      ["Light", "#ffffff"],
    ] as Array<[string, string]>) {
      const dialog = await screen.findByRole("dialog", { name: "Preferences" });
      await user.click(within(dialog).getByRole("radio", { name: label }));
      expect(surfacePaper()).toBe(token);
      await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
      await waitFor(() => {
        expect(screen.queryByRole("dialog", { name: "Preferences" })).not.toBeInTheDocument();
      });
      // Reopen for the next cycle; nothing persisted from the previews.
      await user.click(screen.getByRole("button", { name: "open preferences" }));
    }
    expect(globalThis.localStorage.getItem(APPEARANCE_STORAGE_KEY)).toBe("light");
    const finalDialog = await screen.findByRole("dialog", { name: "Preferences" });
    expect(within(finalDialog).getByRole("radio", { name: "Light" })).toBeChecked();
    expect(surfacePaper()).toBe("#ffffff");
  });

  it("AP12: Dark save -> reload -> reopen -> Wargames previews immediately (never appearance-specific)", async () => {
    const user = userEvent.setup();
    globalThis.localStorage.setItem(APPEARANCE_STORAGE_KEY, "dark");
    renderProviders(<SurfaceHarness />);
    const dialog = await screen.findByRole("dialog", { name: "Preferences" });
    expect(surfacePaper()).toBe("#1c2026");
    expect(within(dialog).getByRole("radio", { name: "Dark" })).toBeChecked();

    await user.click(within(dialog).getByRole("radio", { name: "Wargames" }));
    expect(surfacePaper()).toBe("#10150f");
  });
});
