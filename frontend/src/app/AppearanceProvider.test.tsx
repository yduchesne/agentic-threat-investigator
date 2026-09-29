// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Appearance provider + application composition (PR 31F-4 C01..C05).
//
// The provider owns committed/preview/cancel semantics; the application
// composition keeps exactly one QueryClient, one ThemeProvider and one
// CssBaseline. Appearance changes must never recreate the QueryClient,
// never navigate, never mutate the URL, and never issue server requests —
// any unexpected HTTP request fails loudly through the MSW server.

import { Box } from "@mui/material";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClientProvider, useQueryClient } from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";
import type { ReactElement } from "react";
import { afterEach, describe, expect, it } from "vitest";

import { AppearanceProvider, useAppearance } from "./AppearanceProvider";
import { APPEARANCE_STORAGE_KEY } from "./appearance";
import type { AppearanceStorage } from "./appearance";
import { freshQueryClient, renderProviders } from "../test/render";
import { useHttp } from "../test/server";

useHttp();

/** Interactive probe over the real application appearance context. */
function Probe({ expectedQueryClient }: { expectedQueryClient?: QueryClient } = {}): ReactElement {
  const { appearance, committed, previewing, previewAppearance, commitAppearance, cancelPreview } =
    useAppearance();
  const queryClient = useQueryClient();
  return (
    <Box data-testid="probe-root">
      <span data-testid="appearance">{appearance}</span>
      <span data-testid="committed">{committed}</span>
      <span data-testid="previewing">{String(previewing)}</span>
      <span data-testid="query-client-id">
        {expectedQueryClient === undefined || queryClient === expectedQueryClient ? "same" : "changed"}
      </span>
      <button data-testid="preview-dark" onClick={() => previewAppearance("dark")}>
        preview dark
      </button>
      <button data-testid="preview-wargames" onClick={() => previewAppearance("wargames")}>
        preview wargames
      </button>
      <button data-testid="commit" onClick={commitAppearance}>
        commit
      </button>
      <button data-testid="cancel" onClick={cancelPreview}>
        cancel
      </button>
    </Box>
  );
}

afterEach(() => {
  try {
    globalThis.localStorage.removeItem(APPEARANCE_STORAGE_KEY);
  } catch {
    // Storage may be unavailable; the adapter degrades safely.
  }
});

describe("AppearanceProvider", () => {
  it("C01: no stored preference resolves to Light on the committed and active appearance", () => {
    renderProviders(<Probe />);
    expect(screen.getByTestId("appearance").textContent).toBe("light");
    expect(screen.getByTestId("committed").textContent).toBe("light");
  });

  it("C02: a persisted preference is applied on the very first render", () => {
    globalThis.localStorage.setItem(APPEARANCE_STORAGE_KEY, "control-room");
    renderProviders(<Probe />);
    expect(screen.getByTestId("appearance").textContent).toBe("control-room");
    expect(screen.getByTestId("committed").textContent).toBe("control-room");
  });

  it("previews live without persisting; cancel restores the committed appearance", async () => {
    const user = userEvent.setup();
    globalThis.localStorage.setItem(APPEARANCE_STORAGE_KEY, "dark");
    renderProviders(<Probe />);
    expect(screen.getByTestId("appearance").textContent).toBe("dark");

    await user.click(screen.getByTestId("preview-wargames"));
    expect(screen.getByTestId("appearance").textContent).toBe("wargames");
    expect(screen.getByTestId("previewing").textContent).toBe("true");
    // Not persisted yet.
    expect(globalThis.localStorage.getItem(APPEARANCE_STORAGE_KEY)).toBe("dark");

    await user.click(screen.getByTestId("cancel"));
    expect(screen.getByTestId("appearance").textContent).toBe("dark");
    expect(screen.getByTestId("previewing").textContent).toBe("false");
  });

  it("commit persists the previewed appearance and closes the preview", async () => {
    const user = userEvent.setup();
    renderProviders(<Probe />);
    await user.click(screen.getByTestId("preview-dark"));
    await user.click(screen.getByTestId("commit"));
    expect(screen.getByTestId("appearance").textContent).toBe("dark");
    expect(screen.getByTestId("committed").textContent).toBe("dark");
    expect(screen.getByTestId("previewing").textContent).toBe("false");
    expect(globalThis.localStorage.getItem(APPEARANCE_STORAGE_KEY)).toBe("dark");
  });

  it("C03: previewing/committing keeps the same QueryClient identity", async () => {
    const user = userEvent.setup();
    const queryClient = freshQueryClient();
    renderProviders(<Probe expectedQueryClient={queryClient} />, { queryClient });
    expect(screen.getByTestId("query-client-id").textContent).toBe("same");

    await user.click(screen.getByTestId("preview-dark"));
    expect(screen.getByTestId("query-client-id").textContent).toBe("same");
    await user.click(screen.getByTestId("preview-wargames"));
    await user.click(screen.getByTestId("commit"));
    expect(screen.getByTestId("query-client-id").textContent).toBe("same");
  });

  it("C03: switching appearance never remounts the rendered tree", async () => {
    const user = userEvent.setup();
    renderProviders(<Probe />);
    const rootBefore = screen.getByTestId("probe-root");
    await user.click(screen.getByTestId("preview-dark"));
    const rootAfter = screen.getByTestId("probe-root");
    expect(rootAfter).toBe(rootBefore);
  });

  it("C04/C05: appearance changes cause no navigation, no URL mutation and no server request", async () => {
    const user = userEvent.setup();
    renderProviders(<Probe />);
    const urlBefore = window.location.href;
    await user.click(screen.getByTestId("preview-wargames"));
    await user.click(screen.getByTestId("commit"));
    expect(window.location.href).toBe(urlBefore);
    // MSW is armed in error-on-unhandled mode and Probe issues no queries;
    // any theme-only request would fail this test loudly.
    expect(screen.getByTestId("appearance").textContent).toBe("wargames");
  });

  it("storage read failure degrades to Light without crashing the boot path", () => {
    const storage: AppearanceStorage = {
      getItem() {
        throw new Error("storage blocked");
      },
      setItem() {},
    };
    const queryClient = freshQueryClient();
    render(
      <QueryClientProvider client={queryClient}>
        <AppearanceProvider storage={storage}>
          <Probe />
        </AppearanceProvider>
      </QueryClientProvider>,
    );
    expect(screen.getByTestId("appearance").textContent).toBe("light");
  });
});
