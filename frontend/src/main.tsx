// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
import { StrictMode, type ReactElement } from "react";
import { createRoot } from "react-dom/client";

function App(): ReactElement {
  return <main><h1>Agentic Threat Investigator</h1><p>Analyst workbench bootstrap.</p></main>;
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
