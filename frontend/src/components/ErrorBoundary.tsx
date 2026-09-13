// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Global render error boundary (PR 24A).
//
// Catastrophic render failures show a safe, translated surface. Production
// UI never exposes stack traces; only the error message is logged.

import { Box, Button, Typography } from "@mui/material";
import type { ReactNode } from "react";
import { Component, type ErrorInfo } from "react";

interface AppErrorBoundaryProps {
  children: ReactNode;
  title: string;
  message: string;
  reloadLabel: string;
}

interface AppErrorBoundaryState {
  failed: boolean;
}

/** Catches uncaught render errors below it and renders a safe surface. */
export class AppErrorBoundary extends Component<AppErrorBoundaryProps, AppErrorBoundaryState> {
  constructor(props: AppErrorBoundaryProps) {
    super(props);
    this.state = { failed: false };
  }

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { failed: true };
  }

  componentDidCatch(_error: unknown, info: ErrorInfo): void {
    // Bounded observability only; the UI never renders the stack.
    console.error("ATI render failure", info.componentStack?.slice(0, 2000));
  }

  override render(): ReactNode {
    if (this.state.failed) {
      return (
        <Box role="alert" sx={{ py: 6, textAlign: "center" }}>
          <Typography variant="h1">{this.props.title}</Typography>
          <Typography variant="body1" sx={{ mt: 0.5 }}>
            {this.props.message}
          </Typography>
          <Button variant="contained" sx={{ mt: 2 }} onClick={() => window.location.reload()}>
            {this.props.reloadLabel}
          </Button>
        </Box>
      );
    }
    return this.props.children;
  }
}