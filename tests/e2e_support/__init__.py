# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Harness-only support package for the isolated real-stack E2E environment.

Nothing in this package is imported by production code, installed in any
deployment image, or reachable through HTTP. It exists so the deterministic
Playwright stack can materialize ordinary persisted data through the normal
application persistence seam.
"""
