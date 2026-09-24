#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
# PR 25C deterministic geolocation seeding helper for the isolated E2E stack.
#
# Invoked with the exact browser-created Investigation UUID and an
# allowlisted scenario name after the Playwright spec has completed the
# Investigation. Requires the E2E harness environment exported by
# scripts/e2e.sh: fake operating mode, the dedicated ATI_E2E_SEEDING_ENABLED
# flag, and the host-reachable ATI_DATABASE_URL of the throwaway E2E
# PostgreSQL.
#
# The seeder runs on the host against the E2E Postgres host port. The
# browser never receives database credentials: Playwright only invokes this
# script and observes its exit status and bounded diagnostics.
#
# Exits nonzero on any failure with bounded machine-readable diagnostics and
# no secret output.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

command -v uv >/dev/null || { echo "uv is required; run ./install.sh" >&2; exit 1; }

INVESTIGATION_ID="${1:-}"
SCENARIO="${2:-}"
if [[ -z "$INVESTIGATION_ID" || -z "$SCENARIO" ]]; then
  echo "E2E-SEED-FAILED usage: scripts/e2e-seed-geolocation.sh <investigation-uuid> <scenario>" >&2
  exit 2
fi

: "${ATI_DATABASE_URL:?E2E seeding requires ATI_DATABASE_URL (exported by scripts/e2e.sh)}"
: "${ATI_OPERATING_MODE:?E2E seeding requires ATI_OPERATING_MODE (exported by scripts/e2e.sh)}"
: "${ATI_E2E_SEEDING_ENABLED:?E2E seeding requires ATI_E2E_SEEDING_ENABLED (exported by scripts/e2e.sh)}"

exec uv run python -m tests.e2e_support.seed_geolocation \
  --investigation "$INVESTIGATION_ID" \
  --scenario "$SCENARIO"