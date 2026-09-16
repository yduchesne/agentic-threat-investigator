#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
# PR 26E deterministic GEOINT seeding helper for the isolated E2E stack.
#
# Invoked with the exact browser-created Investigation UUID and an
# allowlisted scenario name after the Playwright spec has completed the
# Investigation (plus --other-investigation for the cross-scope scenario).
# Requires the E2E harness environment exported by scripts/e2e.sh: fake
# operating mode, the dedicated ATI_E2E_SEEDING_ENABLED flag, and the
# host-reachable ATI_DATABASE_URL of the throwaway E2E PostgreSQL.
#
# The seeder runs on the host against the E2E Postgres host port through
# the normal repositories + the production GeoResolution worker. The
# browser never receives database credentials: Playwright only invokes
# this script and observes its exit status and bounded diagnostics.
#
# Exits nonzero on any failure with bounded machine-readable diagnostics
# and no secret output.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

command -v uv >/dev/null || { echo "uv is required; run ./install.sh" >&2; exit 1; }

INVESTIGATION_ID="${1:-}"
SCENARIO="${2:-}"
OTHER_INVESTIGATION="${3:-}"
if [[ -z "$INVESTIGATION_ID" || -z "$SCENARIO" ]]; then
  echo "E2E-GEOINT-SEED-FAILED usage: scripts/e2e-seed-geoint.sh <investigation-uuid> <scenario> [other-investigation-uuid]" >&2
  exit 2
fi

: "${ATI_DATABASE_URL:?E2E seeding requires ATI_DATABASE_URL (exported by scripts/e2e.sh)}"
: "${ATI_OPERATING_MODE:?E2E seeding requires ATI_OPERATING_MODE (exported by scripts/e2e.sh)}"
: "${ATI_E2E_SEEDING_ENABLED:?E2E seeding requires ATI_E2E_SEEDING_ENABLED (exported by scripts/e2e.sh)}"

ARGS=(--investigation "$INVESTIGATION_ID" --scenario "$SCENARIO")
if [[ -n "$OTHER_INVESTIGATION" ]]; then
  ARGS+=(--other-investigation "$OTHER_INVESTIGATION")
fi

exec uv run python -m tests.e2e_support.seed_geoint "${ARGS[@]}"