#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
# PR 26E deterministic reference-geography import helper for the isolated
# E2E stack.
#
# Loads the canonical ATI reference geography (United States -> Washington
# -> Seattle, Texas -> Dallas, EdgeLand ZZ, ...) through the normal
# PR 26B-2 work: `ati-geography-build` derives the ATI Geography Corpus
# from the repository's real-format GeoNames/Natural Earth fixtures, and
# `ati-geography-import` ingests it through the production ingestion
# service. No upstream download and no product HTTP endpoint is involved.
#
# Requires the E2E harness environment exported by scripts/e2e.sh (fake
# operating mode, the host-reachable ATI_DATABASE_URL). Runs on the host
# against the E2E Postgres host port; the browser never receives database
# credentials.
#
# Exits nonzero on any failure with bounded diagnostics and no secret
# output.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

command -v uv >/dev/null || { echo "uv is required; run ./install.sh" >&2; exit 1; }

: "${ATI_DATABASE_URL:?E2E geography import requires ATI_DATABASE_URL (exported by scripts/e2e.sh)}"

FIXTURES="tests/fixtures/geoint"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
CORPUS="$WORK_DIR/ati-geography.ndjson"

echo "== Building the ATI Geography Corpus from repository fixtures =="
uv run ati-geography-build \
  --geonames-country-info "$FIXTURES/geonames/countryInfo.txt" \
  --geonames-admin1 "$FIXTURES/geonames/admin1CodesASCII.txt" \
  --geonames-cities "$FIXTURES/geonames/cities1000.txt" \
  --natural-earth-countries "$FIXTURES/natural_earth/ne_countries.geojson" \
  --natural-earth-admin1 "$FIXTURES/natural_earth/ne_admin1.geojson" \
  --output "$CORPUS"

echo "== Importing the canonical reference geography =="
ATI_OPERATING_MODE="${ATI_OPERATING_MODE:-fake}" uv run ati-geography-import "$CORPUS" >/dev/null

echo "Reference geography import completed."