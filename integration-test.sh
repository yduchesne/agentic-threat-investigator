#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

command -v uv >/dev/null || { echo "uv is required; run ./install.sh" >&2; exit 1; }
command -v podman >/dev/null || { echo "podman is required; run ./install.sh" >&2; exit 1; }
# Prefer the native podman-compose provider: the `podman compose` wrapper may
# delegate to Docker Compose, which requires the Podman socket to be running
# and fails under rootless Podman when it is not.
if command -v podman-compose >/dev/null 2>&1; then
  COMPOSE=(podman-compose)
elif podman compose version >/dev/null 2>&1; then
  COMPOSE=(podman compose)
else
  echo "podman-compose (or podman compose with a working provider) is required; run ./install.sh" >&2; exit 1
fi

# Isolation guarantees (docs/TESTING.md): unique Compose project, unique test
# database name, random host port, and a named container volume instead of the
# developer ATI_DATA_DIR bind mount. The guard in the test suite additionally
# rejects any DATABASE_URL that is not unmistakably a test database.
TEST_ID="ati-test-$(date +%s)-$$"
TEST_PORT=$(shuf -i 55536-60999 -n 1)
export COMPOSE_PROJECT_NAME="$TEST_ID"
export POSTGRES_DB="$TEST_ID"
export POSTGRES_USER=ati
export POSTGRES_PASSWORD=ati-integration-test-only
export ATI_POSTGRES_HOST_PORT="$TEST_PORT"
export DATABASE_URL="postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${TEST_PORT}/${POSTGRES_DB}"

TEST_OVERRIDE=$(mktemp --suffix=.yaml)
cat >"$TEST_OVERRIDE" <<'OVERRIDE'
services:
  postgres:
    volumes: ["ati_test_postgres_data:/var/lib/postgresql"]
volumes:
  ati_test_postgres_data: {}
OVERRIDE

# podman-compose substitutes variables across the whole base file even for
# sections the override replaces, so the required ATI_DATA_DIR in the base
# bind-mount definition must resolve. The value is never used: the override
# mounts the throwaway named volume above instead of any host directory.
export ATI_DATA_DIR="${ATI_DATA_DIR:-/tmp/ati-integration-test-unused}"

cleanup() {
  "${COMPOSE[@]}" -f compose.yaml -f "$TEST_OVERRIDE" -p "$TEST_ID" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$TEST_OVERRIDE"
}
trap cleanup EXIT

echo "== Starting isolated PostgreSQL 18 + pgvector (${TEST_ID}) =="
"${COMPOSE[@]}" -f compose.yaml -f "$TEST_OVERRIDE" -p "$TEST_ID" up -d postgres

echo "== Waiting for PostgreSQL readiness =="
uv run python - "$TEST_PORT" <<'PY'
import os
import sys
import time

import psycopg

url = os.environ["DATABASE_URL"].replace("postgresql+psycopg://", "postgresql://", 1)
deadline = time.monotonic() + 90
while True:
    try:
        with psycopg.connect(url, connect_timeout=3):
            break
    except psycopg.OperationalError:
        if time.monotonic() >= deadline:
            sys.exit("postgres did not become ready in time")
        time.sleep(1)
PY

echo "== Applying Alembic migrations =="
uv run alembic upgrade head

echo "== Running integration tests =="
# The authoritative 85% coverage gate is enforced by build.sh --check on the
# unit suite; the integration suite validates database behavior against real
# PostgreSQL, so coverage is reported without a standalone threshold here.
uv run pytest tests/integration -m integration \
  --cov=agentic_threat_investigator --cov-report=term-missing --cov-fail-under=0

echo "Integration tests passed."
