#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
# PR 24A real-stack browser E2E harness.
#
# Builds and runs the full production-path topology in isolation:
#
#   throwaway PostgreSQL -> migrations -> fake-data bootstrap ->
#   FastAPI (fake mode, bootstrap admin) -> static frontend + Nginx /api ->
#   Playwright Chromium
#
# Isolation follows integration-test.sh principles: unique Compose project,
# unmistakable test DB/user/password, random host ports, a throwaway named
# volume and a generated test-only bootstrap credential. Cleanup only
# touches resources this harness created. No live LLM is required.
#
# Note: podman-compose 1.0.6 cannot `podman start` a container whose
# dependency graph mixes already-running and exited one-shot services
# ("depends on container ... not found in input list"). The harness
# sidesteps that by creating all containers with `up --no-start` and then
# starting the whole named set in one `podman start` call, so every
# `--requires` target is present in the start list.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

command -v uv >/dev/null || { echo "uv is required; run ./install.sh" >&2; exit 1; }
command -v npm >/dev/null || { echo "npm is required; run ./install.sh" >&2; exit 1; }
command -v podman >/dev/null || { echo "podman is required; run ./install.sh" >&2; exit 1; }
if command -v podman-compose >/dev/null 2>&1; then
  COMPOSE=(podman-compose)
elif podman compose version >/dev/null 2>&1; then
  COMPOSE=(podman compose)
else
  echo "podman-compose (or podman compose with a working provider) is required; run ./install.sh" >&2
  exit 1
fi

E2E_ID="ati-e2e-$(date +%s)-$$"

cleanup_stale_ati_test_containers() {
  # Remove stale containers created by this harness only, tolerating the
  # podman dependent-container ordering by retrying until none remain.
  local container project
  for _ in $(seq 1 30); do
    local remaining=0
    while read -r container; do
      [ -n "$container" ] || continue
      project=$(podman inspect --format '{{ index .Config.Labels "io.podman.compose.project" }}' "$container" 2>/dev/null || true)
      case "$project" in
        ati-e2e-*)
          remaining=1
          echo "== Removing stale ATI E2E container $container ($project) =="
          podman rm -f "$container" >/dev/null 2>&1 || true
          ;;
      esac
    done < <(podman ps -aq --filter label=io.podman.compose.project)
    [ "$remaining" -eq 0 ] && break
    sleep 1
  done
}

port_is_available() {
  uv run python - "$1" <<'PY'
import socket
import sys

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", int(sys.argv[1])))
    except OSError:
        raise SystemExit(1)
PY
}

pick_port() {
  local result=""
  for _ in $(seq 1 30); do
    candidate=$(shuf -i 50000-59999 -n 1)
    if port_is_available "$candidate"; then
      result="$candidate"
      break
    fi
  done
  [ -n "$result" ] || { echo "could not find an available port" >&2; exit 1; }
  echo "$result"
}

cleanup_stale_ati_test_containers
FRONTEND_PORT=$(pick_port)
POSTGRES_PORT=$(pick_port)
BOOTSTRAP_PASSWORD="e2e-$(uv run python -c 'import secrets; print(secrets.token_urlsafe(18))')"

export COMPOSE_PROJECT_NAME="$E2E_ID"
export POSTGRES_DB="$E2E_ID"
export POSTGRES_USER=ati
export POSTGRES_PASSWORD=ati-e2e-test-only
export ATI_POSTGRES_HOST_PORT="$POSTGRES_PORT"
# The static frontend host port is variable-driven (compose.yaml), mirroring
# the postgres port pattern.
export ATI_FRONTEND_HOST_PORT="$FRONTEND_PORT"
export ATI_OPERATING_MODE=fake
export ATI_PUBLIC_BASE_URL="http://127.0.0.1:${FRONTEND_PORT}"
export ATI_BOOTSTRAP_ADMIN_USERNAME="e2e-admin"
export E2E_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD"
# Required by the base bind-mount definition; the override replaces the
# postgres volume with a throwaway named volume. The fake-data bootstrap
# materializes its packaged datasets itself.
export ATI_DATA_DIR="${ATI_DATA_DIR:-/tmp/ati-e2e-unused}"
export E2E_BASE_URL="http://127.0.0.1:${FRONTEND_PORT}"
export E2E_ADMIN_USERNAME="$ATI_BOOTSTRAP_ADMIN_USERNAME"
export E2E_ADMIN_PASSWORD="$BOOTSTRAP_PASSWORD"

E2E_OVERRIDE=$(mktemp --suffix=.yaml)
cat >"$E2E_OVERRIDE" <<OVERRIDE
services:
  postgres:
    volumes: ["ati_e2e_postgres_data:/var/lib/postgresql"]
  api:
    environment:
      ATI_BOOTSTRAP_ADMIN_USERNAME: ${ATI_BOOTSTRAP_ADMIN_USERNAME}
      ATI_BOOTSTRAP_ADMIN_PASSWORD: ${E2E_BOOTSTRAP_PASSWORD}
volumes:
  ati_e2e_postgres_data: {}
OVERRIDE

cleanup() {
  "${COMPOSE[@]}" -f compose.yaml -f "$E2E_OVERRIDE" -p "$E2E_ID" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$E2E_OVERRIDE"
}
trap cleanup EXIT

echo "== Building and creating isolated E2E stack ($E2E_ID) =="
"${COMPOSE[@]}" -f compose.yaml -f "$E2E_OVERRIDE" -p "$E2E_ID" up --no-start --build \
  postgres migrate fake-data-bootstrap api frontend

echo "== Starting E2E containers =="
E2E_CONTAINERS=$(podman ps -a --filter "label=io.podman.compose.project=${E2E_ID}" --format '{{.Names}}' | tr '\n' ' ')
# shellcheck disable=SC2086
podman start $E2E_CONTAINERS

echo "== Waiting for the frontend->API boundary =="
uv run python - "$FRONTEND_PORT" <<'PY'
import http.client
import sys
import time

port = int(sys.argv[1])
deadline = time.monotonic() + 420
origin = f"http://127.0.0.1:{port}"
while True:
    ok = False
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/api/v1/runtime", headers={"Origin": origin})
        response = conn.getresponse()
        response.read()
        ok = response.status in (200, 401)
        conn.close()
    except Exception:
        ok = False
    if ok:
        break
    if time.monotonic() >= deadline:
        sys.exit("E2E stack did not become ready in time")
    time.sleep(2)
print("Frontend/API boundary is ready.")
PY

echo "== Ensuring Playwright Chromium =="
if [[ ! -d "${HOME}/.cache/ms-playwright/chromium-"* ]]; then
  (cd frontend && npx playwright install chromium)
fi

echo "== Running Playwright E2E specs =="
(cd frontend && npm run test:e2e)

echo "E2E suite passed."