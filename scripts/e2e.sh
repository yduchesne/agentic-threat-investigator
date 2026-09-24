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

# Host ports for the isolated E2E containers sit ABOVE the default Linux
# ephemeral-port range (net.ipv4.ip_local_port_range is 32768-60999): under
# rootless Podman the user-space port forwarder binds each mapped host port,
# and a port inside the ephemeral range can be silently occupied by an
# outbound connection (intermittent rootlessport EADDRINUSE). The frontend
# and postgres windows are disjoint so one container can never shadow the
# other.
HOST_PORT_LOW=62000
HOST_PORT_HIGH=65535
FRONTEND_PORT_LOW=61000
FRONTEND_PORT_HIGH=61999

port_is_available() {
  uv run python - "$1" <<'PY'
import errno
import socket
import sys

port = int(sys.argv[1])

# Bind all interfaces on both stacks exactly as the rootless-Podman port
# forwarder does. SO_REUSEADDR is deliberately not set: the forwarder binds a
# fresh listener, so a live (non-TIME_WAIT) occupant must fail this probe too.
for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except OSError:
                # Address family unavailable: nothing to probe on this side.
                continue
        try:
            sock.bind((address, port))
        except OSError as exc:
            if exc.errno in (
                errno.EAFNOSUPPORT,
                errno.EADDRNOTAVAIL,
                errno.ENOPROTOOPT,
            ):
                continue
            raise SystemExit(1)
PY
}

pick_port() {
  local low="$1" high="$2"
  local result=""
  local candidate=""
  for _ in $(seq 1 30); do
    candidate=$(shuf -i "$low-$high" -n 1)
    if port_is_available "$candidate"; then
      result="$candidate"
      break
    fi
  done
  [ -n "$result" ] || { echo "could not find an available port in [$low, $high]" >&2; exit 1; }
  echo "$result"
}

cleanup_stale_ati_test_containers
FRONTEND_PORT=$(pick_port "$FRONTEND_PORT_LOW" "$FRONTEND_PORT_HIGH")
POSTGRES_PORT=$(pick_port "$HOST_PORT_LOW" "$HOST_PORT_HIGH")
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
# The throwaway E2E topology raises the in-process login rate limit
# (config_local sets 100/60s instead of the production default 5/60s): the
# full authenticated suite (PR 24A auth spec + PR 24B investigation pair +
# PR 24C analyst browsing) performs several logins within one 60s window,
# and a timing-dependent 429 flake would make the deterministic browser
# suite unreliable on faster/slower runners. The E2E stack is a
# single-admin throwaway test world; production deployments keep the
# default limit.
export ATI_CONFIG_PROFILE=local
# The offline deterministic worker LLM boundary (PR 24B): the E2E stack
# never needs a live LLM. The API process does not compose an LLM.
export ATI_LLM_DRIVER=deterministic
export ATI_PUBLIC_BASE_URL="http://127.0.0.1:${FRONTEND_PORT}"
export ATI_BOOTSTRAP_ADMIN_USERNAME="e2e-admin"
export E2E_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD"
# PR 25C deterministic geolocation seeding (E24-E28): the scripted seeder
# runs on the host against the throwaway E2E Postgres host port through the
# normal application persistence seam. The dedicated enable flag and fake
# operating mode are both required by the seeder's fail-closed guard; the
# browser never receives these database URL values — the Playwright specs
# only invoke the helper script path below.
export ATI_E2E_SEEDING_ENABLED=1
export ATI_DATABASE_URL="postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}"
export E2E_SEED_SCRIPT="$PWD/scripts/e2e-seed-geolocation.sh"
# PR 26E canonical GEOINT seeding + reference geography (GEOINT E2E): the
# host-side seeder runs the production GeoResolution worker against the
# throwaway E2E Postgres host port, and the reference geography is loaded
# through the normal PR 26B-2 build/import work. Both helpers share the
# harness environment; the browser never receives database URLs.
export E2E_GEOINT_SEED_SCRIPT="$PWD/scripts/e2e-seed-geoint.sh"
export E2E_GEOGRAPHY_IMPORT_SCRIPT="$PWD/scripts/e2e-geography-import.sh"
# Required by the base bind-mount definition; the override replaces the
# postgres volume with a throwaway named volume. The fake-data bootstrap
# materializes its packaged datasets itself.
export ATI_DATA_DIR="${ATI_DATA_DIR:-/tmp/ati-e2e-unused}"
mkdir -p "$ATI_DATA_DIR/datasets"
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
      # Test-only profile: raises the in-process login rate limit for the
      # multi-session browser suite (see export above).
      ATI_CONFIG_PROFILE: ${ATI_CONFIG_PROFILE}
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
  postgres migrate fake-data-bootstrap api worker frontend

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

BOOTSTRAP_CONTAINER=$(podman ps -a --filter "label=io.podman.compose.project=${E2E_ID}" --format '{{.Names}}' | grep -F fake-data-bootstrap | head -n 1)
echo "== Waiting for the fake-data bootstrap to complete =="
for _ in $(seq 1 240); do
  state=$(podman inspect -f '{{.State.Status}}' "$BOOTSTRAP_CONTAINER" 2>/dev/null || true)
  [ "$state" = "exited" ] && break
  sleep 2
done
bootstrap_code=$(podman inspect -f '{{.State.ExitCode}}' "$BOOTSTRAP_CONTAINER" 2>/dev/null || echo 1)
if [ "$bootstrap_code" != "0" ]; then
  echo "fake-data bootstrap failed (exit $bootstrap_code)" >&2
  exit 1
fi
echo "Fake-data bootstrap completed."

echo "== Importing the canonical reference geography into the E2E database =="
"$E2E_GEOGRAPHY_IMPORT_SCRIPT"

echo "== Ensuring Playwright Chromium =="
if [[ ! -d "${HOME}/.cache/ms-playwright/chromium-"* ]]; then
  (cd frontend && npx playwright install chromium)
fi

echo "== Running Playwright E2E specs =="
(cd frontend && npm run test:e2e)

echo "E2E suite passed."
