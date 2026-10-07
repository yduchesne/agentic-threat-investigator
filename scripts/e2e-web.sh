#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
# V07-01 server-rendered web acceptance harness.
#
# Builds and runs the real production-path topology for the new HTML
# presentation adapter in isolation:
#
#   throwaway PostgreSQL -> migrations -> fake-data bootstrap ->
#   FastAPI (fake mode, bootstrap admin) serving both /api/v1 and the
#   server-rendered web routes -> React/Nginx frontend in parallel ->
#   Playwright Chromium (and Firefox) against the web origin.
#
# Isolation follows scripts/e2e.sh principles: unique Compose project,
# unmistakable test DB/user/password, random safe host ports, throwaway
# named volume, generated test-only bootstrap credential, scoped cleanup,
# fake operating mode, and no live LLM/provider requirement.
#
# During V07-1..V07-6 this harness is the new-web acceptance gate and
# scripts/e2e.sh remains the React regression harness. They are intentionally
# separate until the V07-7 cutover.
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

E2E_ID="ati-web-e2e-$(date +%s)-$$"

cleanup_stale_ati_test_containers() {
  local container project
  for _ in $(seq 1 30); do
    local remaining=0
    while read -r container; do
      [ -n "$container" ] || continue
      project=$(podman inspect --format '{{ index .Config.Labels "io.podman.compose.project" }}' "$container" 2>/dev/null || true)
      case "$project" in
        ati-web-e2e-*)
          remaining=1
          echo "== Removing stale ATI web E2E container $container ($project) =="
          podman rm -f "$container" >/dev/null 2>&1 || true
          ;;
      esac
    done < <(podman ps -aq --filter label=io.podman.compose.project)
    [ "$remaining" -eq 0 ] && break
    sleep 1
  done
}

# Host ports sit ABOVE the default Linux ephemeral-port range (see
# scripts/e2e.sh for the rootless-Podman rationale). The frontend and
# postgres/API windows are disjoint.
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
for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except OSError:
                continue
        try:
            sock.bind((address, port))
        except OSError as exc:
            if exc.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL, errno.ENOPROTOOPT):
                continue
            raise SystemExit(1)
PY
}

pick_port() {
  local low="$1" high="$2"
  local result="" candidate=""
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
API_PORT=$(pick_port "$HOST_PORT_LOW" "$HOST_PORT_HIGH")
BOOTSTRAP_PASSWORD="web-e2e-$(uv run python -c 'import secrets; print(secrets.token_urlsafe(18))')"

export COMPOSE_PROJECT_NAME="$E2E_ID"
export POSTGRES_DB="$E2E_ID"
export POSTGRES_USER=ati
export POSTGRES_PASSWORD=ati-web-e2e-test-only
export ATI_POSTGRES_HOST_PORT="$POSTGRES_PORT"
export ATI_API_HOST_PORT="$API_PORT"
export ATI_FRONTEND_HOST_PORT="$FRONTEND_PORT"
export ATI_OPERATING_MODE=fake
export ATI_CONFIG_PROFILE=local
export ATI_LLM_DRIVER=deterministic
# Two exact transitional browser origins over one backend: the React SPA
# origin and the server-rendered web origin (the FastAPI/API host port).
export ATI_PUBLIC_BASE_URL="http://127.0.0.1:${FRONTEND_PORT}"
export ATI_WEB_BASE_URL="http://127.0.0.1:${API_PORT}"
export ATI_BOOTSTRAP_ADMIN_USERNAME="web-e2e-admin"
export E2E_BOOTSTRAP_PASSWORD="$BOOTSTRAP_PASSWORD"
export ATI_DATABASE_URL="postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}"
export ATI_DATA_DIR="${ATI_DATA_DIR:-/tmp/ati-web-e2e-unused}"
mkdir -p "$ATI_DATA_DIR/datasets"

E2E_OVERRIDE=$(mktemp --suffix=.yaml)
cat >"$E2E_OVERRIDE" <<OVERRIDE
services:
  postgres:
    volumes: ["ati_web_e2e_postgres_data:/var/lib/postgresql"]
  api:
    environment:
      ATI_BOOTSTRAP_ADMIN_USERNAME: ${ATI_BOOTSTRAP_ADMIN_USERNAME}
      ATI_BOOTSTRAP_ADMIN_PASSWORD: ${E2E_BOOTSTRAP_PASSWORD}
      ATI_CONFIG_PROFILE: ${ATI_CONFIG_PROFILE}
      ATI_WEB_BASE_URL: ${ATI_WEB_BASE_URL}
      ATI_PUBLIC_BASE_URL: ${ATI_PUBLIC_BASE_URL}
volumes:
  ati_web_e2e_postgres_data: {}
OVERRIDE

# podman-compose reads the repo .env unless an explicit alternate env file is
# supplied; the alternate file keeps this harness isolated from developer
# port/origin settings.
E2E_ENV_FILE=$(mktemp --suffix=.env)
cat >"$E2E_ENV_FILE" <<ENVEOF
COMPOSE_PROJECT_NAME=${E2E_ID}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
ATI_POSTGRES_HOST_PORT=${POSTGRES_PORT}
ATI_API_HOST_PORT=${API_PORT}
ATI_FRONTEND_HOST_PORT=${FRONTEND_PORT}
ATI_DATA_DIR=${ATI_DATA_DIR}
ATI_PUBLIC_BASE_URL=${ATI_PUBLIC_BASE_URL}
ATI_WEB_BASE_URL=${ATI_WEB_BASE_URL}
ATI_OPERATING_MODE=${ATI_OPERATING_MODE}
ATI_CONFIG_PROFILE=${ATI_CONFIG_PROFILE}
ATI_LLM_DRIVER=${ATI_LLM_DRIVER}
ATI_BOOTSTRAP_ADMIN_USERNAME=${ATI_BOOTSTRAP_ADMIN_USERNAME}
ATI_BOOTSTRAP_ADMIN_PASSWORD=${E2E_BOOTSTRAP_PASSWORD}
ENVEOF

cleanup() {
  "${COMPOSE[@]}" --env-file "$E2E_ENV_FILE" -f compose.yaml -f "$E2E_OVERRIDE" -p "$E2E_ID" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$E2E_OVERRIDE" "$E2E_ENV_FILE"
}
trap cleanup EXIT

echo "== Building and creating isolated web E2E stack ($E2E_ID) =="
"${COMPOSE[@]}" --env-file "$E2E_ENV_FILE" -f compose.yaml -f "$E2E_OVERRIDE" -p "$E2E_ID" up --no-start --build \
  postgres migrate fake-data-bootstrap api frontend

echo "== Starting web E2E containers =="
E2E_CONTAINERS=$(podman ps -a --filter "label=io.podman.compose.project=${E2E_ID}" --format '{{.Names}}' | tr '\n' ' ')
# shellcheck disable=SC2086
podman start $E2E_CONTAINERS

echo "== Waiting for the web login and parallel React boundaries =="
uv run python - "$API_PORT" "$FRONTEND_PORT" <<'PY'
import http.client
import sys
import time

api_port = int(sys.argv[1])
frontend_port = int(sys.argv[2])
deadline = time.monotonic() + 420


def request(port: int, path: str, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", path, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


while True:
    web_ok = react_ok = False
    try:
        status, body = request(api_port, "/login")
        web_ok = status == 200 and b"<form" in body
    except Exception:
        web_ok = False
    try:
        status, _ = request(
            frontend_port,
            "/api/v1/runtime",
            {"Origin": f"http://127.0.0.1:{frontend_port}"},
        )
        react_ok = status in (200, 401)
    except Exception:
        react_ok = False
    if web_ok and react_ok:
        break
    if time.monotonic() >= deadline:
        sys.exit(f"boundaries not ready (web={web_ok}, react={react_ok})")
    time.sleep(2)
print("Web and React boundaries are ready.")
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

echo "== Ensuring web E2E Node dependencies =="
if [[ ! -d web-e2e/node_modules ]]; then
  (cd web-e2e && npm ci --no-audit --no-fund)
fi

echo "== Ensuring Playwright Chromium and Firefox =="
if ! ls "${HOME}/.cache/ms-playwright"/chromium-* >/dev/null 2>&1; then
  (cd web-e2e && npx playwright install chromium)
fi
if ! ls "${HOME}/.cache/ms-playwright"/firefox-* >/dev/null 2>&1; then
  (cd web-e2e && npx playwright install firefox)
fi

export WEB_E2E_BASE_URL="http://127.0.0.1:${API_PORT}"
export WEB_E2E_ADMIN_USERNAME="$ATI_BOOTSTRAP_ADMIN_USERNAME"
export WEB_E2E_ADMIN_PASSWORD="$BOOTSTRAP_PASSWORD"

echo "== Running the web Playwright acceptance suite (retries=0, workers=1) =="
if [ "$#" -gt 0 ]; then
  (cd web-e2e && npm run test:e2e -- "$@")
else
  (cd web-e2e && npm run test:e2e)
fi

echo "Web E2E suite passed."
