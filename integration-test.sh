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
#
# Host ports for the isolated containers are selected ABOVE the default Linux
# ephemeral-port range (net.ipv4.ip_local_port_range is 32768-60999 on
# GitHub-hosted runners). Under rootless Podman each mapped host port is bound
# by a user-space port forwarder (pasta/gvproxy); a port inside the ephemeral
# range can already be occupied as the source port of an outbound connection
# even though a plain bind() probe reported it free. That surfaced once as an
# intermittent "rootlessport listen ... bind: address already in use" CI
# failure, so ports are also chosen per attempt and the container start is
# retried with a fresh port on any bind conflict.
TEST_ID="ati-test-$(date +%s)-$$"

# PostgreSQL host port sits above the ephemeral range.
HOST_PORT_LOW=62000
HOST_PORT_HIGH=65535
# Redpanda host port sits above the ephemeral range in a disjoint window.
REDPANDA_PORT_LOW=61000
REDPANDA_PORT_HIGH=61999

# Remove stale containers created by this integration harness only. Never
# disturb unrelated developer containers or services.
cleanup_stale_ati_test_containers() {
  local container project
  while read -r container; do
    [ -n "$container" ] || continue
    project=$(podman inspect --format '{{ index .Config.Labels "io.podman.compose.project" }}' "$container" 2>/dev/null || true)
    case "$project" in
      ati-test-*)
        echo "== Removing stale ATI test container $container ($project) =="
        podman rm -f "$container" >/dev/null
        ;;
    esac
  done < <(podman ps -aq --filter label=io.podman.compose.project)
}

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

# choose_host_port <low> <high>: print one random available host port in
# [low, high], or return non-zero when none is free after probing.
choose_host_port() {
  local low="$1" high="$2"
  local candidate=""
  for _ in $(seq 1 30); do
    candidate=$(shuf -i "$low-$high" -n 1)
    if port_is_available "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
    echo "Port $candidate is already in use; selecting another port."
  done
  echo "could not find an available integration-test port in [$low, $high]" >&2
  return 1
}

cleanup_stale_ati_test_containers

# The Redpanda host port is chosen once, above the ephemeral range; the
# PostgreSQL port is chosen per start attempt inside its retry loop below.
export COMPOSE_PROJECT_NAME="$TEST_ID"
export POSTGRES_DB="$TEST_ID"
export POSTGRES_USER=ati
export POSTGRES_PASSWORD=ati-integration-test-only
export ATI_REDPANDA_HOST_PORT="$(choose_host_port "$REDPANDA_PORT_LOW" "$REDPANDA_PORT_HIGH")"
export REDPANDA_PORT="$ATI_REDPANDA_HOST_PORT"
# PR 28G: the deterministic local Redpanda broker endpoint exposed to the
# integration-test process (host-side OUTSIDE listener).
export ATI_EVIDENCE_KAFKA_BOOTSTRAP="127.0.0.1:${REDPANDA_PORT}"

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
# A fresh host port is chosen per attempt and the failed project state is torn
# down between attempts, so a transient rootless-port-forwarder bind conflict
# ("rootlessport listen ... bind: address already in use") must never abort
# the whole integration run.
for _attempt in $(seq 1 40); do
  TEST_PORT="$(choose_host_port "$HOST_PORT_LOW" "$HOST_PORT_HIGH")"
  export ATI_POSTGRES_HOST_PORT="$TEST_PORT"
  export DATABASE_URL="postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${TEST_PORT}/${POSTGRES_DB}"
  if "${COMPOSE[@]}" -f compose.yaml -f "$TEST_OVERRIDE" -p "$TEST_ID" up -d postgres; then
    break
  fi
  echo "PostgreSQL container start failed on port $TEST_PORT; retrying with a fresh port."
  "${COMPOSE[@]}" -f compose.yaml -f "$TEST_OVERRIDE" -p "$TEST_ID" down --remove-orphans >/dev/null 2>&1 || true
  TEST_PORT=""
done
[ -n "$TEST_PORT" ] || { echo "could not start the isolated PostgreSQL container" >&2; exit 1; }

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

echo "== Starting isolated Redpanda broker (${TEST_ID}) =="
# Same bind-conflict backstop as PostgreSQL. Only the failed Redpanda
# container is removed between attempts (PostgreSQL is already running and
# the project must not come down).
for _attempt in $(seq 1 40); do
  REDPANDA_PORT="$(choose_host_port "$REDPANDA_PORT_LOW" "$REDPANDA_PORT_HIGH")"
  export ATI_REDPANDA_HOST_PORT="$REDPANDA_PORT"
  export ATI_EVIDENCE_KAFKA_BOOTSTRAP="127.0.0.1:${REDPANDA_PORT}"
  if "${COMPOSE[@]}" -f compose.yaml -f "$TEST_OVERRIDE" -p "$TEST_ID" up -d redpanda; then
    break
  fi
  echo "Redpanda container start failed on port $REDPANDA_PORT; retrying with a fresh port."
  podman rm -f "${TEST_ID}_redpanda_1" >/dev/null 2>&1 || true
  REDPANDA_PORT=""
done
[ -n "$REDPANDA_PORT" ] || { echo "could not start the isolated Redpanda broker" >&2; exit 1; }

# PR 28G CI follow-up: podman-compose 1.0.6 can return success even when the
# container was never created (e.g. image pull failure), so verify that a
# running Redpanda container exists for *this* integration-test project before
# entering the Kafka readiness loop. Identification uses the Compose project
# and service labels only -- never a guessed container name.
if ! podman ps \
  --filter "label=io.podman.compose.project=${TEST_ID}" \
  --filter "label=com.docker.compose.service=redpanda" \
  --format '{{.ID}}' | grep -q .; then
  echo "Redpanda container failed to start for integration-test project ${TEST_ID}" >&2
  "${COMPOSE[@]}" -f compose.yaml -f "$TEST_OVERRIDE" -p "$TEST_ID" logs redpanda >&2 || true
  exit 1
fi

echo "== Waiting for Redpanda Kafka API readiness =="
uv run python - "$REDPANDA_PORT" <<'PY'
import asyncio
import os
import sys
import time

from aiokafka.admin import AIOKafkaAdminClient

bootstrap = os.environ["ATI_EVIDENCE_KAFKA_BOOTSTRAP"]

deadline = time.monotonic() + 180


async def ready() -> bool:
    client = AIOKafkaAdminClient(bootstrap_servers=bootstrap, request_timeout_ms=5000)
    try:
        await client.start()
        await client.list_topics()
        return True
    except Exception:
        return False
    finally:
        await client.close()


while True:
    if asyncio.run(ready()):
        break
    if time.monotonic() >= deadline:
        sys.exit("redpanda did not become ready in time")
    time.sleep(2)
PY

echo "== Applying Alembic migrations =="
uv run alembic upgrade head

echo "== Running integration tests =="
# The authoritative 85% coverage gate is enforced by build.sh --qa on the
# unit suite; the integration suite validates database behavior against real
# PostgreSQL, so coverage is reported without a standalone threshold here.
uv run pytest tests/integration -m integration \
  --cov=agentic_threat_investigator --cov-report=term-missing --cov-fail-under=0

echo "== Building frontend production bundle =="
# The deployable frontend artifact is only produced after the integration
# tests have succeeded: type-checking and bundling run here, so a failing
# integration run never yields a deployable dist/ bundle.
command -v npm >/dev/null || { echo 'npm is required for the frontend build; run ./install.sh' >&2; exit 1; }
if [[ ! -d frontend/node_modules ]]; then (cd frontend && npm ci) >/dev/null; fi
(cd frontend && npm run build)

echo "Integration tests passed; frontend production bundle built."
