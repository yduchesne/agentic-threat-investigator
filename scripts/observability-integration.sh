#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
# End-to-end OpenTelemetry delivery acceptance harness (PR 34).
#
# The authoritative integration gate proving that ATI telemetry traverses the
# deployed observability stack in one real execution:
#
#   ati-telemetry-test (production composition)
#     -> OTLP/HTTP
#     -> OpenTelemetry Collector (real, pinned)
#     -> Prometheus / Jaeger / Loki (real, pinned)
#     -> Grafana provisioning/health (real, pinned)
#
# Orchestration is owned end to end (PR 34 section 4/7/17):
#   start isolated topology -> wait TOPOLOGY_READY -> build the repo ATI image
#   -> run the real generator one-shot attached to the isolated network
#   -> bounded-poll convergence (Prometheus/Jaeger/Loki) + Grafana verification
#   -> only after READY_FOR_ASSERTIONS: run the authoritative assertions
#   -> collect bounded run-state/diagnostics -> teardown owned resources only
#
# Usage:
#   ./scripts/observability-integration.sh [--keep-on-failure] [--timeout N]
#
# This harness is NOT part of ./build.sh --intg (PR 34 section 11/18): the
# ordinary integration gate stays lightweight and never requires the
# observability stack.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

command -v uv >/dev/null || { echo "uv is required" >&2; exit 1; }
command -v podman >/dev/null || { echo "podman is required" >&2; exit 1; }
if command -v podman-compose >/dev/null 2>&1; then
  COMPOSE=(podman-compose)
elif podman compose version >/dev/null 2>&1; then
  COMPOSE=(podman compose)
else
  echo "podman-compose (or podman compose with a working provider) is required" >&2
  exit 1
fi

KEEP_ON_FAILURE=0
TIMEOUT_SECONDS=1200
while [ $# -gt 0 ]; do
  case "$1" in
    --keep-on-failure) KEEP_ON_FAILURE=1; shift ;;
    --timeout) TIMEOUT_SECONDS="$2"; shift 2 ;;
    -h|--help) sed -n '1,35p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

RUN_ID="ati-obs-$(date +%s)-$$"
ARTIFACT_DIR="artifacts/observability-integration/$RUN_ID"
mkdir -p "$ARTIFACT_DIR"
export COMPOSE_PROJECT_NAME="$RUN_ID"
export ATI_OBS_RUN_ID="$RUN_ID"
export ATI_OBS_STATE_DIR="$PWD/$ARTIFACT_DIR"
# The isolated Compose network (never the developer `ati` network); the
# generator container attaches to exactly this topology.
export ATI_OBSERVABILITY_TEST_NETWORK="${RUN_ID}_obsnet"

# Synthetic random Grafana admin credentials, harness-run local only (PR 34
# section 6.4: never committed, never logged, never reused).
gen_password() { openssl rand -hex 16 2>/dev/null || printf 'ati-obs-only'; }
export ATI_OBS_GRAFANA_ADMIN_USER="ati-obs-admin"
export ATI_OBS_GRAFANA_ADMIN_PASSWORD="$(gen_password)"

# Host ports for the harness topology, all ABOVE the default Linux ephemeral
# range (32768-60999 on GitHub-hosted runners) exactly like integration-test.sh
# (PR 34 section 4.3). Each window is disjoint; choose_host_port probes a real
# bind before selecting.
OBS_PORT_LOW=61000
OBS_PORT_HIGH=65535

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

choose_host_port() {
  local low="$1" high="$2"
  local candidate=""
  for _ in $(seq 1 30); do
    candidate=$(shuf -i "$low-$high" -n 1)
    if port_is_available "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo "could not find an available observability-harness port in [$low, $high]" >&2
  return 1
}

export ATI_OBS_COLLECTOR_OTLP_PORT=$(choose_host_port "$OBS_PORT_LOW" "$OBS_PORT_HIGH")
export ATI_OBS_COLLECTOR_HEALTH_PORT=$(choose_host_port "$OBS_PORT_LOW" "$OBS_PORT_HIGH")
export ATI_OBS_PROMETHEUS_PORT=$(choose_host_port "$OBS_PORT_LOW" "$OBS_PORT_HIGH")
export ATI_OBS_JAEGER_PORT=$(choose_host_port "$OBS_PORT_LOW" "$OBS_PORT_HIGH")
export ATI_OBS_LOKI_PORT=$(choose_host_port "$OBS_PORT_LOW" "$OBS_PORT_HIGH")
export ATI_OBS_GRAFANA_PORT=$(choose_host_port "$OBS_PORT_LOW" "$OBS_PORT_HIGH")

export ATI_OBS_COLLECTOR_HEALTH_URL="http://127.0.0.1:${ATI_OBS_COLLECTOR_HEALTH_PORT}"
export ATI_OBS_PROMETHEUS_URL="http://127.0.0.1:${ATI_OBS_PROMETHEUS_PORT}"
export ATI_OBS_JAEGER_URL="http://127.0.0.1:${ATI_OBS_JAEGER_PORT}"
export ATI_OBS_LOKI_URL="http://127.0.0.1:${ATI_OBS_LOKI_PORT}"
export ATI_OBS_GRAFANA_URL="http://127.0.0.1:${ATI_OBS_GRAFANA_PORT}"

# Pinned image identities (PR 34 must use the repository-pinned versions).
PINNED_IMAGES='{
  "otel-collector": "docker.io/otel/opentelemetry-collector-contrib:0.161.0",
  "prometheus": "docker.io/prom/prometheus:v3.14.0",
  "jaeger": "docker.io/jaegertracing/jaeger:2.21.0",
  "loki": "docker.io/grafana/loki:3.7.8",
  "grafana": "docker.io/grafana/grafana:13.2.2"
}'

write_state() {
  cat > "$ARTIFACT_DIR/run-state.json" <<STATE
{
  "run_id": "$RUN_ID",
  "signal_run_id": "${ATI_OBS_SIGNAL_RUN_ID:-}",
  "ati_git_sha": "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)",
  "signals_emitted": false,
  "stage": "TOPOLOGY_START",
  "pinned_images": $PINNED_IMAGES,
  "ports": {
    "collector_otlp": "$ATI_OBS_COLLECTOR_OTLP_PORT",
    "collector_health": "$ATI_OBS_COLLECTOR_HEALTH_PORT",
    "prometheus": "$ATI_OBS_PROMETHEUS_PORT",
    "jaeger": "$ATI_OBS_JAEGER_PORT",
    "loki": "$ATI_OBS_LOKI_PORT",
    "grafana": "$ATI_OBS_GRAFANA_PORT"
  }
}
STATE
}
write_state

fail() {
  echo "== Observability harness failure: $1 ==" >&2
  exit 1
}

teardown() {
  "${COMPOSE[@]}" -f compose.observability.test.yaml -p "$RUN_ID" down -v --remove-orphans >/dev/null 2>&1 || true
  podman rm -f "$GENERATOR_CONTAINER" >/dev/null 2>&1 || true
  if [ -n "${GENERATOR_IMAGE:-}" ]; then
    podman rmi -f "$GENERATOR_IMAGE" >/dev/null 2>&1 || true
  fi
}

cleanup() {
  if [ "${_DONE:-0}" != "1" ]; then
    echo "== Collecting bounded diagnostics for partial run $RUN_ID ==" >&2
    ATI_OBS_RUN_ID="$RUN_ID" uv run python -m tests.integration.observability.status \
      --run-id "$RUN_ID" --state-dir "$ARTIFACT_DIR" --diagnose >/dev/null 2>&1 || true
    echo "== Bounded service logs (tail) ==" >&2
    for svc in otel-collector prometheus jaeger loki grafana; do
      "${COMPOSE[@]}" -f compose.observability.test.yaml -p "$RUN_ID" logs --tail 40 "$svc" >"$ARTIFACT_DIR/$svc.log" 2>&1 || true
    done
    echo "diagnostics: $ARTIFACT_DIR" >&2
    if [ "$KEEP_ON_FAILURE" = "1" ]; then
      echo "topology retained for inspection (project $RUN_ID); run" >&2
      echo "podman-compose -f compose.observability.test.yaml -p $RUN_ID down -v" >&2
    else
      teardown
    fi
  else
    teardown
  fi
}
trap cleanup EXIT

echo "== Observability delivery run $RUN_ID =="
echo "artifacts: $ARTIFACT_DIR"

# Remove stale containers owned by PREVIOUS observability-harness runs only;
# never disturb unrelated developer containers.
cleanup_stale_obs_containers() {
  local container project
  for container in $(podman ps -aq --filter label=io.podman.compose.project 2>/dev/null); do
    project=$(podman inspect --format '{{ index .Config.Labels "io.podman.compose.project" }}' "$container" 2>/dev/null || true)
    case "$project" in
      ati-obs-*)
        podman stop -t 5 "$container" >/dev/null 2>&1 || true
        ;;
    esac
  done
  for pass in 1 2 3; do
    for container in $(podman ps -aq --filter label=io.podman.compose.project 2>/dev/null); do
      project=$(podman inspect --format '{{ index .Config.Labels "io.podman.compose.project" }}' "$container" 2>/dev/null || true)
      case "$project" in
        ati-obs-*)
          podman rm -f "$container" >/dev/null 2>&1 || true
          ;;
      esac
    done
  done
  for network in $(podman network ls --quiet | grep '^ati-obs-' || true); do
    podman network rm -f "$network" >/dev/null 2>&1 || true
  done
  for volume in $(podman volume ls --quiet | grep '^ati-obs-' || true); do
    podman volume rm -f "$volume" >/dev/null 2>&1 || true
  done
}

cleanup_stale_obs_containers

echo "== Starting isolated observability topology (Collector, Prometheus, Jaeger, Loki, Grafana) =="
for service in otel-collector jaeger loki prometheus grafana; do
  "${COMPOSE[@]}" -f compose.observability.test.yaml -p "$RUN_ID" up -d "$service" \
    || fail "podman-compose could not start $service"
done

missing=0
for service in otel-collector prometheus jaeger loki grafana; do
  podman ps -a --filter "label=io.podman.compose.project=${RUN_ID}" \
    --format '{{.Names}}' 2>/dev/null \
    | grep -qx "${RUN_ID}_${service}_1" || { echo "service $service was not started by podman-compose" >&2; missing=1; }
done
[ "$missing" = "0" ] || fail "the isolated observability topology did not fully start"

record_image_digests() {
  uv run python - "$ARTIFACT_DIR" <<'PY'
import json, subprocess, sys
from pathlib import Path
path = Path(sys.argv[1]) / "run-state.json"
state = json.loads(path.read_text())
images = {
    "otel-collector": "docker.io/otel/opentelemetry-collector-contrib:0.161.0",
    "prometheus": "docker.io/prom/prometheus:v3.14.0",
    "jaeger": "docker.io/jaegertracing/jaeger:2.21.0",
    "loki": "docker.io/grafana/loki:3.7.8",
    "grafana": "docker.io/grafana/grafana:13.2.2",
}
digests = {}
for name, image in images.items():
    try:
        result = subprocess.run(
            ["podman", "inspect", "-t", "image", "-f", "{{.Id}}", image],
            capture_output=True, text=True, timeout=30, check=False,
        )
        digest = result.stdout.strip()
        digests[name] = digest if digest else "unknown"
    except Exception:  # noqa: BLE001 - diagnostics must never fail the harness
        digests[name] = "unknown"
state["image_digests"] = digests
path.write_text(json.dumps(state, indent=2))
PY
}
record_image_digests

echo "== Waiting for observability topology readiness (TOPOLOGY_READY) =="
uv run python -m tests.integration.observability.status \
  --run-id "$RUN_ID" --state-dir "$ARTIFACT_DIR" \
  --wait --until-stage TOPOLOGY_READY --timeout-seconds 600 \
  || fail "the observability topology did not become ready in time"
uv run python -m tests.integration.observability.status \
  --run-id "$RUN_ID" --state-dir "$ARTIFACT_DIR" --status || true

echo "== Building the repository ATI image (generator runtime) =="
GENERATOR_IMAGE="ati-obs-generator:pr34-${RUN_ID##*-}"
podman build -f Dockerfile -t "$GENERATOR_IMAGE" . || fail "ATI image build failed"

# The unique diagnostic run identity correlating every signal (PR 34 2.5).
ATI_OBS_SIGNAL_RUN_ID=$(uv run python -c 'import sys, uuid; sys.stdout.write(str(uuid.uuid4()))')
export ATI_OBS_SIGNAL_RUN_ID
# The verifier/status CLI discover the run through ATI_OBS_RUN_ID; that must
# be the SIGNAL UUID (the correlation key of every Prometheus series, Jaeger
# span, and Loki line), not the Compose project identity.
export ATI_OBS_RUN_ID="$ATI_OBS_SIGNAL_RUN_ID"
uv run python - "$ARTIFACT_DIR" "$ATI_OBS_SIGNAL_RUN_ID" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1]) / "run-state.json"
state = json.loads(path.read_text())
state["signal_run_id"] = sys.argv[2]
path.write_text(json.dumps(state, indent=2))
PY

echo "== Running the production-composition diagnostic generator =="
echo "signal run id: $ATI_OBS_SIGNAL_RUN_ID"
GENERATOR_OUTPUT="$ARTIFACT_DIR/generator-output.txt"
set +e
# The generator container receives ONLY the two required environment
# variables. No signal-specific OTLP endpoint/header override is passed
# (even empty values would change the exporter endpoint resolution) and no
# host OTLP variable can leak into the container: the pinned OTel exporters
# therefore target exactly ``http://otel-collector:4318`` (PR 34 section 15).
podman run --rm \
  --name "${RUN_ID}_generator_1" \
  --network "$ATI_OBSERVABILITY_TEST_NETWORK" \
  -e ATI_OBSERVABILITY_ENABLED=true \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 \
  "$GENERATOR_IMAGE" \
  ati-telemetry-test --run-id "$ATI_OBS_SIGNAL_RUN_ID" >"$GENERATOR_OUTPUT" 2>&1
GENERATOR_EXIT=$?
set -e
GENERATOR_CONTAINER=""
if [ "$GENERATOR_EXIT" != "0" ]; then
  echo "== Generator failed (exit $GENERATOR_EXIT) ==" >&2
  sed -n '1,80p' "$GENERATOR_OUTPUT" >&2 || true
  fail "generator exit $GENERATOR_EXIT (stage GENERATOR)"
fi
tail -5 "$GENERATOR_OUTPUT"
uv run python - "$ARTIFACT_DIR" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1]) / "run-state.json"
state = json.loads(path.read_text())
state["signals_emitted"] = True
state["generator_exit"] = 0
path.write_text(json.dumps(state, indent=2))
PY

echo "== Waiting for backend convergence (READY_FOR_ASSERTIONS) =="
uv run python -m tests.integration.observability.status \
  --run-id "$RUN_ID" --state-dir "$ARTIFACT_DIR" \
  --wait --until-stage READY_FOR_ASSERTIONS --timeout-seconds "$TIMEOUT_SECONDS" \
  || fail "telemetry convergence did not reach READY_FOR_ASSERTIONS"

echo "== Running authoritative observability assertions =="
uv run pytest tests/integration/observability -m observability -q \
  || fail "observability assertions failed"
_DONE=1
echo "== Observability delivery SUCCESS: run $RUN_ID =="
echo "evidence: $ARTIFACT_DIR/run-state.json"
exit 0
