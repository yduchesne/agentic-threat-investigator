#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# start.sh -- start the local Podman Compose stack (docs/DEPLOYMENT.md).
#
# The stack is always composed from compose.yaml (core ATI services) plus
# compose.observability.yaml (the optional OpenTelemetry stack: Collector,
# Prometheus, Jaeger, Loki, Grafana, postgres-exporter). This mirrors the
# repository's pinned compose provider (podman-compose 1.0.6), which does
# not implement Compose `profiles:`.
#
# The script is idempotent: already-running healthy containers are left as
# they are (`up --no-recreate`). Every expected service is then health
# checked -- at the container level and, where the service exposes one, at
# the service level -- and unhealthy services are repaired when possible
# (restart/recreate/re-run). Every decision is logged. At the end the
# reachable endpoints are printed: HTTP services show the URL to their
# login/home page, everything else shows host:port or "internal".
#
#   ./start.sh            start (or verify) the full local stack
#   ./start.sh --teardown tear down all stack containers, delete their
#                         stored data (PostgreSQL, Prometheus, Loki,
#                         Grafana), then start a fresh stack
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage: ./start.sh [OPTION]

Start (and verify) the local ATI Podman Compose stack: core services plus
the observability stack (OpenTelemetry Collector, Prometheus, Jaeger, Loki,
Grafana, postgres-exporter).

The script is idempotent: already-running healthy containers are left as
they are. It checks the health of every expected container and service,
repairs unhealthy ones when possible, logs every decision, and prints the
reachable endpoints when done.

Options:
  -t, --teardown  Tear down all running stack containers and delete their
                  stored data (PostgreSQL data, Prometheus/Loki/Grafana
                  observability data), then start a fresh stack.
  -h, --help      Show this help message and exit.
USAGE
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
  -t | --teardown)
    TEARDOWN=1
    ;;
  "")
    TEARDOWN=0
    ;;
  *)
    echo "Unknown option: $1" >&2
    usage >&2
    exit 2
    ;;
esac
if [[ $# -gt 1 ]]; then
  echo "Unexpected argument: $2" >&2
  usage >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Tooling and environment resolution
# ---------------------------------------------------------------------------

command -v podman >/dev/null || { echo "podman is required; run ./install.sh" >&2; exit 1; }
# Prefer the native podman-compose provider: the `podman compose` wrapper may
# delegate to Docker Compose, which requires the Podman socket to be running
# and fails under rootless Podman when it is not.
if command -v podman-compose >/dev/null 2>&1; then
  COMPOSE=(podman-compose)
elif podman compose version >/dev/null 2>&1; then
  COMPOSE=(podman compose)
else
  echo "podman-compose (or podman compose with a working provider) is required; run ./install.sh" >&2
  exit 1
fi
COMPOSE_FILES=(-f compose.yaml -f compose.observability.yaml)

# Resolve a value with the same precedence Compose itself uses: process
# environment > .env > documented default. podman-compose 1.0.6 does not
# honour COMPOSE_PROJECT_NAME from .env, so the default project name is
# derived exactly the way podman-compose derives it (directory basename).
get_env() {
  local key="$1" default="${2:-}" value=""
  if [[ -n "${!key:-}" ]]; then
    printf '%s\n' "${!key}"
    return 0
  fi
  if [[ -f .env ]]; then
    value=$(sed -n "s/^${key}=//p" .env | tail -n 1)
    if [[ -n "$value" ]]; then
      printf '%s\n' "$value"
      return 0
    fi
  fi
  printf '%s\n' "$default"
}

require_env() {
  local key="$1"
  if [[ -z "$(get_env "$key")" ]]; then
    echo "error: ${key} is not set. Create a local .env from .env.example (see docs/DEPLOYMENT.md)." >&2
    exit 1
  fi
}

# The compose graph refuses to run without these; fail with a helpful
# message instead of an opaque podman-compose traceback.
require_env ATI_DATA_DIR
require_env POSTGRES_PASSWORD

PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$(basename "$ROOT_DIR")}"
ATI_DATA_DIR=$(get_env ATI_DATA_DIR)
# Host-published ports, matching compose.yaml / compose.observability.yaml
# defaults. API port 8000 is fixed in compose.yaml.
API_PORT=8000
FRONTEND_PORT=$(get_env ATI_FRONTEND_HOST_PORT 8080)
POSTGRES_PORT=$(get_env ATI_POSTGRES_HOST_PORT 54320)
REDPANDA_PORT=$(get_env ATI_REDPANDA_HOST_PORT 9092)
GRAFANA_PORT=$(get_env ATI_GRAFANA_HOST_PORT 3000)
PROMETHEUS_PORT=$(get_env ATI_PROMETHEUS_HOST_PORT 9090)
JAEGER_PORT=$(get_env ATI_JAEGER_HOST_PORT 16686)

# Image used as the disposable in-network HTTP probe for services that have
# no published host port and no shell inside their pinned image (the
# Collector and Loki are distroless). Grafana is part of this stack, so its
# image is always present once the stack image set has been pulled/built.
NET_PROBE_IMAGE=docker.io/grafana/grafana:13.2.2

# Wrap commands in coreutils `timeout` when available (universal on the
# supported Linux distributions) so a stuck probe can never hang the script.
TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_CMD=timeout; fi
run_with_timeout() {
  local secs="$1"
  shift
  if [[ -n "$TIMEOUT_CMD" ]]; then
    "$TIMEOUT_CMD" "$secs" "$@"
  else
    "$@"
  fi
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
step() { log "==> $*"; }
ok() { log "ok   $*"; }
warn() { log "warn $*"; }
err() { log "error $*"; }
# User-facing head-up before a potentially lengthy operation, with a
# duration estimate where one can be given.
note() { log "note $*"; }

# ---------------------------------------------------------------------------
# Stored data locations (docs/DEPLOYMENT.md "Persistent host root")
# ---------------------------------------------------------------------------

# Host directories that hold service-managed durable data. These are the
# ONLY paths start/stop scripts ever delete, and only under an explicit
# --teardown. Pre-existing operator artifacts under datasets/ are inputs,
# not service-managed data, and are never deleted.
DATA_STORES=(
  "${ATI_DATA_DIR}/postgres/data"
  "${ATI_DATA_DIR}/observability/prometheus"
  "${ATI_DATA_DIR}/observability/loki"
  "${ATI_DATA_DIR}/observability/grafana"
)

# Under rootless Podman the container users land in the host user's subuid
# range, so a host-created directory owned by the invoking user is not
# writable by the container process. The observability images run as
# non-root users (loki=10001, prometheus=nobody=65534, grafana=472) and
# fail with "permission denied" unless their data directory is
# world-writable. These directories hold only local monitoring data; making
# them world-writable is the standard local-developer fix. PostgreSQL is
# NOT touched: its entrypoint runs as root and sets its own ownership.
WORLD_WRITABLE_STORES=(
  "${ATI_DATA_DIR}/observability/prometheus"
  "${ATI_DATA_DIR}/observability/loki"
  "${ATI_DATA_DIR}/observability/grafana"
)

ensure_data_dirs() {
  local dir
  mkdir -p "$ATI_DATA_DIR/datasets"
  for dir in "${DATA_STORES[@]}"; do
    if [[ ! -d "$dir" ]]; then
      step "creating data directory: $dir"
      mkdir -p "$dir"
    fi
  done
  # Ensure the observability containers can write their data dirs (see
  # WORLD_WRITABLE_STORES above).
  for dir in "${WORLD_WRITABLE_STORES[@]}"; do
    chmod 1777 "$dir" 2>/dev/null || chmod 777 "$dir"
  done
}

# remove_tree <path>: delete a host directory tree that may contain files
# owned by container-mapped uids (rootless Podman subuid subrange). A plain
# host `rm -rf` fails on those files; `podman unshare` enters the same user
# namespace Podman uses for containers, where the invoking user is root
# over the whole subuid range.
remove_tree() {
  local path="$1"
  if [[ -e "$path" ]]; then
    step "deleting stored data: $path (--teardown)"
    podman unshare rm -rf "$path" || { err "could not delete $path"; return 1; }
  else
    log "no stored data to delete at $path"
  fi
  return 0
}

delete_data_dirs() {
  local dir
  for dir in "${DATA_STORES[@]}"; do
    remove_tree "$dir" || true
  done
}

# ---------------------------------------------------------------------------
# Compose and container helpers
# ---------------------------------------------------------------------------

compose_cmd() {
  "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" "$@"
}

# cid_for <service>: print the compose container id of a service (or empty).
cid_for() {
  local service="$1"
  podman ps -a \
    --filter "label=io.podman.compose.project=${PROJECT_NAME}" \
    --filter "label=com.docker.compose.service=${service}" \
    --format '{{.ID}}' | head -n 1
}

container_state() {
  local service="$1" cid
  cid=$(cid_for "$service")
  [[ -n "$cid" ]] || { printf '%s\n' missing; return 0; }
  podman inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || printf '%s\n' unknown
}

# resolve_compose_network: name of the project's compose network, derived
# from a running project container (authoritative under rootless Podman).
COMPOSE_NETWORK=""
resolve_compose_network() {
  local cid
  cid=$(podman ps -a --filter "label=io.podman.compose.project=${PROJECT_NAME}" --format '{{.ID}}' | head -n 1)
  [[ -n "$cid" ]] || return 1
  COMPOSE_NETWORK=$(podman inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$cid" | tr ' ' '\n' | grep -v '^$' | head -n 1)
  [[ -n "$COMPOSE_NETWORK" ]]
}

# ---------------------------------------------------------------------------
# Health probes
# ---------------------------------------------------------------------------

# http_probe <url>: 0 when the endpoint answers 2xx/3xx.
http_probe() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS --max-time 5 -o /dev/null "$url" 2>/dev/null
  else
    python3 - "$url" <<'PY'
import sys
import urllib.request

try:
    urllib.request.urlopen(sys.argv[1], timeout=5).read()
except Exception:
    raise SystemExit(1)
PY
  fi
}

# net_probe <url>: probe an in-Compose-network HTTP endpoint from a
# disposable container joined to the project network. Needed for services
# whose pinned image has no shell (Collector, Loki) and no published port.
net_probe() {
  local url="$1"
  [[ -n "$COMPOSE_NETWORK" ]] || { warn "project network unknown; cannot probe $url"; return 1; }
  run_with_timeout 30 podman run --rm --network "$COMPOSE_NETWORK" \
    --entrypoint /usr/bin/wget "$NET_PROBE_IMAGE" \
    -q -O /dev/null --timeout=5 --tries=1 "$url" 2>/dev/null
}

# tcp_probe <host> <port>: 0 when the TCP port accepts connections.
tcp_probe() {
  local host="$1" port="$2"
  run_with_timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null
}

# one_shot_status <service>: 0=exited 0, 1=exited nonzero (or missing),
# 2=not finished yet (running, or accepted by Podman but not started
# yet -- "created"/"configured"/transient states are NOT failures; the
# initial podman start queues containers in dependency order), 3=container
# missing.
one_shot_status() {
  local service="$1" cid state code
  cid=$(cid_for "$service")
  [[ -n "$cid" ]] || return 3
  state=$(podman inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)
  code=$(podman inspect -f '{{.State.ExitCode}}' "$cid" 2>/dev/null || true)
  case "$state" in
    running) return 2 ;;
    exited)
      [[ "$code" == "0" ]] && return 0 || return 1
      ;;
    # Podman has the container but it has not run yet (freshly created, or
    # queued behind an earlier start in the same `podman start` call). Keep
    # waiting: the caller bounds the wait.
    *)
      return 2
      ;;
  esac
}

wait_one_shot() {
  local service="$1" timeout_s="${2:-300}" deadline now rc
  deadline=$(($(date +%s) + timeout_s))
  while :; do
    one_shot_status "$service"
    rc=$?
    [[ "$rc" -eq 2 ]] || return "$rc" # 0 done, 1 failed, 3 missing
    now=$(date +%s)
    [[ "$now" -ge "$deadline" ]] && return 2
    sleep 2
  done
}

# Service-specific readiness probes (return 0 = ready). Container
# running-state is checked separately by daemon_healthy.
probe_postgres() {
  local cid status
  cid=$(cid_for postgres)
  [[ -n "$cid" ]] || return 1
  status=$(podman inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || true)
  if [[ "$status" == healthy ]]; then
    return 0
  fi
  # Fallback: the published port accepts a pg wire connection.
  tcp_probe 127.0.0.1 "$POSTGRES_PORT"
}

probe_redpanda() {
  local cid
  cid=$(cid_for redpanda)
  [[ -n "$cid" ]] || return 1
  # Authoritative broker readiness through the pinned image's own rpk.
  if run_with_timeout 30 podman exec "$cid" rpk cluster health >/dev/null 2>&1; then
    return 0
  fi
  # Fallback: broker listener on the published port accepts TCP.
  tcp_probe 127.0.0.1 "$REDPANDA_PORT"
}

probe_api() { http_probe "http://127.0.0.1:${API_PORT}/health/ready"; }
probe_frontend() { http_probe "http://127.0.0.1:${FRONTEND_PORT}/"; }
probe_grafana() { http_probe "http://127.0.0.1:${GRAFANA_PORT}/login"; }
probe_prometheus() { http_probe "http://127.0.0.1:${PROMETHEUS_PORT}/-/healthy"; }
probe_jaeger() { http_probe "http://127.0.0.1:${JAEGER_PORT}/"; }
probe_otel_collector() { net_probe "http://otel-collector:13131/"; }
probe_loki() { net_probe "http://loki:3100/ready"; }
probe_postgres_exporter() { net_probe "http://postgres-exporter:9187/metrics"; }
# worker and geo-resolver expose no HTTP boundary; their service health is
# their container running-state (checked by daemon_healthy).
probe_worker() { return 0; }
probe_geo_resolver() { return 0; }

# daemon_healthy <service>: container running AND service probe ok. Probe
# function names cannot contain hyphens, so the service name is normalized
# (geo-resolver -> probe_geo_resolver).
daemon_healthy() {
  local service="$1"
  [[ "$(container_state "$service")" == running ]] || return 1
  "probe_${service//-/_}"
}

# ---------------------------------------------------------------------------
# Start / repair helpers
#
# podman-compose 1.0.6 stamps every created container with `--requires`
# edges to its compose dependencies; `podman start` then rejects any
# container whose dependency closure is not fully present in the *same*
# start call (the documented scripts/e2e.sh "depends on container ... not
# found in input list" failure). All starts therefore use ONE `podman
# start` over the entire project container set -- running containers in the
# list are no-ops, so already-running services are left exactly as they
# are. `podman restart` has the same restriction because exited one-shot
# dependencies count as "not started", so daemon repairs stop the target
# and re-run the full-closure start. Container creation uses `up --no-start`
# (create only, no dependency-aware start).
# ---------------------------------------------------------------------------

# podman_start_project: start every project container in a single call.
podman_start_project() {
  local cids
  cids=$(podman ps -a --filter "label=io.podman.compose.project=${PROJECT_NAME}" --format '{{.ID}}' | tr '\n' ' ')
  if [[ -z "${cids// /}" ]]; then
    warn "no project containers to start"
    return 1
  fi
  step "starting project containers (single podman start; already-running ones are left as-is)"
  # shellcheck disable=SC2086
  podman start $cids >/dev/null 2>&1 || warn "podman start reported a problem for one or more containers"
}

repair_create() {
  local service="$1"
  step "repair: creating missing service: $service"
  compose_cmd up --no-start --no-recreate "$service" >/dev/null 2>&1 || true
  podman_start_project
}

repair_restart() {
  local service="$1" cid
  cid=$(cid_for "$service")
  if [[ -n "$cid" ]]; then
    step "repair: stopping + restarting $service"
    # podman restart refuses when one-shot dependencies have exited; stop
    # the target, then let the full-closure start bring it back up.
    podman stop --timeout 30 "$cid" >/dev/null 2>&1 || true
    podman_start_project
  else
    repair_create "$service"
  fi
}

repair_one_shot() {
  local service="$1" cid
  cid=$(cid_for "$service")
  if [[ -z "$cid" ]]; then
    step "repair: creating missing one-shot service: $service"
    compose_cmd up --no-start --no-recreate "$service" >/dev/null 2>&1 || true
  fi
  step "repair: re-running one-shot service: $service"
  podman_start_project
}

# ---------------------------------------------------------------------------
# Health verification with repair
# ---------------------------------------------------------------------------

daemon_deadline_seconds() {
  case "$1" in
    api) printf '%s\n' 420 ;;       # waits on migrate + fake-data bootstrap
    postgres) printf '%s\n' 600 ;;  # cold init + health-check warm-up
    *) printf '%s\n' 300 ;;
  esac
}

# health_check_daemon <service>: wait (bounded) for the service to become
# healthy, then attempt exactly ONE repair if it never did, wait a short
# bounded grace period, and report success or failure. Repair loops are
# deliberately bounded: a service with an environmental problem (for
# example a missing required secret) must never be restarted forever.
health_check_daemon() {
  local service="$1"
  local deadline now
  deadline=$(($(date +%s) + $(daemon_deadline_seconds "$service")))
  # Phase 1: wait for readiness without repairing (a cold start may simply
  # be slow: image startup, migrations, bootstrap).
  until daemon_healthy "$service"; do
    now=$(date +%s)
    ((now < deadline)) || break
    sleep 3
  done
  if daemon_healthy "$service"; then
    ok "$service: healthy"
    return 0
  fi
  # Phase 2: exactly one repair attempt.
  case "$(container_state "$service")" in
    missing | created)
      warn "$service: container is '$(container_state "$service")'; one repair attempt (create/start)"
      repair_create "$service"
      ;;
    *)
      warn "$service: container is '$(container_state "$service")'; one repair attempt (restart)"
      repair_restart "$service"
      ;;
  esac
  # Phase 3: bounded grace period after the single repair.
  deadline=$(($(date +%s) + 90))
  until daemon_healthy "$service"; do
    now=$(date +%s)
    ((now < deadline)) || break
    sleep 3
  done
  if daemon_healthy "$service"; then
    ok "$service: healthy after one repair"
    return 0
  fi
  err "$service: NOT healthy after one repair attempt (container state: $(container_state "$service")); see its logs: podman logs $(cid_for "$service")"
  return 1
}

# health_check_one_shot <service>: wait (bounded) for the one-shot to
# complete with exit code 0; attempt exactly ONE re-run on failure and
# report success or failure.
health_check_one_shot() {
  local service="$1"
  if wait_one_shot "$service" 300; then
    ok "$service: completed (exit 0)"
    return 0
  fi
  warn "$service: did not complete (exit code $(podman inspect -f '{{.State.ExitCode}}' "$(cid_for "$service")" 2>/dev/null || echo '?') ); one repair attempt (re-run)"
  repair_one_shot "$service"
  if wait_one_shot "$service" 300; then
    ok "$service: completed after one re-run (exit 0)"
    return 0
  fi
  err "$service: still did not complete after one re-run"
  return 1
}

# ---------------------------------------------------------------------------
# Teardown (used by --teardown in start.sh and by stop.sh --teardown)
# ---------------------------------------------------------------------------

# tear_down: stop and remove every stack container plus named/anonymous
# project volumes, then delete the service-managed stored data.
tear_down() {
  step "tearing down compose project: $PROJECT_NAME"
  if compose_cmd down --remove-orphans --volumes --timeout 30 >/dev/null 2>&1; then
    ok "compose project torn down (containers removed)"
  else
    warn "compose down reported a problem; continuing (containers may already be gone)"
  fi
  delete_data_dirs
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

# endpoint_for <service>: line printed in the final summary. HTTP services
# show the URL to their login/home page; others host:port or "internal".
endpoint_for() {
  case "$1" in
    postgres) printf 'localhost:%s (PostgreSQL 18 + pgvector + PostGIS)\n' "$POSTGRES_PORT" ;;
    redpanda) printf 'localhost:%s (Kafka-compatible broker)\n' "$REDPANDA_PORT" ;;
    migrate | fake-data-bootstrap | scheduler) printf 'one-shot (no persistent endpoint)\n' ;;
    api) printf 'http://localhost:%s/docs (FastAPI; health: /health/ready)\n' "$API_PORT" ;;
    worker) printf 'internal (no host port; investigation worker)\n' ;;
    geo-resolver) printf 'internal (no host port; geographic resolution worker)\n' ;;
    frontend) printf 'http://localhost:%s/ (application login/home)\n' "$FRONTEND_PORT" ;;
    otel-collector) printf 'internal (OTLP gateway; health http://otel-collector:13131/)\n' ;;
    prometheus) printf 'http://localhost:%s/ (metrics UI)\n' "$PROMETHEUS_PORT" ;;
    jaeger) printf 'http://localhost:%s/ (trace search UI)\n' "$JAEGER_PORT" ;;
    loki) printf 'internal (log backend; readiness http://loki:3100/ready)\n' ;;
    grafana) printf 'http://localhost:%s/login (dashboards; local admin admin/admin by default)\n' "$GRAFANA_PORT" ;;
    postgres-exporter) printf 'internal (metrics http://postgres-exporter:9187/metrics)\n' ;;
    *) printf 'internal\n' ;;
  esac
}

final_status() {
  local service="$1" rc
  case "$service" in
    migrate | fake-data-bootstrap | scheduler)
      # `||` protects the caller from set -e: one_shot_status is allowed to
      # fail (a completed one-shot is rc 0, anything else is not).
      one_shot_status "$service" && rc=0 || rc=$?
      case "$rc" in
        0) printf 'completed\n' ;;
        2) printf 'running\n' ;;
        3) printf 'missing\n' ;;
        *) printf 'failed\n' ;;
      esac
      ;;
    *)
      if daemon_healthy "$service"; then printf 'healthy\n'; else printf 'unhealthy\n'; fi
      ;;
  esac
}

print_summary() {
  local service status lines=0
  step "service summary (project: $PROJECT_NAME)"
  for service in postgres redpanda migrate fake-data-bootstrap api worker geo-resolver scheduler frontend otel-collector prometheus jaeger loki grafana postgres-exporter; do
    status=$(final_status "$service")
    printf '  %-20s %-10s %s\n' "$service" "$status" "$(endpoint_for "$service")"
    [[ "$status" == healthy || "$status" == completed ]] || lines=$((lines + 1))
  done
  if ((lines > 0)); then
    err "some services are not healthy; see the log above for repair attempts"
  else
    ok "all expected services are healthy"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

DAEMON_SERVICES=(postgres redpanda api worker geo-resolver frontend otel-collector prometheus jaeger loki grafana postgres-exporter)
ONE_SHOT_SERVICES=(migrate fake-data-bootstrap scheduler)

# stack_already_up: true when every daemon is running and every one-shot
# has already completed -- the fully idempotent no-op case, where the start
# phase is skipped entirely and nothing is disturbed.
stack_already_up() {
  local service state
  for service in "${DAEMON_SERVICES[@]}"; do
    state=$(container_state "$service")
    [[ "$state" == running ]] || return 1
  done
  for service in "${ONE_SHOT_SERVICES[@]}"; do
    one_shot_status "$service" || return 1
  done
  return 0
}

if ((TEARDOWN)); then
  step "teardown requested: removing stack and stored data before starting"
  note "Teardown stops every container with a 30s grace period each; allow up to ~2 minutes, plus data deletion."
  tear_down
fi

ensure_data_dirs

EXPECTED_SERVICES=(postgres redpanda migrate fake-data-bootstrap api worker geo-resolver scheduler frontend otel-collector prometheus jaeger loki grafana postgres-exporter)

containers_exist_for_all() {
  local service
  for service in "${EXPECTED_SERVICES[@]}"; do
    [[ -n "$(cid_for "$service")" ]] || return 1
  done
  return 0
}

if containers_exist_for_all; then
  log "all expected containers already exist; skipping the create phase"
else
  EXISTING_CONTAINERS=$(podman ps -a --filter "label=io.podman.compose.project=${PROJECT_NAME}" --format '{{.ID}}' | sed '/^$/d' | wc -l)
  if ((EXISTING_CONTAINERS == 0)); then
    note "Starting containers from a clean slate. This operation might take 3-5 minutes or longer: the first run also builds the backend, PostgreSQL, and frontend images (requires network access)."
  else
    note "Starting containers. This operation might take a while."
  fi
  step "creating compose project containers: $PROJECT_NAME (compose.yaml + compose.observability.yaml)"
  # Create-only: `up --no-start` builds/pulls missing images (first run) and
  # creates every container without podman-compose's dependency-aware start.
  # Start uses a single plain `podman start` over the full project set (see
  # the podman_start_project comment).
  # Full create output is shown (first run builds images) and mirrored to a
  # log for diagnosis; set -o pipefail makes the compose exit code win.
  if ! compose_cmd up --no-start --no-recreate --remove-orphans 2>&1 | tee /tmp/ati-start-create.log; then
    err "container creation failed (image build/pull problem); see /tmp/ati-start-create.log, check podman and the .env configuration (docs/DEPLOYMENT.md)"
    exit 1
  fi
  ok "all expected containers are created (running containers left as they are)"
fi

if ! resolve_compose_network; then
  warn "could not determine the compose network name; in-network health probes are unavailable"
fi

if stack_already_up; then
  step "entire stack is already up and consistent; leaving every container as-is"
else
  note "Starting containers. This operation might take a while (typically ~1-2 minutes; a few minutes when the database data directory is fresh)."
  podman_start_project
fi

step "waiting for PostgreSQL readiness (migrations need a working database)"
note "PostgreSQL is polled until it accepts connections (up to 5 minutes; ~20-40s on a fresh data directory)."
POSTGRES_DEADLINE=$(($(date +%s) + 300))
until probe_postgres; do
  [[ $(date +%s) -lt "$POSTGRES_DEADLINE" ]] || { err "PostgreSQL did not become ready in time"; break; }
  sleep 3
done

step "running one-shot services to completion (migrations, fake-data bootstrap)"
note "One-shot services re-run deterministically on every start; migrations take seconds and the fake-data bootstrap typically ~10-60s, occasionally a few minutes."
OVERALL=0
health_check_one_shot migrate || OVERALL=1
health_check_one_shot fake-data-bootstrap || OVERALL=1
health_check_one_shot scheduler || OVERALL=1

step "checking and repairing container/service health"
for service in "${DAEMON_SERVICES[@]}"; do
  health_check_daemon "$service" || OVERALL=1
done

print_summary

exit "$OVERALL"
