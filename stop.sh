#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# stop.sh -- stop the local Podman Compose stack (docs/DEPLOYMENT.md).
#
# The stack is always the compose.yaml (core ATI services) plus
# compose.observability.yaml (OpenTelemetry stack) composition used by
# start.sh. Stopping is scoped to this compose project; unrelated containers
# are never touched.
#
#   ./stop.sh            stop all stack containers (containers and stored
#                        data are kept; ./start.sh resumes them)
#   ./stop.sh --teardown stop and REMOVE every stack container and delete
#                        the service-managed stored data (PostgreSQL,
#                        Prometheus, Loki, Grafana). Destructive -- requires
#                        explicit intent.
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage: ./stop.sh [OPTION]

Stop the local ATI Podman Compose stack: core services plus the
observability stack (OpenTelemetry Collector, Prometheus, Jaeger, Loki,
Grafana, postgres-exporter).

Options:
  -t, --teardown  Stop and remove every stack container and delete their
                  stored data (PostgreSQL data, Prometheus/Loki/Grafana
                  observability data). This is destructive and cannot be
                  undone.
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
# environment > .env > documented default.
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

# The compose graph refuses to parse without these; fail with a helpful
# message instead of an opaque podman-compose traceback.
require_env ATI_DATA_DIR
require_env POSTGRES_PASSWORD

PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$(basename "$ROOT_DIR")}"
ATI_DATA_DIR=$(get_env ATI_DATA_DIR)

# Service-managed durable host directories -- the ONLY paths this script
# ever deletes, and only under an explicit --teardown. Operator artifacts
# under datasets/ are inputs and are never deleted.
DATA_STORES=(
  "${ATI_DATA_DIR}/postgres/data"
  "${ATI_DATA_DIR}/observability/prometheus"
  "${ATI_DATA_DIR}/observability/loki"
  "${ATI_DATA_DIR}/observability/grafana"
)

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
step() { log "==> $*"; }
ok() { log "ok   $*"; }
warn() { log "warn $*"; }
err() { log "error $*"; }
# User-facing head-up before a potentially lengthy operation, with a
# duration estimate where one can be given.
note() { log "note $*"; }

compose_cmd() {
  "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" "$@"
}

# Stop every stack container. Containers and stored data are preserved, so
# ./start.sh can resume the same stack. podman-compose chatter (resolved
# config dump, per-container commands) is suppressed; failures surface the
# tail of the log.
stop_stack() {
  step "stopping compose project: $PROJECT_NAME"
  note "Stopping all stack containers. This usually takes ~10-60s, but each long-running worker is given a 30s grace period before being killed, so allow up to ~2 minutes."
  if compose_cmd stop --timeout 30 >/tmp/ati-stop.log 2>&1; then
    ok "all stack containers stopped (containers and data preserved)"
  else
    tail -n 20 /tmp/ati-stop.log >&2 || true
    warn "compose stop reported a problem; verify with ./start.sh"
    return 1
  fi
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

# Stop and remove every stack container plus named/anonymous project
# volumes, then delete the service-managed stored data.
tear_down() {
  local dir
  step "tearing down compose project: $PROJECT_NAME"
  note "Tearing down the stack and deleting stored data. Stopping can take up to ~2 minutes (30s grace per container); data deletion itself is usually fast."
  if compose_cmd down --remove-orphans --volumes --timeout 30 >/tmp/ati-stop.log 2>&1; then
    ok "compose project torn down (containers removed)"
  else
    tail -n 20 /tmp/ati-stop.log >&2 || true
    warn "compose down reported a problem; continuing (containers may already be gone)"
  fi
  for dir in "${DATA_STORES[@]}"; do
    remove_tree "$dir" || true
  done
  ok "teardown complete"
}

if ((TEARDOWN)); then
  tear_down
else
  stop_stack
fi
