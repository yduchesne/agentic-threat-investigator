#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
# OpenCTI interoperability harness (PR 33E section 10).
#
# This is the separate, explicit interoperability gate: a real OpenCTI 6.9
# stack (pinned images) + ATI PostgreSQL + ATI Redpanda, seeded with an
# ATI-authored deterministic STIX fake world, consumed through OpenCTI's real
# TAXII 2.1 collection by the production Taxii21Datasource, published through
# real Redpanda, and persisted through the real consumer into PostgreSQL.
# It is NOT part of ./build.sh --intg and ordinary CI stays independent.
#
# Orchestration (section 10.9) is owned end to end:
#   start isolated topology -> wait infra -> bootstrap OpenCTI collection/auth
#   -> seed deterministic fixtures -> wait OpenCTI feed convergence
#   -> run ATI TAXII ingestion -> wait the ingestion-completion barrier
#   -> only after READY_FOR_ASSERTIONS: run interop assertions
#   -> collect success evidence -> teardown
#
# Usage:
#   ./scripts/opencti-integration.sh [--keep-on-failure] [--incremental] [--timeout N]
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
INCREMENTAL=0
TIMEOUT_SECONDS=3600
while [ $# -gt 0 ]; do
  case "$1" in
    --keep-on-failure) KEEP_ON_FAILURE=1; shift ;;
    --incremental) INCREMENTAL=1; shift ;;
    --timeout) TIMEOUT_SECONDS="$2"; shift 2 ;;
    -h|--help) sed -n '1,30p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

COMPOSE_FILE="tests/interop/opencti/compose.yaml"
RUN_ID="opencti-interop-$(date +%s)-$$"
ARTIFACT_DIR="artifacts/opencti-interop/$RUN_ID"
mkdir -p "$ARTIFACT_DIR"
export COMPOSE_PROJECT_NAME="$RUN_ID"

# Synthetic random credentials used only inside this isolated harness run.
gen_password() { openssl rand -hex 16 2>/dev/null || printf 'ati-interop-only'; }
gen_admin_token() {
  # OpenCTI 6.9 validates APP__ADMIN__TOKEN against a strict UUIDv4 grammar.
  uv run python -c 'import sys, uuid; sys.stdout.write(str(uuid.uuid4()))'
}
export ATI_INTEROP_PGUSER=ati
export ATI_INTEROP_DB="ati_interop_${RUN_ID##*-}"
export ATI_INTEROP_PGPASSWORD="$(gen_password)"
export ATI_INTEROP_RABBIT_USER=ati
export ATI_INTEROP_RABBIT_PASS="$(gen_password)"
export ATI_INTEROP_S3_PASS="$(gen_password)"
export ATI_INTEROP_OPENCTI_ADMIN_PASS="OpenCTI-Interop-Admin-$(gen_password)"
export ATI_INTEROP_OPENCTI_ADMIN_TOKEN="$(gen_admin_token)"
export ATI_INTEROP_CONNECTOR_ID="$(gen_admin_token)"
export ATI_INTEROP_ENCRYPTION_KEY="$(gen_password)"
export ATI_INTEROP_PG_PORT=$((62000 + RANDOM % 1000))
export ATI_INTEROP_REDPANDA_PORT=$((61000 + RANDOM % 900))
export ATI_INTEROP_OPENCTI_PORT=$((63000 + RANDOM % 1000))
export ATI_INTEROP_TAXII_TLS_PORT=$((64000 + RANDOM % 1000))
export ATI_INTEROP_RABBITMQ_MANAGEMENT_PORT=$((65100 + RANDOM % 400))
# Range 65100..65499 keeps the published host port below the 65535 bound
# (a ``65000 + RANDOM % 999`` form can exceed the valid port space and make
# Podman reject the rabbitmq mapping, which silently cascades into a
# skipped OpenCTI stack).
export ATI_INTEROP_RABBITMQ_API_URL="http://127.0.0.1:${ATI_INTEROP_RABBITMQ_MANAGEMENT_PORT}"
# Elasticsearch is also published per run so the PR 33E-1 Option C identity
# resolution can read OpenCTI's durable materialization state from the host.
# Range 65000..65099 keeps the published host port below the 65535 bound
# (a ``66000 + RANDOM % 500`` form can exceed the valid port space: Podman
# rejects it with ``parsing host port: port numbers must be between 1 and
# 65535``, which silently cascades into a skipped OpenCTI stack) and disjoint
# from the RabbitMQ management band 65100..65499.
export ATI_INTEROP_ES_PORT=$((65000 + RANDOM % 100))
# RabbitMQ management API reachable from the host so the seeder can wait for
# the worker's push-queue consumer before seeding (PR 33E-1 worker-mailbox
# gate); the synthetic random credentials already live in ATI_INTEROP_RABBIT_*.

echo "== OpenCTI interop run $RUN_ID =="
echo "artifacts: $ARTIFACT_DIR"

# TLS certificate for the ATI HTTPS client (validate_provider_url requires
# credential-free HTTPS; the driver verifies this generated CA).
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$ARTIFACT_DIR/tls-key.pem" -out "$ARTIFACT_DIR/tls-cert.pem" \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
cat > "$ARTIFACT_DIR/nginx.conf" <<'NGINX'
server {
  listen 443 ssl;
  ssl_certificate /etc/nginx/tls/tls-cert.pem;
  ssl_certificate_key /etc/nginx/tls/tls-key.pem;
  location / {
    proxy_pass http://opencti-platform:8080;
    proxy_set_header Host $host;
  }
}
NGINX
export ATI_INTEROP_TLS_DIR="$PWD/$ARTIFACT_DIR"
export ATI_INTEROP_NGINX_CONF="$PWD/$ARTIFACT_DIR/nginx.conf"

fail() {
  echo "== Interop failure: $1 ==" >&2
  exit 1
}

# Write deterministic run state + manifests the tooling consumes.
# ``seed_accepted`` is updated again by the seeder's own state merge so the
# work-id/connector metadata recorded after seeding is never clobbered.
write_state() {
  cat > "$ARTIFACT_DIR/run-state.json" <<STATE
{
  "run_id": "$RUN_ID",
  "seed_accepted": $1,
  "ati_git_sha": "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)",
  "pinned_images": {
    "opencti/platform": "6.9.29",
    "opencti/worker": "6.9.29",
    "opencti/connector-import-file-stix": "6.9.29",
    "redis": "8.10.1",
    "elasticsearch": "8.19.21",
    "rabbitmq": "4.3-management",
    "nginx": "1.27.5",
    "seaweedfs": "4.48"
  },
  "manifest": "$ARTIFACT_DIR/manifest-v1.json"
}
STATE
}
write_state false

# Record the resolved immutable image digests actually used by this run
# (diagnostic metadata only; never a new production dependency).
record_image_digests() {
  uv run python - "$ARTIFACT_DIR" <<'PY'
import json, subprocess, sys
from pathlib import Path
state_dir = Path(sys.argv[1])
path = state_dir / "run-state.json"
state = json.loads(path.read_text())
pinned = state.get("pinned_images") or {}
byname = {
    "opencti/platform": "docker.io/opencti/platform:6.9.29",
    "opencti/worker": "docker.io/opencti/worker:6.9.29",
    "opencti/connector-import-file-stix": "docker.io/opencti/connector-import-file-stix:6.9.29",
    "redis": "docker.io/library/redis:8.10.1",
    "elasticsearch": "docker.elastic.co/elasticsearch/elasticsearch:8.19.21",
    "rabbitmq": "docker.io/library/rabbitmq:4.3-management",
    "nginx": "docker.io/library/nginx:1.27.5",
    "seaweedfs": "docker.io/chrislusf/seaweedfs:4.48",
}
digests = {}
for name, image in byname.items():
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
uv run python - "$ARTIFACT_DIR" <<'PY'
import json, sys
from tests.interop.opencti.fixtures.opencti_fake_world import (
    expected_manifest_v1,
    expected_manifest_v2,
)
Path = __import__("pathlib").Path
out = Path(sys.argv[1])
out.joinpath("manifest-v1.json").write_text(json.dumps(expected_manifest_v1(), indent=2))
out.joinpath("manifest-v2.json").write_text(json.dumps(expected_manifest_v2(), indent=2))
PY

teardown() {
  "${COMPOSE[@]}" -f "$COMPOSE_FILE" -p "$RUN_ID" down -v --remove-orphans >/dev/null 2>&1 || true
}

cleanup() {
  if [ "${_DONE:-0}" != "1" ]; then
    # Unexpected termination (or an explicit fail()): never let the async
    # readiness race into assertions; collect bounded diagnostics instead.
    echo "== Collecting diagnostics for partial run $RUN_ID ==" >&2
    uv run python -m tests.interop.opencti.status \
      --run-id "$RUN_ID" --state-dir "$ARTIFACT_DIR" \
      --manifest "$ARTIFACT_DIR/manifest-v1.json" --diagnose >/dev/null 2>&1 || true
    if [ "$KEEP_ON_FAILURE" = "1" ]; then
      echo "topology retained for inspection (project $RUN_ID); run" >&2
      echo "podman compose -f $COMPOSE_FILE -p $RUN_ID down -v" >&2
    else
      teardown
    fi
  else
    teardown
  fi
}
trap cleanup EXIT

echo "== Starting isolated topology (PostgreSQL, Redpanda, OpenCTI stack) =="
# Work around podman-compose 1.0.6 fragility: the multi-service ``up -d``
# dependency graph is unreliable here ("container ... depends on container ...
# not found in input list"), so services are started one at a time in
# dependency order after removing any stale containers this project label
# owns. ``restart: always`` (set per service) absorbs startup races with
# Elasticsearch/RabbitMQ/SeaweedFS: podman-compose 1.0.6 ignores
# ``condition: service_healthy`` dependency gating.
for stale in $(podman ps -aq --filter "label=io.podman.compose.project=${RUN_ID}" 2>/dev/null); do
  podman rm -f "$stale" >/dev/null 2>&1 || true
done
# Clean up any leftover containers from PREVIOUS interop runs: every
# ``opencti-interop-*`` Compose project is owned exclusively by this harness
# (per-run unique IDs), and podman-compose 1.0.6 matches existing containers
# by config-hash, which collides across runs.
cleanup_stale_interop_containers() {
  # Rootless Podman enforces container removal order (dependents first), so a
  # single ``podman rm -f`` pass can silently skip stale containers and leave
  # a previous interop topology running. Stop everything owned by the harness
  # first, then retry the removal set until nothing of ours remains or the
  # bounded pass count is exhausted.
  local container project remaining pass
  for container in $(podman ps -aq --filter label=io.podman.compose.project 2>/dev/null); do
    project=$(podman inspect --format '{{ index .Config.Labels "io.podman.compose.project" }}' "$container" 2>/dev/null || true)
    case "$project" in
      opencti-interop-*)
        podman stop -t 5 "$container" >/dev/null 2>&1 || true
        ;;
    esac
  done
  for pass in 1 2 3 4 5; do
    for container in $(podman ps -aq --filter label=io.podman.compose.project 2>/dev/null); do
      project=$(podman inspect --format '{{ index .Config.Labels "io.podman.compose.project" }}' "$container" 2>/dev/null || true)
      case "$project" in
        opencti-interop-*)
          podman rm -f "$container" >/dev/null 2>&1 || true
          ;;
      esac
    done
    remaining=$(podman ps -aq --filter label=io.podman.compose.project 2>/dev/null | while read -r c; do
      podman inspect --format '{{ index .Config.Labels "io.podman.compose.project" }}' "$c" 2>/dev/null || true
    done | grep -c '^opencti-interop-' || true)
    [ "${remaining:-0}" -eq 0 ] && break
  done
  for network in $(podman network ls --quiet | grep '^opencti-interop' || true); do
    podman network rm -f "$network" >/dev/null 2>&1 || true
  done
  for volume in $(podman volume ls --quiet | grep '^opencti-interop' || true); do
    podman volume rm -f "$volume" >/dev/null 2>&1 || true
  done
}

cleanup_stale_interop_containers

for service in \
  ati-postgres ati-redpanda \
  redis elasticsearch rabbitmq seaweedfs \
  opencti-platform opencti-worker opencti-import-stix opencti-tls; do
  "${COMPOSE[@]}" -f "$COMPOSE_FILE" -p "$RUN_ID" up -d "$service" \
    || fail "podman-compose could not start $service"
done
record_image_digests

# podman-compose 1.0.6 reports exit 0 even when a service container was not
# created (e.g. an invalid port mapping or a dependency that failed to
# start); fail fast with a bounded message instead of entering the long
# OpenCTI health wait with a missing platform. Podman's ps template has no
# ``.Label`` field, so the check matches the known container names of this
# harness-owned project.
missing=0
for service in \
  ati-postgres ati-redpanda \
  redis elasticsearch rabbitmq seaweedfs \
  opencti-platform opencti-worker opencti-import-stix opencti-tls; do
  podman ps -a --filter "label=io.podman.compose.project=${RUN_ID}" \
    --format '{{.Names}}' 2>/dev/null \
    | grep -qx "${RUN_ID}_${service}_1" || { echo "service $service was not started by podman-compose" >&2; missing=1; }
done
[ "$missing" = "0" ] || fail "the isolated topology did not fully start"

echo "== Applying ATI Alembic migrations on the isolated PostgreSQL =="
DATABASE_URL="postgresql+psycopg://${ATI_INTEROP_PGUSER}:${ATI_INTEROP_PGPASSWORD}@127.0.0.1:${ATI_INTEROP_PG_PORT}/${ATI_INTEROP_DB}" \
  uv run alembic upgrade head
export DATABASE_URL="postgresql+psycopg://${ATI_INTEROP_PGUSER}:${ATI_INTEROP_PGPASSWORD}@127.0.0.1:${ATI_INTEROP_PG_PORT}/${ATI_INTEROP_DB}"
export ATI_EVIDENCE_KAFKA_BOOTSTRAP="127.0.0.1:${ATI_INTEROP_REDPANDA_PORT}"
export ATI_EVIDENCE_KAFKA_BOOTSTRAP_SERVERS="127.0.0.1:${ATI_INTEROP_REDPANDA_PORT}"

echo "== Waiting for OpenCTI API readiness =="
OPENCTI_READY=0
HEALTH_URL="http://127.0.0.1:${ATI_INTEROP_OPENCTI_PORT}/health?health_access_key=interop-health"
for _ in $(seq 1 180); do
  if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
    OPENCTI_READY=1; break
  fi
  sleep 5
done
[ "$OPENCTI_READY" = "1" ] || fail "OpenCTI API did not become healthy in time"

echo "== Seeding deterministic fake world into real OpenCTI (stage v1) =="
export ATI_INTEROP_TOKEN_FILE="$ARTIFACT_DIR/ati-consumer-token"
SEEDER_JSON=$(OPENCTI_API_URL="http://127.0.0.1:${ATI_INTEROP_OPENCTI_PORT}" \
  OPENCTI_ADMIN_TOKEN="$ATI_INTEROP_OPENCTI_ADMIN_TOKEN" \
  SEED_STAGE=v1 uv run python -m tests.interop.opencti.seed_opencti)
# Merge the seeder's work/connector correlation metadata into run-state.json
# (the seeder never prints credentials, only bounded import-job ids).
uv run python - "$ARTIFACT_DIR" "$SEEDER_JSON" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1]) / "run-state.json"
state = json.loads(path.read_text())
seeder = json.loads(sys.argv[2])
for key, value in seeder.items():
    if key != "collection_id":
        state[key] = value
state["seed_accepted"] = True
path.write_text(json.dumps(state, indent=2))
PY
COLLECTION_ID=$(printf '%s' "$SEEDER_JSON" | uv run python -c 'import json,sys; print(json.load(sys.stdin)["collection_id"])')
[ -n "$COLLECTION_ID" ] || fail "seeder did not report a TAXII collection id"
# The incremental v2 seed reuses this collection (and its objects) instead of
# attempting to create a second one.
export OPENCTI_TAXII_COLLECTION_ID="$COLLECTION_ID"
TAXII_URL="https://127.0.0.1:${ATI_INTEROP_TAXII_TLS_PORT}/taxii2/root/collections/${COLLECTION_ID}/objects/"
echo "TAXII collection: $TAXII_URL"

# Restricted consumer bearer token: written by the seeder to a 0600 file and
# read here into the ATI driver environment (never printed, never logged).
ATI_TAXII_TOKEN=$(cat "$ATI_INTEROP_TOKEN_FILE" 2>/dev/null || echo "$ATI_INTEROP_OPENCTI_ADMIN_TOKEN")

export OPENCTI_TAXII_URL="$TAXII_URL"
export OPENCTI_TAXII_TOKEN="$ATI_TAXII_TOKEN"
export OPENCTI_API_URL="http://127.0.0.1:${ATI_INTEROP_OPENCTI_PORT}"
export ATI_OPENCTI_CA_CERT="$ARTIFACT_DIR/tls-cert.pem"
export RUN_STATE_FILE="$ARTIFACT_DIR/run-state.json"
export DATASOURCE_ID=opencti-collection
export ATI_INTEROP_ES_URL="http://127.0.0.1:${ATI_INTEROP_ES_PORT}"
# Force real pagination: the 16-object fixture requires several pages at 5/request.
export ATI_TAXII_PAGE_SIZE=5
export ATI_TAXII_MAX_PAGES=8

CANONICAL_V1="$ARTIFACT_DIR/manifest-v1-canonical.json"
export ATI_MANIFEST_V1_CANONICAL="$CANONICAL_V1"
export ATI_MANIFEST_V2_CANONICAL="$ARTIFACT_DIR/manifest-v2-canonical.json"

echo "== Waiting for OpenCTI TAXII feed convergence (materializable type-counts) =="
# The pre-mapping gate uses deterministic feed type-counts (the seed manifest
# never asserts rejected-object identity), so materialization settles before
# the canonical seed->OpenCTI identity mapping is resolved below.
wait_for_feed_seed() {
  uv run python -m tests.interop.opencti.status \
    --run-id "$RUN_ID" --state-dir "$ARTIFACT_DIR" \
    --manifest "$ARTIFACT_DIR/manifest-v1.json" --wait \
    --until-stage OPENCTI_FEED_CONVERGED --timeout-seconds "$TIMEOUT_SECONDS"
}
wait_for_feed_seed || fail "OpenCTI feed did not converge in time"

echo "== Resolving seed -> OpenCTI canonical identities and verifying TAXII =="
# PR 33E-1 Option C: establish the seed -> OpenCTI standard_id mapping from
# OpenCTI materialization state (x_opencti_stix_ids), verify every canonical
# identity (including relationship endpoints and Sighting refs) against the
# real TAXII collection, and write the canonical manifests ATI ingest and the
# assertion suite consume. Identity collisions, missing materialized objects,
# or unrewritten refs fail loudly here.
uv run python -m tests.interop.opencti.canonical_identity \
  --run-id "$RUN_ID" --state-dir "$ARTIFACT_DIR" \
  --manifest "$ARTIFACT_DIR/manifest-v1.json" \
  --out-manifest "$CANONICAL_V1" --exact-feed \
  || fail "canonical identity resolution/verification failed"

# Canonical settle window: the canonical feed gate must hold across two
# independent convergence probes on the ATI-received identities.
sleep 15
wait_for_canonical_feed() {
  uv run python -m tests.interop.opencti.status \
    --run-id "$RUN_ID" --state-dir "$ARTIFACT_DIR" \
    --manifest "$CANONICAL_V1" --wait \
    --until-stage OPENCTI_FEED_CONVERGED --timeout-seconds "$TIMEOUT_SECONDS"
}
wait_for_canonical_feed || fail "canonical OpenCTI feed did not converge (settle window)"
sleep 15
wait_for_canonical_feed || fail "OpenCTI feed did not stay converged (settle window)"

echo "== Running ATI TAXII acquisition (production path) =="
uv run python -m tests.interop.opencti.ati_acquisition \
  || { echo "ATI acquisition failed; diagnosed state:" >&2; \
       uv run python -m tests.interop.opencti.status --run-id "$RUN_ID" \
         --state-dir "$ARTIFACT_DIR" --manifest "$CANONICAL_V1" --diagnose >&2 || true; fail "acquisition"; }

echo "== Waiting on the ingestion-completion barrier =="
uv run python -m tests.interop.opencti.status \
  --run-id "$RUN_ID" --state-dir "$ARTIFACT_DIR" \
  --manifest "$CANONICAL_V1" \
  --wait --timeout-seconds "$TIMEOUT_SECONDS" \
  || fail "ingestion-completion barrier did not reach READY_FOR_ASSERTIONS"

if [ "$INCREMENTAL" = "1" ]; then
  echo "== Seeding incremental v2 objects into OpenCTI =="
  OPENCTI_API_URL="$OPENCTI_API_URL" OPENCTI_ADMIN_TOKEN="$ATI_INTEROP_OPENCTI_ADMIN_TOKEN" \
    SEED_STAGE=v2 uv run python -m tests.interop.opencti.seed_opencti
  uv run python -m tests.interop.opencti.status \
    --run-id "$RUN_ID" --state-dir "$ARTIFACT_DIR" \
    --manifest "$ARTIFACT_DIR/manifest-v2.json" \
    --wait --until-stage OPENCTI_FEED_CONVERGED --timeout-seconds "$TIMEOUT_SECONDS" \
    || fail "v2 feed did not converge in time"
  uv run python -m tests.interop.opencti.canonical_identity \
    --run-id "$RUN_ID" --state-dir "$ARTIFACT_DIR" \
    --manifest "$ARTIFACT_DIR/manifest-v2.json" \
    --out-manifest "$ATI_MANIFEST_V2_CANONICAL" \
    || fail "v2 canonical identity resolution failed"
  sleep 2
  uv run python -m tests.interop.opencti.status \
    --run-id "$RUN_ID" --state-dir "$ARTIFACT_DIR" \
    --manifest "$ATI_MANIFEST_V2_CANONICAL" \
    --wait --until-stage OPENCTI_FEED_CONVERGED --timeout-seconds "$TIMEOUT_SECONDS" \
    || fail "v2 canonical feed did not converge in time"
  echo "== Running the incremental second ATI acquisition =="
  uv run python -m tests.interop.opencti.ati_acquisition \
    || fail "second acquisition failed"
  uv run python - "$ARTIFACT_DIR" <<'PY'
import json, sys
path = f"{sys.argv[1]}/run-state.json"
state = json.load(open(path))
state["second_run_completed"] = True
json.dump(state, open(path, "w"), indent=2)
PY
fi

echo "== Running OpenCTI interoperability assertions =="
uv run pytest tests/interop -m interop -q || fail "interop assertions failed"
_DONE=1
echo "== Interop SUCCESS: run $RUN_ID =="
echo "evidence: $ARTIFACT_DIR/run-state.json"
exit 0
