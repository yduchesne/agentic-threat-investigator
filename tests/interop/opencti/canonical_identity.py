#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33E-1 Option C: seed -> OpenCTI canonical identity resolution.

Real OpenCTI 6.9 regenerates a deterministic ``standard_id`` (UUIDv5) for
every imported object and exports that canonical identity (plus canonical
``source_ref``/``target_ref``/``sighting_of_ref``/``where_sighted_refs``)
through TAXII; the fixture seed IDs are preserved only in OpenCTI's
materialization state (``x_opencti_stix_ids``). This module

1. establishes the seed -> canonical mapping from OpenCTI materialization
   state (Elasticsearch ``x_opencti_stix_ids``, the platform's durable
   store), **never** by accepting arbitrary TAXII output;
2. independently verifies the mapped canonical identities (including
   relationship endpoints and the Sighting references) through the real
   TAXII 2.1 collection;
3. builds the canonical run manifest used by the ATI readiness barrier and
   the final assertion suite, so ATI ``source_record_id`` and CTI Entity
   canonical identities remain exactly the identities ATI received through
   TAXII (no seed-ID substitution inside ATI).

Every network interaction is bounded; the CLI never prints tokens, payloads,
or full feed content.

Usage:

  canonical_identity.py --run-id <id> --state-dir <dir> --manifest <seed manifest> \
      --out-manifest <canonical manifest path> [--exact-feed] \
      [--timeout-seconds <n>] [--interval-seconds <n>]

Environment:

  ATI_INTEROP_ES_URL     Elasticsearch HTTP URL of the pinned OpenCTI stack
  OPENCTI_TAXII_URL      TAXII 2.1 collection objects URL
  OPENCTI_TAXII_TOKEN    optional bearer token for the collection
  ATI_OPENCTI_CA_CERT    optional per-run TLS CA for the TAXII endpoint
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, cast

from tests.interop.opencti.fixtures.opencti_fake_world import (
    CATEGORY_REJECTED,
    CATEGORY_SUPPORTED,
    CATEGORY_UNSUPPORTED,
    fake_world_objects_v1,
)

_TAXII_ACCEPT = "application/taxii+json;version=2.1"
_TAXII_MEDIA_TYPE = "application/taxii+json"
_MAX_FEED_PROBE_PAGES = 20
_ES_INDICES = (
    "opencti_stix_domain_objects,"
    "opencti_stix_cyber_observables,"
    "opencti_stix_core_relationships,"
    "opencti_stix_sighting_relationships"
)
_ES_QUERY_SIZE = 500
_MAPPING_SETTLE_SECONDS = 180
"""Bounded settle budget for ES materialization after feed type-counts pass."""


def _require(env: str) -> str:
    value = os.environ.get(env, "")
    if not value:
        raise SystemExit(f"{env} is required")
    return value


def resolve_seed_to_canonical(es_url: str, seed_ids: list[str]) -> dict[str, str]:
    """Return the seed-id -> OpenCTI ``standard_id`` mapping from ES state.

    Queries the platform's durable STIX indices through their stable aliases,
    matches documents whose ``x_opencti_stix_ids`` array contains any seed id,
    and maps each seed id to that document's ``standard_id``. A seed id found
    under more than one canonical identity is raised (identity collision means
    the mapping is not a function and the acceptance cannot rely on it).
    """
    found: dict[str, str] = {}
    for hit in _es_hits_for_seed_ids(es_url, seed_ids):
        standard_id = hit.get("standard_id")
        seed_candidates = hit.get("x_opencti_stix_ids") or []
        if not isinstance(standard_id, str) or not standard_id:
            continue
        for candidate in seed_candidates:
            if not isinstance(candidate, str) or candidate not in seed_ids:
                continue
            previous = found.get(candidate)
            if previous is not None and previous != standard_id:
                raise RuntimeError(
                    f"seed id {candidate} maps to multiple canonical identities: "
                    f"{previous} and {standard_id}"
                )
            found[candidate] = standard_id
    return found


def _es_hits_for_seed_ids(es_url: str, seed_ids: list[str]) -> list[dict[str, Any]]:
    """Query the ES aliases for documents carrying any of the seed ids."""
    body = json.dumps(
        {
            "size": _ES_QUERY_SIZE,
            "_source": [
                "standard_id",
                "x_opencti_stix_ids",
                "entity_type",
            ],
            "query": {"terms": {"x_opencti_stix_ids.keyword": seed_ids}},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{es_url.rstrip('/')}/{_ES_INDICES}/_search",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    hits = payload.get("hits", {}).get("hits")
    if not isinstance(hits, list):
        return []
    return [
        (hit.get("_source") if isinstance(hit.get("_source"), dict) else {})
        for hit in hits
    ]


def _taxii_ssl_context() -> ssl.SSLContext:
    """Return the per-run TLS context honoring the harness CA (never blind)."""
    ca_file = os.environ.get("ATI_OPENCTI_CA_CERT")
    return (
        ssl.create_default_context(cafile=ca_file)
        if ca_file
        else ssl.create_default_context()
    )


def taxii_feed_objects() -> list[dict[str, Any]]:
    """Return a bounded object representation of the real TAXII collection.

    Only the fields the identity machinery needs are retained: type, id,
    value/name, relationship type + endpoint refs, and Sighting refs. The
    probe follows the server's opaque ``next`` pagination up to a bounded
    page count (the pinned stack caps single-page sizes).
    """
    url = _require("OPENCTI_TAXII_URL")
    headers = {"Accept": _TAXII_ACCEPT, "User-Agent": "ati-interop-identity/0.1"}
    token = os.environ.get("OPENCTI_TAXII_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    context = _taxii_ssl_context()
    collected: list[dict[str, Any]] = []
    page_params: dict[str, str] = {"limit": "500"}
    for _ in range(_MAX_FEED_PROBE_PAGES):
        separator = "&" if "?" in url else "?"
        request = urllib.request.Request(
            f"{url}{separator}{urllib.parse.urlencode(page_params)}",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(
                request, timeout=30, context=context
            ) as response:
                content_type = response.headers.get("Content-Type", "")
                if _TAXII_MEDIA_TYPE not in content_type:
                    break
                payload = json.loads(response.read().decode("utf-8"))
        except Exception:  # noqa: BLE001 - a probe failure means "not settled"
            break
        if not isinstance(payload, dict) or not isinstance(
            payload.get("objects"), list
        ):
            break
        for obj in payload["objects"]:
            if not isinstance(obj, dict) or not isinstance(obj.get("id"), str):
                continue
            collected.append(_bounded_feed_object(obj))
        more = bool(payload.get("more"))
        next_token = payload.get("next")
        if not more or not isinstance(next_token, str) or not next_token.strip():
            break
        page_params = {"next": next_token.strip()}
    return collected


def _bounded_feed_object(obj: dict[str, Any]) -> dict[str, Any]:
    """Retain only the bounded fields the identity machinery consumes."""
    keep = [
        "type",
        "id",
        "name",
        "value",
        "relationship_type",
        "source_ref",
        "target_ref",
        "sighting_of_ref",
        "where_sighted_refs",
        "identity_class",
    ]
    return {key: obj[key] for key in keep if key in obj}


def feed_type_counts(objects: list[dict[str, Any]]) -> dict[str, int]:
    """Return the observed object-type counts of one feed snapshot."""
    counts: dict[str, int] = {}
    for obj in objects:
        o_type = obj.get("type")
        if isinstance(o_type, str):
            counts[o_type] = counts.get(o_type, 0) + 1
    return counts


class IdentityResolutionError(RuntimeError):
    """Raised when the canonical identity contract cannot be satisfied."""


def build_seed_reference_contracts(
    manifest: dict[str, Any],
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, Any]]]:
    """Return seed relationship/sighting reference contracts for a manifest.

    ``(relationship_seed_id -> {"relationship_type", "source", "target"},
    sighting_seed_id -> {"sighting_of", "where_sighted"})`` derived from the
    exact fixture objects that this manifest actually seeds (single source of
    truth for the bundle); objects outside the manifest categories (e.g. the
    v2 scenario adds only a campaign) contribute no contracts.
    """
    categories = manifest.get("object_categories") or {}
    expected_seed_ids = {
        seed_id for seed_ids in categories.values() for seed_id in seed_ids
    }
    relationships: dict[str, dict[str, str]] = {}
    sightings: dict[str, dict[str, Any]] = {}
    for obj in fake_world_objects_v1():
        if obj["id"] not in expected_seed_ids:
            continue
        if obj["type"] == "relationship":
            relationships[obj["id"]] = {
                "relationship_type": obj["relationship_type"],
                "source": obj["source_ref"],
                "target": obj["target_ref"],
            }
        elif obj["type"] == "sighting":
            sightings[obj["id"]] = {
                "sighting_of": obj["sighting_of_ref"],
                "where_sighted": list(obj.get("where_sighted_refs") or []),
            }
    return relationships, sightings


def verify_feed_canonical(
    manifest: dict[str, Any],
    mapping: dict[str, str],
    feed_objects: list[dict[str, Any]],
    *,
    exact_feed: bool,
) -> dict[str, Any]:
    """Verify the canonical identities against the real TAXII collection.

    Returns a bounded verification dict. Raises :class:`IdentityResolutionError`
    on any contract violation (missing materializable object, reference not
    rewritten to canonical identity, rejected object visible, or identity
    collision), so a broken seed -> canonical -> TAXII chain fails loudly.
    """
    categories = manifest.get("object_categories") or {}
    materializable = list(
        (categories.get(CATEGORY_SUPPORTED) or [])
        + (categories.get(CATEGORY_UNSUPPORTED) or [])
    )
    rejected = list(categories.get(CATEGORY_REJECTED) or [])
    canonical_ids = [mapping[seed] for seed in materializable if seed in mapping]
    feed_ids = {obj["id"] for obj in feed_objects}
    by_id = {obj["id"]: obj for obj in feed_objects}

    missing = sorted(set(canonical_ids) - feed_ids)
    if missing:
        raise IdentityResolutionError(
            f"canonical identities missing from the TAXII feed: {missing}"
        )

    # A clean v1 run must show exactly the materialized fixture (no foreign
    # or rejected objects may leak into the collection).
    if exact_feed:
        unexpected = sorted(feed_ids - set(canonical_ids))
        if unexpected:
            raise IdentityResolutionError(
                f"TAXII feed exposes objects outside the materialized fixture: "
                f"{unexpected}"
            )

    # Relationship endpoint canonicalization: every legal relationship's
    # exported refs must be the canonical identities of its seed endpoints.
    relationships, sightings = build_seed_reference_contracts(manifest)
    for seed_rel, contract in relationships.items():
        canonical_rel = mapping.get(seed_rel)
        if canonical_rel is None:
            if seed_rel in rejected:
                continue  # schema-rejected: intentionally never materialized
            raise IdentityResolutionError(
                f"materializable relationship {seed_rel} has no canonical identity"
            )
        feed_obj = by_id.get(canonical_rel)
        if feed_obj is None:
            raise IdentityResolutionError(
                f"relationship {seed_rel} canonical {canonical_rel} not in feed"
            )
        source_canonical = mapping.get(contract["source"])
        target_canonical = mapping.get(contract["target"])
        if (
            feed_obj.get("source_ref") != source_canonical
            or feed_obj.get("target_ref") != target_canonical
        ):
            raise IdentityResolutionError(
                f"relationship {seed_rel} endpoints not canonicalized: "
                f"expected ({source_canonical}, {target_canonical}) "
                f"observed ({feed_obj.get('source_ref')}, {feed_obj.get('target_ref')})"
            )

    # Sighting canonicalization: sighting_of_ref and where_sighted_refs must
    # be the canonical identities of their seed endpoints.
    for seed_sighting, contract in sightings.items():
        canonical_sighting = mapping.get(seed_sighting)
        if canonical_sighting is None:
            raise IdentityResolutionError(
                f"materializable sighting {seed_sighting} has no canonical identity"
            )
        feed_obj = by_id.get(canonical_sighting)
        if feed_obj is None:
            raise IdentityResolutionError(
                f"sighting {seed_sighting} canonical {canonical_sighting} not in feed"
            )
        if feed_obj.get("sighting_of_ref") != mapping.get(contract["sighting_of"]):
            raise IdentityResolutionError(
                f"sighting {seed_sighting} sighting_of_ref not canonicalized: "
                f"expected {mapping.get(contract['sighting_of'])}"
            )
        observed_where = set(feed_obj.get("where_sighted_refs") or [])
        expected_where = {
            mapping[where_seed] for where_seed in contract["where_sighted"]
        }
        if not expected_where.issubset(observed_where):
            raise IdentityResolutionError(
                f"sighting {seed_sighting} where_sighted_refs not canonicalized: "
                f"expected {sorted(expected_where)} observed {sorted(observed_where)}"
            )

    # Rejected objects must never appear in the materialization state OR the
    # feed; they are deliberately not ATI unsupported-object coverage.
    mapped_rejected = sorted(set(rejected) & set(mapping))
    if mapped_rejected:
        raise IdentityResolutionError(
            f"REJECTED_BY_OPENCTI_PROFILE objects were materialized: {mapped_rejected}"
        )
    rejected_in_feed = sorted(set(rejected) & feed_ids)
    if rejected_in_feed:
        raise IdentityResolutionError(
            f"REJECTED_BY_OPENCTI_PROFILE objects visible in the feed: "
            f"{rejected_in_feed}"
        )

    # Bijectivity: no canonical identity may come from two seed ids.
    if len(set(mapping.values())) != len(mapping):
        raise IdentityResolutionError(
            "canonical identity mapping is not bijective for the materializable set"
        )

    return {
        "ok": True,
        "mapped_count": len(mapping),
        "materializable_count": len(materializable),
        "visible_count": len(feed_ids),
        "exact_feed_match": exact_feed,
        "relationship_refs_canonicalized": True,
        "sighting_refs_canonicalized": True,
        "rejected_absent": True,
    }


def build_canonical_manifest(
    seed_manifest: dict[str, Any], mapping: dict[str, str]
) -> dict[str, Any]:
    """Translate every identity-bearing manifest field to canonical IDs.

    Seed IDs become the canonical identities ATI actually receives through
    TAXII; ``REJECTED_BY_OPENCTI_PROFILE`` objects keep their seed identity
    (they have no canonical counterpart) together with their reason and are
    never part of any ATI expectation. No ATI production vocabulary or
    relationship profile is touched.
    """
    categories = seed_manifest.get("object_categories") or {}
    translated_categories = {
        category: [mapping[seed] for seed in seed_ids if seed in mapping]
        for category, seed_ids in categories.items()
    }
    manifest = cast(dict[str, Any], json.loads(json.dumps(seed_manifest)))
    manifest["object_categories"] = translated_categories
    manifest["expected_evidence_ids"] = [
        mapping[seed] for seed in (seed_manifest.get("expected_evidence_ids") or [])
    ]
    manifest["stix_ids"] = [
        mapping[seed]
        for seed in (seed_manifest.get("stix_ids") or [])
        if seed in mapping
    ]
    entities: dict[str, list[str]] = {}
    for entity_type, values in (seed_manifest.get("expected_entities") or {}).items():
        entities[entity_type] = [mapping.get(value, value) for value in values]
    manifest["expected_entities"] = entities
    relationships = []
    for rel in seed_manifest.get("expected_relationships") or []:
        relationships.append(
            {
                "type": rel["type"],
                "source": mapping.get(rel["source"], rel["source"]),
                "target": mapping.get(rel["target"], rel["target"]),
            }
        )
    manifest["expected_relationships"] = relationships
    sighting = seed_manifest.get("expected_sighting_evidence") or {}
    sighting_of_seed = sighting.get("sighting_of")
    if sighting.get("seed_id"):
        manifest["expected_sighting_evidence"] = {
            "seed_id": sighting["seed_id"],
            "evidence_id": mapping.get(str(sighting["seed_id"])),
            "sighting_of_seed": sighting_of_seed,
            "sighting_of": mapping.get(str(sighting_of_seed))
            if sighting_of_seed
            else None,
        }
    else:
        manifest["expected_sighting_evidence"] = {}
    unsupported_seed_ids = seed_manifest.get("unsupported_stix_ids") or []
    manifest["unsupported_stix_ids"] = [
        mapping[seed] for seed in unsupported_seed_ids if seed in mapping
    ]
    manifest["seed_to_canonical"] = dict(sorted(mapping.items()))
    manifest.pop("expected_feed_type_counts", None)
    manifest["canonical"] = True
    return manifest


def _write_state_delta(
    state_dir: Path, mapping: dict[str, str], verification: dict[str, Any], stage: str
) -> None:
    """Merge the bounded identity mapping + verification into run-state.json.

    The v2 resolution run must never clobber the v1 mapping: mappings are
    unioned so the recorded provenance stays a single seed -> canonical map
    for the whole run; per-stage feed-verification records are preserved
    (``feed_verification_v1``/``feed_verification_v2``) with the latest also
    mirrored at ``feed_verification`` for diagnostics.
    """
    path = state_dir / "run-state.json"
    state = json.loads(path.read_text()) if path.exists() else {}
    previous = state.get("identity_map")
    merged = dict(previous) if isinstance(previous, dict) else {}
    merged.update(mapping)
    state["identity_map"] = dict(sorted(merged.items()))
    state[f"feed_verification_{stage}"] = verification
    state["feed_verification"] = verification
    path.write_text(json.dumps(state, indent=2))


def _main_argv(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out-manifest", required=True)
    parser.add_argument("--exact-feed", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=300.0)
    parser.add_argument("--interval-seconds", type=float, default=3.0)
    args = parser.parse_args(argv)

    state_dir = Path(args.state_dir)
    seed_manifest = json.loads(Path(args.manifest).read_text())
    categories = seed_manifest.get("object_categories") or {}
    materializable = list(
        (categories.get(CATEGORY_SUPPORTED) or [])
        + (categories.get(CATEGORY_UNSUPPORTED) or [])
    )
    rejected = list(categories.get(CATEGORY_REJECTED) or [])
    all_seed_ids = materializable + rejected

    es_url = _require("ATI_INTEROP_ES_URL")
    started = time.monotonic()
    while True:
        mapping = resolve_seed_to_canonical(es_url, all_seed_ids)
        missing = sorted(set(materializable) - set(mapping))
        if not missing:
            break
        if time.monotonic() - started >= args.timeout_seconds:
            print(
                f"IDENTITY_MAPPING_INCOMPLETE missing={missing} "
                f"settled_in={time.monotonic() - started:.1f}s"
            )
            return 2
        time.sleep(args.interval_seconds)

    feed_objects = taxii_feed_objects()
    verification = verify_feed_canonical(
        seed_manifest,
        mapping,
        feed_objects,
        exact_feed=args.exact_feed,
    )
    canonical = build_canonical_manifest(seed_manifest, mapping)
    Path(args.out_manifest).write_text(json.dumps(canonical, indent=2))

    stage = "v1" if seed_manifest.get("fixture") == "opencti-fake-world-v1" else "v2"
    _write_state_delta(state_dir, mapping, verification, stage)
    Path(state_dir, "identity-map.json").write_text(
        json.dumps({"seed_to_canonical": dict(sorted(mapping.items()))}, indent=2)
    )
    print(
        f"IDENTITY_RESOLVED mapped={len(mapping)} rejected={len(rejected)} "
        f"visible={verification['visible_count']} exact={verification['exact_feed_match']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(_main_argv())
