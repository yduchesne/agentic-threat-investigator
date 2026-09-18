# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install SQL API v0026: global Evidence persistence (PR 28B).

PR 28B makes the PR 28A global Evidence model authoritative in PostgreSQL.
The v0.1 legacy Evidence table (Investigation-owned, single-subject
observation rows) is transformed in place:

- old ``ati.evidence`` rows become ``ati.evidence_observation`` rows,
  preserving their immutable observation UUIDs; the new stable
  ``ati.evidence`` rows are derived through the PR 28A domain contract
  ``evidence_id_for_source_record`` (the database stores the deterministic
  identity but never derives it);
- the old subject binding becomes an ``ati.evidence_observation_entity``
  association; the old Investigation ownership becomes an
  ``ati.investigation_evidence`` admission;
- ``relationship_observation``, GEOINT observation/resolution, and
  assessment/report finding-support provenance are repointed to exact
  ``EvidenceObservation`` values;
- only rows whose source has an approved stable identity contract (the
  ThreatFox semantic format) AND that carry the exact upstream
  ``source_record_id`` are migratable; any other legacy row aborts the
  migration closed rather than inventing identity (the plan's STOP);
- the new write functions ``ati.persist_evidence_observation``,
  ``ati.associate_evidence_observation_entity``, and
  ``ati.admit_investigation_evidence`` own DB-side version allocation,
  material no-op detection, canonical diffs, idempotent associations, and
  exact admission; RelationshipObservation/Assessment/report/coordinator/
  GEOINT write functions are repointed onto the new provenance.

Evidence and EvidenceObservation never use ``domain_object_history``:
EvidenceObservation is authoritative intelligence history. Pre-28B legacy
Evidence history rows are preserved untouched as legacy audit data.

The downgrade is a documented limited downgrade: v0.2 states that cannot be
represented in v0.1 (stable global Evidence, several admitted versions of
one Evidence, observation Entity associations) are not losslessly
reversible, and the restored archived v0.1 functions reference the v0.1
shape only.
"""

import json
from pathlib import Path

from alembic import op
from sqlalchemy import text as sql_text
from sqlalchemy.engine import Connection

from agentic_threat_investigator.domain.evidence import evidence_id_for_source_record
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)

revision = "0031_global_evidence_persistence"
down_revision = "0030_datasource_log"

_THREATFOX_SOURCE = SourceId.THREATFOX.value
_THREATFOX_SEMANTIC_FORMAT = SemanticFormatId.THREATFOX.value
"""The approved stable identity contract of the ThreatFox source."""


def _read(name: str) -> str:
    """Read one immutable SQL API v0026 file."""
    return Path(__file__).parents[1].joinpath(f"sql/ati/v0026/{name}").read_text()


def _backfill(bind: Connection) -> None:
    """Transform legacy Evidence rows onto the PR 28B tables (fail closed).

    Every legacy row must belong to an approved stable-identity source and
    carry the exact upstream ``source_record_id``; rows from any other
    source abort the migration (the plan's STOP) instead of deriving an
    identity by hashing payloads, IOCs, retrieval timestamps, or old random
    UUIDs. The old observation UUID is preserved: it becomes the new
    ``EvidenceObservation.id``. Versions are assigned deterministically per
    stable Evidence by ``(retrieved_at, id)``; the first observation of each
    Evidence carries ``diff = NULL`` and later versions carry the canonical
    shallow ``{old, new}`` diff from their immediate predecessor.
    """
    legacy = sql_text(
        "SELECT id, investigation_id, evidence_type, subject_entity_id, "
        "source, source_record_id, source_url, observed_at, retrieved_at, "
        "facts, raw_payload FROM ati.evidence_legacy_v01"
    )
    result = bind.execute(legacy)
    rows = list(result.fetchall())

    unmigratable = [
        (row.id, row.source, row.source_record_id)
        for row in rows
        if row.source != _THREATFOX_SOURCE or row.source_record_id is None
    ]
    if unmigratable:
        sources = ", ".join(
            sorted({item[1] or "<null source>" for item in unmigratable})
        )
        raise RuntimeError(
            "PR 28B migration STOP: "
            f"{len(unmigratable)} legacy evidence row(s) from unsupported "
            f"source(s) [{sources}] lack an approved stable identity contract; "
            "no identity is invented; a reviewer decision is required before "
            "upgrading (first unsupported row: "
            f"{str(unmigratable[0][0])})"
        )

    # One stable Evidence row per distinct (source, source_record_id).
    stable: dict[tuple[str, str], dict[str, object]] = {}
    for row in rows:
        key = (row.source, row.source_record_id)
        if key not in stable:
            stable[key] = {
                "id": evidence_id_for_source_record(
                    SemanticFormatId.THREATFOX, SourceId.THREATFOX, key[1]
                ),
                "evidence_type": row.evidence_type,
                "source": row.source,
                "source_record_id": row.source_record_id,
            }
    for entry in stable.values():
        bind.execute(
            sql_text(
                "INSERT INTO ati.evidence (id, evidence_type, source, source_record_id) "
                "VALUES (:id, :evidence_type, :source, :source_record_id)"
            ),
            entry,
        )

    # Observations with deterministic per-Evidence versions.
    ordered = sorted(rows, key=lambda r: (r.retrieved_at, r.id))
    versions: dict[tuple[str, str], int] = {}
    for row in ordered:
        key = (row.source, row.source_record_id)
        version = versions.get(key, 0) + 1
        versions[key] = version
        evidence_id = stable[key]["id"]
        diff = None
        if version > 1:
            previous = next(
                prior
                for prior in ordered
                if (prior.source, prior.source_record_id) == key
                and (prior.retrieved_at, prior.id) < (row.retrieved_at, row.id)
            )
            diff = _material_diff(
                {
                    "observed_at": previous.observed_at,
                    "source_url": previous.source_url,
                    "facts": previous.facts,
                    "raw_payload": previous.raw_payload,
                },
                {
                    "observed_at": row.observed_at,
                    "source_url": row.source_url,
                    "facts": row.facts,
                    "raw_payload": row.raw_payload,
                },
            )
        bind.execute(
            sql_text(
                "INSERT INTO ati.evidence_observation ("
                "id, evidence_id, version, source_url, observed_at, retrieved_at, "
                "facts, raw_payload, diff, created_at) "
                "VALUES (:id, :evidence_id, :version, :source_url, :observed_at, "
                ":retrieved_at, CAST(:facts AS jsonb), CAST(:raw_payload AS "
                "jsonb), CAST(:diff AS jsonb), now())"
            ),
            {
                "id": row.id,
                "evidence_id": evidence_id,
                "version": version,
                "source_url": row.source_url,
                "observed_at": row.observed_at,
                "retrieved_at": row.retrieved_at,
                "facts": json.dumps(row.facts),
                "raw_payload": None
                if row.raw_payload is None
                else json.dumps(row.raw_payload),
                "diff": None if diff is None else json.dumps(diff),
            },
        )

    # Observation-level Entity association from the old subject binding.
    for row in rows:
        bind.execute(
            sql_text(
                "INSERT INTO ati.evidence_observation_entity "
                "(evidence_observation_id, entity_id) VALUES (:id, :entity_id)"
            ),
            {"id": row.id, "entity_id": row.subject_entity_id},
        )

    # Exact admission from the old Investigation ownership.
    for row in rows:
        bind.execute(
            sql_text(
                "INSERT INTO ati.investigation_evidence ("
                "investigation_id, evidence_observation_id, inclusion_reason, "
                "discovered_from_evidence_observation_id, added_at, added_by) "
                "VALUES (:investigation_id, :id, 'provider_result', NULL, "
                "COALESCE(:retrieved_at, now()), 'system')"
            ),
            {
                "investigation_id": row.investigation_id,
                "id": row.id,
                "retrieved_at": row.retrieved_at,
            },
        )


def _material_diff(
    previous: dict[str, object], candidate: dict[str, object]
) -> dict[str, object] | None:
    """Compute the canonical shallow {key: {old, new}} material diff.

    Matches the PR 28A ``material_state_diff`` contract; keys are emitted in
    sorted order and a key changed to/from JSON null records old/new of None
    in the shallow material object.
    """
    diff: dict[str, object] = {}
    for key in sorted(set(previous) | set(candidate)):
        if previous[key] != candidate[key]:
            diff[key] = {"old": previous[key], "new": candidate[key]}
    return diff or None


def upgrade() -> None:
    """Install the PR 28B global Evidence schema, migration, and functions."""
    conn = op.get_bind()
    op.execute(_read("global_evidence_persistence.sql"))
    _backfill(conn)
    # Repoint the provenance FKs only AFTER the backfill populated
    # ati.evidence_observation: PostgreSQL validates existing rows when the
    # FK is added, so an earlier ADD would fail closed on every legacy
    # database carrying pre-28B observation rows.
    op.execute(_read("repoint_provenance_fks.sql"))
    # Install the repointed write functions BEFORE dropping the legacy
    # table: the v0.1 GEOINT/research functions still reference
    # ati.evidence (now ati.evidence_legacy_v01) and must be dropped by
    # repointed_write_functions.sql first, or the DROP TABLE fails on
    # dependent objects.
    op.execute(_read("repointed_write_functions.sql"))
    op.execute("DROP TABLE ati.evidence_legacy_v01")


def downgrade() -> None:
    """Restore the v0.1 shape with a documented limited-downgrade policy.

    Databases whose PR 28B tables contain migrated rows CANNOT be losslessly
    downgraded: stable global Evidence identity, per-Evidence observation
    versions, observation Entity associations, and exact Investigation
    admission have no v0.1 representation (I28B-12). For such databases the
    downgrade raises a typed error directing the operator to restore a
    pre-28B backup; for empty/fresh databases the PR 28B objects are dropped
    and the archived v0.1 function definitions reinstalled so development
    round-trips and test fixtures remain usable.
    """
    conn = op.get_bind()
    has_rows = conn.execute(
        sql_text(
            "SELECT EXISTS (SELECT 1 FROM ati.evidence_observation) "
            "OR EXISTS (SELECT 1 FROM ati.evidence) "
            "OR EXISTS (SELECT 1 FROM ati.investigation_evidence)"
        )
    ).scalar()
    if has_rows:
        raise RuntimeError(
            "PR 28B downgrade STOP (I28B-12): the upgraded database contains "
            "migrated Evidence/EvidenceObservation/InvestigationEvidence rows "
            "that cannot be losslessly represented in the v0.1 shape. Restore a "
            "pre-28B backup to downgrade; no lossy silent conversion is performed."
        )
    # Drop the PR 28B-specific tables in dependency-safe order: the
    # association/admission children first, then the repointed FKs from
    # pre-existing tables, then the observation/stable tables.
    op.execute("DROP TABLE IF EXISTS ati.investigation_evidence")
    op.execute("DROP TABLE IF EXISTS ati.evidence_observation_entity")
    op.execute("DROP INDEX IF EXISTS ati.investigation_evidence_observation_idx")
    op.execute("DROP INDEX IF EXISTS ati.evidence_observation_entity_entity_idx")
    op.execute(
        "DROP INDEX IF EXISTS ati.relationship_observation_evidence_observation_idx"
    )
    op.execute(
        "ALTER TABLE ati.relationship_observation "
        "DROP CONSTRAINT IF EXISTS relationship_observation_evidence_observation_fk"
    )
    op.execute(
        "ALTER TABLE ati.entity_location_observation "
        "DROP CONSTRAINT IF EXISTS "
        "entity_location_observation_evidence_observation_fk"
    )
    op.execute(
        "ALTER TABLE ati.geo_resolution "
        "DROP CONSTRAINT IF EXISTS geo_resolution_evidence_observation_fk"
    )
    op.execute(
        "ALTER TABLE ati.assessment_finding_support "
        "DROP CONSTRAINT IF EXISTS assessment_finding_support_evidence_fk"
    )
    op.execute("DROP TABLE IF EXISTS ati.evidence_observation")
    op.execute("DROP TABLE IF EXISTS ati.evidence")
    op.execute(
        "DROP FUNCTION IF EXISTS ati.persist_evidence_observation("
        "uuid, text, text, text, text, timestamptz, timestamptz, jsonb, jsonb, "
        "timestamptz, uuid)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.associate_evidence_observation_entity(uuid, uuid)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.admit_investigation_evidence("
        "uuid, uuid, text, uuid, timestamptz, text)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.append_relationship_observation("
        "uuid, uuid, uuid, timestamptz, timestamptz, text, double precision)"
    )
    # Drop the v0026 SIGnature-changed functions so the archived v0.1
    # definitions (with p_evidence_id parameters and evidence_id return
    # columns) can be reinstalled.
    op.execute(
        "DROP FUNCTION IF EXISTS ati.append_entity_location_observation("
        "uuid, uuid, uuid, uuid, text, timestamptz, timestamptz, "
        "timestamptz, text)"
    )
    op.execute("DROP FUNCTION IF EXISTS ati.create_geo_resolution(uuid, uuid, uuid)")
    op.execute(
        "DROP FUNCTION IF EXISTS ati.claim_geo_resolutions(text, integer, integer, integer)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.complete_geo_resolution_resolved("
        "uuid, bigint, text, uuid, uuid, text, timestamptz, timestamptz, "
        "timestamptz, text)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.complete_geo_resolution_unresolvable("
        "uuid, bigint, text, text)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS ati.record_geo_resolution_failure("
        "uuid, bigint, text, text, boolean, double precision, "
        "double precision, integer)"
    )
    # Reconstruct the empty v0.1 schema shape (only used by the no-rows
    # branch) so a fresh empty database can round-trip 0030 -> 0031 -> 0030
    # -> 0031. The upgrade renames ati.evidence to the transitional legacy
    # name and transforms it again.
    op.execute(
        "CREATE TABLE ati.evidence ("
        " id uuid PRIMARY KEY DEFAULT gen_random_uuid(),"
        " investigation_id uuid NOT NULL,"
        " evidence_type text NOT NULL,"
        " subject_entity_id uuid NOT NULL REFERENCES ati.entity(id),"
        " source text NOT NULL,"
        " source_record_id text,"
        " source_url text,"
        " observed_at timestamptz,"
        " retrieved_at timestamptz NOT NULL,"
        " facts jsonb NOT NULL DEFAULT '{}',"
        " raw_payload jsonb,"
        " version bigint NOT NULL)"
    )
    op.execute(
        "ALTER TABLE ati.relationship_observation "
        "RENAME COLUMN evidence_observation_id TO evidence_id"
    )
    op.execute(
        "ALTER TABLE ati.relationship_observation ADD COLUMN investigation_id uuid"
    )
    op.execute(
        "ALTER TABLE ati.relationship_observation "
        "ADD CONSTRAINT relationship_observation_evidence_fk "
        "FOREIGN KEY (evidence_id) REFERENCES ati.evidence(id)"
    )
    op.execute(
        "ALTER TABLE ati.entity_location_observation "
        "RENAME COLUMN evidence_observation_id TO evidence_id"
    )
    op.execute(
        "ALTER TABLE ati.entity_location_observation "
        "ADD CONSTRAINT entity_location_observation_evidence_id_fkey "
        "FOREIGN KEY (evidence_id) REFERENCES ati.evidence(id)"
    )
    op.execute(
        "ALTER TABLE ati.geo_resolution "
        "RENAME COLUMN evidence_observation_id TO evidence_id"
    )
    op.execute(
        "ALTER TABLE ati.geo_resolution "
        "ADD CONSTRAINT geo_resolution_evidence_id_fkey "
        "FOREIGN KEY (evidence_id) REFERENCES ati.evidence(id)"
    )
    op.execute(
        "ALTER TABLE ati.assessment_finding_support "
        "ADD CONSTRAINT assessment_finding_support_evidence_fk "
        "FOREIGN KEY (evidence_id) REFERENCES ati.evidence(id)"
    )
    # Restore the archived v0.1 function definitions (function portions
    # only; the archived DDL is owned by earlier migrations).
    for name in (
        "sql/ati/v0018/relationship_persistence.sql",
        "sql/ati/v0011/assessment_persistence.sql",
        "sql/ati/v0017/research_execution.sql",
        "sql/ati/v0019/report_persistence.sql",
        "sql/ati/v0021/geoint_persistence.sql",
        "sql/ati/v0022/geoint_persistence.sql",
        "sql/ati/v0024/geo_resolution_lifecycle.sql",
    ):
        text = Path(__file__).parents[1].joinpath(name).read_text()
        marker = "CREATE OR REPLACE FUNCTION"
        if marker in text:
            op.execute(text[text.index(marker) :])
