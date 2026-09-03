# SPDX-License-Identifier: AGPL-3.0-only
"""Create PR 3 persistence schema and versioned SQL helpers."""

from pathlib import Path

from alembic import op

revision = "0002_persistence_foundation"
down_revision = "0001_bootstrap"


def upgrade() -> None:
    """Install the ATI schema, core resources, and immutable history support."""
    op.execute("CREATE SCHEMA IF NOT EXISTS ati")
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute(
        Path(__file__).parents[1].joinpath("sql/ati/v0001/jsonb_diff.sql").read_text()
    )
    op.execute(
        Path(__file__)
        .parents[1]
        .joinpath("sql/ati/v0001/write_functions.sql")
        .read_text()
    )
    op.execute(
        """
        CREATE TABLE ati.domain_object_history (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), object_type text NOT NULL,
          object_id uuid NOT NULL, version bigint NOT NULL, operation text NOT NULL,
          state jsonb NOT NULL, diff jsonb NOT NULL DEFAULT '{}'::jsonb,
          actor_id uuid, request_id uuid, investigation_id uuid,
          occurred_at timestamptz NOT NULL DEFAULT now()
        );
        CREATE INDEX domain_object_history_object_idx ON ati.domain_object_history(object_type, object_id, version);
        CREATE SEQUENCE ati.entity_version_seq AS bigint;
        CREATE TABLE ati.entity (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), entity_type text NOT NULL,
          canonical_value text NOT NULL, display_name text, attributes jsonb NOT NULL DEFAULT '{}',
          content_hash bytea, version bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz, deleted_by_actor_id uuid,
          UNIQUE(entity_type, canonical_value)
        );
        CREATE INDEX entity_canonical_idx ON ati.entity(entity_type, canonical_value) WHERE deleted_at IS NULL;
        CREATE SEQUENCE ati.relationship_version_seq AS bigint;
        CREATE TABLE ati.relationship (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), source_entity_id uuid NOT NULL REFERENCES ati.entity(id),
          target_entity_id uuid NOT NULL REFERENCES ati.entity(id), relationship_type_urn text NOT NULL,
          version bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
          deleted_at timestamptz, deleted_by_actor_id uuid,
          UNIQUE(source_entity_id, relationship_type_urn, target_entity_id)
        );
        CREATE INDEX relationship_adjacency_idx ON ati.relationship(source_entity_id, relationship_type_urn) WHERE deleted_at IS NULL;
        CREATE SEQUENCE ati.relationship_observation_version_seq AS bigint;
        CREATE TABLE ati.relationship_observation (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), relationship_id uuid NOT NULL REFERENCES ati.relationship(id),
          evidence_id uuid NOT NULL, investigation_id uuid, observed_at timestamptz, retrieved_at timestamptz NOT NULL,
          source text NOT NULL, confidence double precision, version bigint NOT NULL
        );
        CREATE INDEX relationship_observation_time_idx ON ati.relationship_observation(relationship_id, retrieved_at DESC);
        CREATE SEQUENCE ati.evidence_version_seq AS bigint;
        CREATE TABLE ati.evidence (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), investigation_id uuid NOT NULL, evidence_type text NOT NULL,
          subject_entity_id uuid NOT NULL REFERENCES ati.entity(id), source text NOT NULL, source_record_id text,
          source_url text, observed_at timestamptz, retrieved_at timestamptz NOT NULL, facts jsonb NOT NULL DEFAULT '{}',
          raw_payload jsonb, version bigint NOT NULL
        );
        CREATE INDEX evidence_lookup_idx ON ati.evidence(investigation_id, subject_entity_id, source, evidence_type, retrieved_at DESC);
        CREATE SEQUENCE ati.investigation_version_seq AS bigint;
        CREATE TABLE ati.investigation (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), status text NOT NULL, trigger_type text NOT NULL,
          objective text NOT NULL, budget jsonb NOT NULL DEFAULT '{}', operational_state jsonb NOT NULL DEFAULT '{}',
          version bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
          started_at timestamptz, completed_at timestamptz, deleted_at timestamptz, deleted_by_actor_id uuid
        );
        CREATE INDEX investigation_status_idx ON ati.investigation(status, created_at DESC) WHERE deleted_at IS NULL;
        CREATE SEQUENCE ati.assessment_version_seq AS bigint;
        CREATE TABLE ati.assessment (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(), investigation_id uuid NOT NULL, verdict text NOT NULL,
          confidence text NOT NULL, summary text NOT NULL, analyzed_evidence_ids jsonb NOT NULL DEFAULT '[]',
          supporting_evidence jsonb NOT NULL DEFAULT '[]', contradicting_evidence jsonb NOT NULL DEFAULT '[]',
          limitations jsonb NOT NULL DEFAULT '[]', unresolved_questions jsonb NOT NULL DEFAULT '[]',
          recommended_next_steps jsonb NOT NULL DEFAULT '[]', version bigint NOT NULL,
          created_at timestamptz NOT NULL DEFAULT now()
        );
        """
    )


def downgrade() -> None:
    """Remove the PR 3 schema."""
    op.execute("DROP SCHEMA IF EXISTS ati CASCADE")
