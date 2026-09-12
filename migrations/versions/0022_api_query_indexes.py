# SPDX-License-Identifier: AGPL-3.0-only
"""Install PR 23A query-path indexes for the analyst-facing read layer.

Every index exists because a concrete PR 23A query contract requires it; the
pre-existing ``investigation_status_idx`` and
``relationship_observation_time_idx`` are replaced by supersets that add the
stable pagination tie-breakers, so no redundant access path remains.
"""

from alembic import op

revision = "0022_api_query_indexes"
down_revision = "0021_rel_obs_history_semantics"


def upgrade() -> None:
    """Install the indexes backing the PR 23A keyset query contracts."""
    op.execute("""
        DROP INDEX IF EXISTS ati.investigation_status_idx;
        CREATE INDEX investigation_active_created_idx
          ON ati.investigation(created_at DESC, id ASC)
          WHERE deleted_at IS NULL;
        CREATE INDEX investigation_active_status_created_idx
          ON ati.investigation(status, created_at DESC, id ASC)
          WHERE deleted_at IS NULL;

        CREATE INDEX evidence_investigation_source_listing_idx
          ON ati.evidence(investigation_id, source, retrieved_at DESC, id ASC);
        CREATE INDEX evidence_investigation_subject_listing_idx
          ON ati.evidence(investigation_id, subject_entity_id,
                          retrieved_at DESC, id ASC);
        CREATE INDEX evidence_investigation_type_listing_idx
          ON ati.evidence(investigation_id, evidence_type,
                          retrieved_at DESC, id ASC);

        CREATE INDEX relationship_target_adjacency_idx
          ON ati.relationship(target_entity_id, relationship_type_urn,
                              source_entity_id)
          WHERE deleted_at IS NULL;

        DROP INDEX IF EXISTS ati.relationship_observation_time_idx;
        CREATE INDEX relationship_observation_investigation_retrieved_idx
          ON ati.relationship_observation(investigation_id,
                                          retrieved_at DESC, id ASC);
        CREATE INDEX relationship_observation_relationship_retrieved_idx
          ON ati.relationship_observation(relationship_id,
                                          retrieved_at DESC, id ASC);
        CREATE INDEX relationship_observation_relationship_observed_idx
          ON ati.relationship_observation(relationship_id,
                                          observed_at DESC, id ASC)
          WHERE observed_at IS NOT NULL;

        CREATE INDEX research_result_investigation_created_idx
          ON ati.research_result(investigation_id, created_at DESC, id ASC);
        CREATE INDEX research_result_investigation_subject_created_idx
          ON ati.research_result(investigation_id, subject_entity_id,
                                 created_at DESC, id ASC);

        CREATE INDEX assessment_investigation_version_idx
          ON ati.assessment(investigation_id, version DESC, id ASC)
          WHERE deleted_at IS NULL;

        CREATE INDEX domain_history_occurred_idx
          ON ati.domain_object_history(occurred_at DESC, id ASC);
        CREATE INDEX domain_history_type_occurred_idx
          ON ati.domain_object_history(object_type, occurred_at DESC, id ASC);
        CREATE INDEX domain_history_object_occurred_idx
          ON ati.domain_object_history(object_type, object_id,
                                       occurred_at DESC, id ASC);
        CREATE INDEX domain_history_investigation_occurred_idx
          ON ati.domain_object_history(investigation_id,
                                       occurred_at DESC, id ASC)
          WHERE investigation_id IS NOT NULL;
        """)


def downgrade() -> None:
    """Remove the PR 23A query indexes and restore the superseded indexes."""
    op.execute("""
        DROP INDEX IF EXISTS ati.domain_history_investigation_occurred_idx;
        DROP INDEX IF EXISTS ati.domain_history_object_occurred_idx;
        DROP INDEX IF EXISTS ati.domain_history_type_occurred_idx;
        DROP INDEX IF EXISTS ati.domain_history_occurred_idx;
        DROP INDEX IF EXISTS ati.assessment_investigation_version_idx;
        DROP INDEX IF EXISTS ati.research_result_investigation_subject_created_idx;
        DROP INDEX IF EXISTS ati.research_result_investigation_created_idx;
        DROP INDEX IF EXISTS ati.relationship_observation_relationship_observed_idx;
        DROP INDEX IF EXISTS ati.relationship_observation_relationship_retrieved_idx;
        DROP INDEX IF EXISTS ati.relationship_observation_investigation_retrieved_idx;
        DROP INDEX IF EXISTS ati.relationship_target_adjacency_idx;
        DROP INDEX IF EXISTS ati.evidence_investigation_type_listing_idx;
        DROP INDEX IF EXISTS ati.evidence_investigation_subject_listing_idx;
        DROP INDEX IF EXISTS ati.evidence_investigation_source_listing_idx;
        DROP INDEX IF EXISTS ati.investigation_active_status_created_idx;
        DROP INDEX IF EXISTS ati.investigation_active_created_idx;
        CREATE INDEX investigation_status_idx
          ON ati.investigation(status, created_at DESC) WHERE deleted_at IS NULL;
        CREATE INDEX relationship_observation_time_idx
          ON ati.relationship_observation(relationship_id, retrieved_at DESC);
        """)
