# SPDX-License-Identifier: AGPL-3.0-only
"""Add immutable audit event persistence."""
from alembic import op

revision = "0004_audit"
down_revision = "0003_identity"


def upgrade() -> None:
    """Create the append-only audit table and query indexes."""
    op.execute(
        """
        CREATE SEQUENCE ati.audit_event_version_seq AS bigint;
        CREATE TABLE ati.audit_event (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          action text NOT NULL,
          outcome text NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
          occurred_at timestamptz NOT NULL DEFAULT now(),
          actor_id uuid,
          actor_username text,
          object_type text,
          object_id uuid,
          metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
          request_id uuid,
          version bigint NOT NULL DEFAULT nextval('ati.audit_event_version_seq')
        );
        CREATE INDEX audit_event_actor_time_idx ON ati.audit_event (actor_id, occurred_at DESC);
        CREATE INDEX audit_event_action_time_idx ON ati.audit_event (action, occurred_at DESC);
        CREATE INDEX audit_event_object_time_idx ON ati.audit_event (object_type, object_id, occurred_at DESC);
        """
    )


def downgrade() -> None:
    """Remove audit persistence."""
    op.execute(
        "DROP TABLE IF EXISTS ati.audit_event; DROP SEQUENCE IF EXISTS ati.audit_event_version_seq"
    )
