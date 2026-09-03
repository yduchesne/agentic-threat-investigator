# SPDX-License-Identifier: AGPL-3.0-only
"""Add local users, credentials, and server-side sessions."""
from alembic import op

revision = "0003_identity"
down_revision = "0002_persistence_foundation"


def upgrade() -> None:
    """Create identity tables and lookup indexes."""
    op.execute(
        """
      CREATE SEQUENCE ati.user_version_seq AS bigint;
      CREATE TABLE ati."user" (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), username text NOT NULL,
        display_name text, role text NOT NULL CHECK (role IN ('admin','analyst')),
        enabled boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now(), deleted_at timestamptz,
        deleted_by_actor_id uuid, version bigint NOT NULL
      );
      CREATE UNIQUE INDEX user_username_idx ON ati."user" (username);
      CREATE TABLE ati.credential (
        user_id uuid PRIMARY KEY REFERENCES ati."user"(id),
        password_hash text NOT NULL, password_changed_at timestamptz NOT NULL
      );
      CREATE TABLE ati.session (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_id uuid NOT NULL REFERENCES ati."user"(id),
        token_hash bytea NOT NULL UNIQUE, created_at timestamptz NOT NULL,
        expires_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL, revoked_at timestamptz
      );
      CREATE INDEX session_token_hash_idx ON ati.session(token_hash);
      CREATE INDEX session_user_idx ON ati.session(user_id);
    """
    )


def downgrade() -> None:
    """Remove identity resources."""
    op.execute(
        'DROP TABLE IF EXISTS ati.session, ati.credential, ati."user" CASCADE; DROP SEQUENCE IF EXISTS ati.user_version_seq'
    )
