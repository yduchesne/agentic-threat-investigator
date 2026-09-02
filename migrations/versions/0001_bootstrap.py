# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Initial empty migration; schema arrives in PR 3."""

revision = "0001_bootstrap"
down_revision = None


def upgrade() -> None:
    """Create the initial migration revision without application tables."""

    pass


def downgrade() -> None:
    """Reverse the empty bootstrap revision."""

    pass
