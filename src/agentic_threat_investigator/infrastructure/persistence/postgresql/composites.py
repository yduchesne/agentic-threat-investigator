# SPDX-License-Identifier: AGPL-3.0-only
"""Psycopg adapters for ATI PostgreSQL composite input types."""

from typing import Any, cast

from psycopg import AsyncConnection
from psycopg.types.composite import CompositeInfo, register_composite


async def register_entity_batch_composite(connection: AsyncConnection[Any]) -> None:
    """Register the entity batch composite on one pooled psycopg connection."""
    info = await CompositeInfo.fetch(connection, "ati.entity_batch_item")
    register_composite(cast(CompositeInfo, info), connection)
