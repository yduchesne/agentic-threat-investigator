# SPDX-License-Identifier: AGPL-3.0-only
"""Psycopg adapters for ATI PostgreSQL composite input types."""

from typing import Any, cast

from psycopg import AsyncConnection
from psycopg.types.composite import CompositeInfo, register_composite


async def register_batch_composites(connection: AsyncConnection[Any]) -> None:
    """Register all batch composites on one pooled psycopg connection."""
    for type_name in (
        "ati.entity_batch_item",
        "ati.source_record_batch_item",
        "ati.document_batch_item",
        "ati.document_chunk_batch_item",
    ):
        info = await CompositeInfo.fetch(connection, type_name)
        register_composite(cast(CompositeInfo, info), connection)
