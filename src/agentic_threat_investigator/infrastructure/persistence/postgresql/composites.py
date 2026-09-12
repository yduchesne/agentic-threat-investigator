# SPDX-License-Identifier: AGPL-3.0-only
"""Psycopg adapters for ATI PostgreSQL composite input types."""

from typing import Any

from psycopg import AsyncConnection
from psycopg.types.composite import CompositeInfo, register_composite


async def register_batch_composites(connection: AsyncConnection[Any]) -> None:
    """Register all batch composites on one pooled psycopg connection.

    A composite type absent from the connected schema (for example during a
    migration-downgrade window below the revision that introduced it) is
    skipped: any statement that actually needs it will fail at execution time
    with psycopg's own type error, and registration is only an OID
    optimization. Production schemas always carry every type.
    """
    for type_name in (
        "ati.entity_batch_item",
        "ati.source_record_batch_item",
        "ati.document_batch_item",
        "ati.document_chunk_batch_item",
        "ati.assessment_finding_item",
        "ati.assessment_finding_support_item",
        # PR 23B report input composites.
        "ati.report_narrative_item",
        "ati.report_narrative_support_item",
        "ati.report_finding_item",
        "ati.report_finding_support_item",
        "ati.report_research_item",
    ):
        info = await CompositeInfo.fetch(connection, type_name)
        if info is None:
            continue
        register_composite(info, connection)
