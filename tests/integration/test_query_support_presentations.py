# SPDX-License-Identifier: AGPL-3.0-only
"""PR 31F-5 integration: bounded Investigation-scoped support resolution.

The resolver returns presentation metadata only for exactly admitted
observations: duplicates resolve once, cross-Investigation IDs fail
closed (absent), missing IDs are simply absent, and the raw provider
payload never appears in the projection.
"""

from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

import pytest

from agentic_threat_investigator.app.query.support_presentations import (
    SupportPresentationQuery,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import EvidenceType
from agentic_threat_investigator.domain.relationships import RelationshipType
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.services import (
    PostgresQueryServices,
)
from tests.support.query_fixtures import (
    seed_entity,
    seed_evidence_observation,
    seed_investigation,
    seed_observation,
    seed_relationship,
)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_support_resolution_returns_semantic_metadata_only(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Evidence + observation supports resolve to semantic presentation."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await seed_entity(
            uow, entity_type=EntityType.DOMAIN, value="update-package.test"
        )
        target = await seed_entity(
            uow, entity_type=EntityType.MALWARE, value="malware.badloader_v2"
        )
        evidence_id = await seed_evidence_observation(
            uow,
            investigation_id=investigation_id,
            entity_id=source,
            evidence_type=EvidenceType.DNS,
            source="urn:ati:source:google_public_dns",
        )
        edge = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=target
        )
        observation = await seed_observation(
            uow,
            investigation_id=investigation_id,
            relationship=edge,
            evidence_observation_id=evidence_id,
        )

        assert uow.session is not None
        services = PostgresQueryServices(uow.session)
        result = await services.support_presentations.resolve(
            SupportPresentationQuery(
                investigation_id=investigation_id,
                evidence_observation_ids=(evidence_id,),
                relationship_observation_ids=(observation.id,),
            )
        )
        evidence = result.evidence[0]
        assert evidence.evidence_observation_id == evidence_id
        assert evidence.evidence_type == EvidenceType.DNS
        assert evidence.source == "urn:ati:source:google_public_dns"
        assert evidence.subject_entity_value == "update-package.test"
        assert evidence.subject_entity_type == EntityType.DOMAIN
        # No raw provider payload field exists on the projection.
        assert not hasattr(evidence, "raw_payload")
        edge_presentation = result.relationship_observations[0]
        assert edge_presentation.relationship_observation_id == observation.id
        assert edge_presentation.relationship_type == RelationshipType.RESOLVES_TO
        assert edge_presentation.source_entity_value == "update-package.test"
        assert edge_presentation.target_entity_value == "malware.badloader_v2"
        assert edge_presentation.source_entity_type == EntityType.DOMAIN
        assert edge_presentation.target_entity_type == EntityType.MALWARE


@pytest.mark.asyncio
@pytest.mark.integration
async def test_support_resolution_deduplicates_and_omits_missing(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Duplicate requested IDs resolve once; missing IDs are simply absent."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        source = await seed_entity(
            uow, entity_type=EntityType.DOMAIN, value="update-package.test"
        )
        evidence_id = await seed_evidence_observation(
            uow, investigation_id=investigation_id, entity_id=source
        )

        assert uow.session is not None
        services = PostgresQueryServices(uow.session)
        missing = uuid4()
        result = await services.support_presentations.resolve(
            SupportPresentationQuery(
                investigation_id=investigation_id,
                evidence_observation_ids=(evidence_id, evidence_id, missing),
                relationship_observation_ids=(),
            )
        )
        assert [item.evidence_observation_id for item in result.evidence] == [
            evidence_id
        ]
        assert result.relationship_observations == ()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_support_resolution_is_investigation_scoped(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Cross-Investigation support IDs fail closed (absent from the result)."""
    async with uow_factory() as uow:
        investigation_a = await seed_investigation(uow)
        investigation_b = await seed_investigation(uow)
        source = await seed_entity(
            uow, entity_type=EntityType.DOMAIN, value="update-package.test"
        )
        target = await seed_entity(
            uow, entity_type=EntityType.MALWARE, value="malware.badloader_v2"
        )
        # The evidence/observation belong only to investigation A.
        evidence_id = await seed_evidence_observation(
            uow, investigation_id=investigation_a, entity_id=source
        )
        edge = await seed_relationship(
            uow, source_entity_id=source, target_entity_id=target
        )
        observation = await seed_observation(
            uow,
            investigation_id=investigation_a,
            relationship=edge,
            evidence_observation_id=evidence_id,
        )

        assert uow.session is not None
        services = PostgresQueryServices(uow.session)
        result = await services.support_presentations.resolve(
            SupportPresentationQuery(
                investigation_id=investigation_b,
                evidence_observation_ids=(evidence_id,),
                relationship_observation_ids=(observation.id,),
            )
        )
        assert result.evidence == ()
        assert result.relationship_observations == ()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_support_resolution_empty_request_is_empty(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """An empty request set resolves to an empty presentation result."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        assert uow.session is not None
        services = PostgresQueryServices(uow.session)
        result = await services.support_presentations.resolve(
            SupportPresentationQuery(
                investigation_id=investigation_id,
            )
        )
        assert result.evidence == ()
        assert result.relationship_observations == ()
