# SPDX-License-Identifier: AGPL-3.0-only
"""Real-PostgreSQL coverage for atomic provider-observation graph persistence.

Every scenario persists synthetic, deterministic Evidence plus PR 18B
extraction output through the PR 18C service against the isolated migrated
database, asserting atomicity, stable-identity reuse, immutable observations,
history/version invariants, and the documented soft-deleted identity policy.
"""

# pylint: disable=redefined-outer-name

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from types import TracebackType
from typing import Self
from uuid import UUID, uuid4

import pytest
from psycopg.errors import UniqueViolation
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from agentic_threat_investigator.app.extraction.models import (
    EntityIdentity,
    ExtractedEntity,
    ExtractionResult,
    RelationshipAssertion,
)
from agentic_threat_investigator.app.persistence.repositories import (
    EvidenceDuplicateIdentityError,
    InvestigationNotFoundError,
    SoftDeletedIdentityError,
)
from agentic_threat_investigator.app.provider_observation_persistence import (
    ProviderObservationPersistenceService,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.investigation import (
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
    default_investigation_budget,
)
from agentic_threat_investigator.domain.relationships import (
    RelationshipObservation,
    RelationshipType,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql import (
    relationship_repositories,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.repositories import (
    PostgresEntityRepository,
)

_RETRIEVED_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
_DOMAIN = "malicious-domain.test"
_IP = "203.0.113.42"
_MALWARE = "win.asyncrat"

_DNS_SOURCE = "urn:ati:source:google_public_dns"
_THREATFOX_SOURCE = "urn:ati:source:threatfox"
_GEOLOCATION_SOURCE = "urn:ati:source:dbip_city_lite"
_ABUSEIPDB_SOURCE = "urn:ati:source:abuseipdb"
_URLHAUS_SOURCE = "urn:ati:source:urlhaus"


async def seed_investigation(uow: PostgresUnitOfWork) -> UUID:
    """Create one visible investigation in the active unit of work."""
    investigation_id = uuid4()
    await uow.investigations.create(
        InvestigationState(
            investigation_id=investigation_id,
            status=InvestigationStatus.RUNNING,
            trigger_type=InvestigationTriggerType.MANUAL,
            root_entity_ids=[uuid4()],
            objective="Assess the root indicator.",
            budget=default_investigation_budget(),
            started_at=_RETRIEVED_AT,
        )
    )
    return investigation_id


def dns_evidence(investigation_id: UUID, evidence_id: UUID | None = None) -> Evidence:
    """Build deterministic DNS Evidence with a canonical domain subject."""
    return Evidence(
        id=evidence_id or uuid4(),
        investigation_id=investigation_id,
        type=EvidenceType.DNS,
        subject=EntityRef(type=EntityType.DOMAIN, value=_DOMAIN),
        source=_DNS_SOURCE,
        observed_at=None,
        retrieved_at=_RETRIEVED_AT,
        facts={"answers": [_IP], "status": 0},
        raw_payload=None,
    )


def dns_extraction(evidence_id: UUID) -> ExtractionResult:
    """Build the deterministic DNS extraction for the DNS Evidence fixture."""
    return ExtractionResult(
        entities=(ExtractedEntity(type=EntityType.IP_ADDRESS, value=_IP),),
        relationships=(
            RelationshipAssertion(
                source=EntityIdentity(type=EntityType.DOMAIN, value=_DOMAIN),
                type=RelationshipType.RESOLVES_TO,
                target=EntityIdentity(type=EntityType.IP_ADDRESS, value=_IP),
                evidence_id=evidence_id,
            ),
        ),
    )


def threatfox_extraction(evidence_id: UUID, subject: str = _IP) -> ExtractionResult:
    """Build the deterministic ThreatFox extraction asserting the malware edge."""
    return ExtractionResult(
        entities=(
            ExtractedEntity(
                type=EntityType.MALWARE, value=_MALWARE, display_name="AsyncRAT"
            ),
        ),
        relationships=(
            RelationshipAssertion(
                source=EntityIdentity(type=EntityType.IP_ADDRESS, value=subject),
                type=RelationshipType.ASSOCIATED_WITH,
                target=EntityIdentity(type=EntityType.MALWARE, value=_MALWARE),
                evidence_id=evidence_id,
            ),
        ),
    )


def threatfox_evidence(investigation_id: UUID) -> Evidence:
    """Build deterministic ThreatFox Evidence with the IP as subject."""
    return Evidence(
        id=uuid4(),
        investigation_id=investigation_id,
        type=EvidenceType.THREAT_INTELLIGENCE,
        subject=EntityRef(type=EntityType.IP_ADDRESS, value=_IP),
        source=_THREATFOX_SOURCE,
        observed_at=None,
        retrieved_at=_RETRIEVED_AT,
        facts={
            "matches": [
                {"ioc": _IP, "malware": _MALWARE, "malware_printable": "AsyncRAT"}
            ]
        },
        raw_payload=None,
    )


def require_id(evidence: Evidence) -> UUID:
    """Narrow the optional Evidence identity for extraction construction."""
    assert evidence.id is not None  # noqa: S101 - fixtures always set one
    return evidence.id


async def count(uow: PostgresUnitOfWork, query: str) -> int:
    """Run one bounded count query inside the unit of work."""
    assert uow.session is not None  # noqa: S101 - the UoW is active
    result = await uow.session.execute(text(query))
    return int(result.scalar_one())


async def table_count(uow: PostgresUnitOfWork, table: str) -> int:
    """Count every row of one application table."""
    return await count(uow, f"SELECT count(*) FROM ati.{table}")


async def entity_count(uow: PostgresUnitOfWork, entity_type: str) -> int:
    """Count entities of one type."""
    return await count(
        uow,
        f"SELECT count(*) FROM ati.entity "  # nosec B608 - fixed test constant
        f"WHERE entity_type = '{entity_type}'",
    )


async def _history_count(
    uow: PostgresUnitOfWork, object_type: str, object_id: UUID | None = None
) -> int:
    """Count history rows for one object type and optional identity."""
    assert uow.session is not None  # noqa: S101 - the UoW is active
    if object_id is None:
        result = await uow.session.execute(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type = :object_type"
            ),
            {"object_type": object_type},
        )
    else:
        result = await uow.session.execute(
            text(
                "SELECT count(*) FROM ati.domain_object_history "
                "WHERE object_type = :object_type AND object_id = :object_id"
            ),
            {"object_type": object_type, "object_id": object_id},
        )
    return int(result.scalar_one())


async def _audit_count(uow: PostgresUnitOfWork, object_id: UUID) -> int:
    """Count audit events recorded for one evidence identity."""
    assert uow.session is not None  # noqa: S101 - the UoW is active
    result = await uow.session.execute(
        text(
            "SELECT count(*) FROM ati.audit_event "
            "WHERE object_type = 'evidence' AND object_id = :object_id"
        ),
        {"object_id": object_id},
    )
    return int(result.scalar_one())


async def _single_row(uow: PostgresUnitOfWork, query: str) -> tuple[int, int]:
    """Return the first row of one bounded verification query."""
    assert uow.session is not None  # noqa: S101 - the UoW is active
    result = await uow.session.execute(text(query))
    row = result.one()
    return int(row[0]), int(row[1])


async def snapshot_counts(uow: PostgresUnitOfWork) -> dict[str, int]:
    """Capture the graph-state counters used by rollback assertions."""
    return {
        "entities": await table_count(uow, "entity"),
        "ip_entities": await entity_count(uow, "ip_address"),
        "domain_entities": await entity_count(uow, "domain"),
        "relationships": await table_count(uow, "relationship"),
        "observations": await table_count(uow, "relationship_observation"),
        "evidence": await table_count(uow, "evidence"),
        "history": await table_count(uow, "domain_object_history"),
        "audit_events": await table_count(uow, "audit_event"),
    }


def extraction_service(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> ProviderObservationPersistenceService:
    """Build the persistence service under test."""
    return ProviderObservationPersistenceService(uow_factory)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_dns_scenario_persists_the_canonical_graph(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """E1 persists one DOMAIN, one IP, one stable edge, one observation, history."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    evidence = dns_evidence(investigation_id)
    service = extraction_service(uow_factory)
    result = await service.persist(evidence, dns_extraction(evidence.id))  # type: ignore[arg-type]

    assert result.evidence.id == evidence.id
    domain = next(e for e in result.entities if e.type is EntityType.DOMAIN)
    address = next(e for e in result.entities if e.type is EntityType.IP_ADDRESS)
    assert domain.value == _DOMAIN and address.value == _IP
    assert len(result.relationships) == 1
    assert result.relationships[0].type is RelationshipType.RESOLVES_TO
    assert result.relationships[0].source_entity_id == domain.id
    assert result.relationships[0].target_entity_id == address.id

    async with uow_factory() as uow:
        assert await entity_count(uow, "domain") == 1
        assert await entity_count(uow, "ip_address") == 1
        assert await table_count(uow, "evidence") == 1
        assert await table_count(uow, "relationship") == 1
        assert await table_count(uow, "relationship_observation") == 1
        assert await _history_count(uow, "entity", domain.id) == 1
        assert await _history_count(uow, "entity", address.id) == 1
        assert await _history_count(uow, "evidence", evidence.id) == 1
        assert await _history_count(uow, "relationship") == 1
        assert await _history_count(uow, "relationship_observation") == 1
        assert evidence.id is not None  # noqa: S101 - the service persists it
        assert await _audit_count(uow, evidence.id) == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_threatfox_reuses_the_ip_and_creates_malware(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """E2 reuses the discovered IP, creates the MALWARE entity, and asserts the edge."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)
    first = dns_evidence(investigation_id)
    dns_result = await service.persist(first, dns_extraction(first.id))  # type: ignore[arg-type]
    address = next(e for e in dns_result.entities if e.type is EntityType.IP_ADDRESS)

    second = threatfox_evidence(investigation_id)
    assert second.id is not None  # noqa: S101 - built with a fixed identity
    threat_result = await service.persist(second, threatfox_extraction(second.id))

    reused_ip = next(
        e for e in threat_result.entities if e.type is EntityType.IP_ADDRESS
    )
    assert reused_ip.id == address.id
    malware = next(e for e in threat_result.entities if e.type is EntityType.MALWARE)
    assert malware.value == _MALWARE
    assert malware.display_name == "AsyncRAT"
    assert len(threat_result.relationships) == 1
    assert threat_result.relationships[0].type is RelationshipType.ASSOCIATED_WITH

    async with uow_factory() as uow:
        assert await entity_count(uow, "malware") == 1
        assert await entity_count(uow, "ip_address") == 1
        assert await table_count(uow, "evidence") == 2
        assert await table_count(uow, "relationship") == 2
        assert await table_count(uow, "relationship_observation") == 2
        assert (
            await _history_count(
                uow, "relationship_observation", threat_result.observations[0].id
            )
            == 1
        )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_new_evidence_same_edge_appends_observation(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A new Evidence ID on the same semantic edge appends only an observation."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)
    first = dns_evidence(investigation_id)
    await service.persist(first, dns_extraction(first.id))  # type: ignore[arg-type]

    second = dns_evidence(investigation_id)
    result = await service.persist(second, dns_extraction(second.id))  # type: ignore[arg-type]

    async with uow_factory() as uow:
        assert await entity_count(uow, "domain") == 1
        assert await entity_count(uow, "ip_address") == 1
        assert await table_count(uow, "relationship") == 1
        assert await table_count(uow, "evidence") == 2
        assert await table_count(uow, "relationship_observation") == 2
        # Reuse must not spurious-bump versions: one history entry each, and
        # the stored version equals the version in that single history entry.
        assert await _history_count(uow, "relationship") == 1
        domain_version, domain_history_version = await _single_row(
            uow,
            "SELECT e.version, h.version FROM ati.entity e "
            "JOIN ati.domain_object_history h ON h.object_type = 'entity' "
            "AND h.object_id = e.id WHERE e.entity_type = 'domain'",
        )
        assert domain_version == domain_history_version


@pytest.mark.asyncio
@pytest.mark.integration
async def test_same_evidence_replay_conflicts_and_rolls_back(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Replaying one Evidence ID is a typed conflict with unchanged graph state."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)
    evidence = dns_evidence(investigation_id)
    await service.persist(evidence, dns_extraction(evidence.id))  # type: ignore[arg-type]

    async with uow_factory() as uow:
        before = await snapshot_counts(uow)

    with pytest.raises(EvidenceDuplicateIdentityError):
        replay = dns_evidence(investigation_id, evidence_id=evidence.id)
        await service.persist(replay, dns_extraction(replay.id))  # type: ignore[arg-type]

    async with uow_factory() as uow:
        after = await snapshot_counts(uow)
    assert after == before


@pytest.mark.asyncio
@pytest.mark.integration
async def test_empty_extraction_persists_evidence_only(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Empty extraction persists Evidence and audit; prior graph history stays."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)
    dns = dns_evidence(investigation_id)
    await service.persist(dns, dns_extraction(dns.id))  # type: ignore[arg-type]
    async with uow_factory() as uow:
        before = await snapshot_counts(uow)

    geolocation = Evidence(
        id=uuid4(),
        investigation_id=investigation_id,
        type=EvidenceType.GEOLOCATION,
        subject=EntityRef(type=EntityType.IP_ADDRESS, value=_IP),
        source=_GEOLOCATION_SOURCE,
        observed_at=None,
        retrieved_at=_RETRIEVED_AT,
        facts={"country_code": "US", "city": "Springfield"},
        raw_payload=None,
    )
    result = await service.persist(geolocation, ExtractionResult())

    assert len(result.entities) == 1  # only the subject identity
    assert result.relationships == ()
    async with uow_factory() as uow:
        after = await snapshot_counts(uow)
    assert after["evidence"] == before["evidence"] + 1
    assert after["history"] == before["history"] + 1  # evidence CREATE only
    assert after["relationships"] == before["relationships"]
    assert after["observations"] == before["observations"]


@pytest.mark.asyncio
@pytest.mark.integration
async def test_fact_only_and_urlhaus_entities_do_not_invent_edges(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """DB-IP/AbuseIPDB persist evidence only; URLhaus persists entities without edges."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)

    reputation = Evidence(
        id=uuid4(),
        investigation_id=investigation_id,
        type=EvidenceType.REPUTATION,
        subject=EntityRef(type=EntityType.IP_ADDRESS, value=_IP),
        source=_ABUSEIPDB_SOURCE,
        observed_at=None,
        retrieved_at=_RETRIEVED_AT,
        facts={"abuse_confidence_score": 85},
        raw_payload=None,
    )
    abuse_result = await service.persist(reputation, ExtractionResult())
    assert abuse_result.relationships == ()

    urlhaus = Evidence(
        id=uuid4(),
        investigation_id=investigation_id,
        type=EvidenceType.THREAT_INTELLIGENCE,
        subject=EntityRef(type=EntityType.DOMAIN, value=_DOMAIN),
        source=_URLHAUS_SOURCE,
        observed_at=None,
        retrieved_at=_RETRIEVED_AT,
        facts={"matches": [{"url": f"http://{_DOMAIN}/payload.exe"}]},
        raw_payload=None,
    )
    urlhaus_extraction = ExtractionResult(
        entities=(
            ExtractedEntity(type=EntityType.URL, value=f"http://{_DOMAIN}/payload.exe"),
        ),
        relationships=(),
    )
    urlhaus_result = await service.persist(urlhaus, urlhaus_extraction)
    assert urlhaus_result.relationships == ()
    assert len(urlhaus_result.entities) == 2

    async with uow_factory() as uow:
        # No URL-host relationship is invented; only the two entities exist.
        assert await table_count(uow, "relationship") == 0
        assert await table_count(uow, "relationship_observation") == 0
        assert await table_count(uow, "evidence") == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_missing_investigation_is_a_typed_error(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A missing parent investigation is a typed error with zero graph mutation."""
    service = extraction_service(uow_factory)
    evidence = dns_evidence(uuid4())
    with pytest.raises(InvestigationNotFoundError):
        await service.persist(evidence, dns_extraction(evidence.id))  # type: ignore[arg-type]

    async with uow_factory() as uow:
        assert await table_count(uow, "entity") == 0
        assert await table_count(uow, "evidence") == 0
        assert await table_count(uow, "relationship") == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_mid_transaction_observation_failure_rolls_back_everything(
    uow_factory: Callable[[], PostgresUnitOfWork],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure at the observation stage leaves no partial graph state."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)

    async def exploding_append(self: object, observation: object) -> object:
        raise RuntimeError("injected observation failure")

    monkeypatch.setattr(
        relationship_repositories.PostgresRelationshipObservationRepository,
        "append",
        exploding_append,
    )
    service = extraction_service(uow_factory)
    evidence = dns_evidence(investigation_id)
    with pytest.raises(RuntimeError, match="injected"):
        await service.persist(evidence, dns_extraction(evidence.id))  # type: ignore[arg-type]

    async with uow_factory() as uow:
        assert await table_count(uow, "entity") == 0
        assert await table_count(uow, "evidence") == 0
        assert await table_count(uow, "relationship") == 0
        assert await table_count(uow, "relationship_observation") == 0
        # Only the seeded investigation's own history remains; the rolled-back
        # transaction contributed no history of any kind.
        assert await table_count(uow, "domain_object_history") == 1
        assert await _history_count(uow, "investigation") == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_writers_share_one_canonical_identity(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Two concurrent writers discover the same absent edge without raw failures."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)

    async def writer() -> Evidence:
        evidence = dns_evidence(investigation_id)
        await service.persist(evidence, dns_extraction(evidence.id))  # type: ignore[arg-type]
        return evidence

    evidence_ids = await asyncio.gather(
        asyncio.wait_for(writer(), 20),
        asyncio.wait_for(writer(), 20),
    )
    assert len(evidence_ids) == 2

    async with uow_factory() as uow:
        assert await entity_count(uow, "domain") == 1
        assert await entity_count(uow, "ip_address") == 1
        assert await table_count(uow, "relationship") == 1
        assert await table_count(uow, "evidence") == 2
        assert await table_count(uow, "relationship_observation") == 2


@pytest.mark.asyncio
@pytest.mark.integration
async def test_soft_deleted_entity_rediscovery_fails_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Rediscovering a soft-deleted entity never creates a second canonical row."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)
    first = dns_evidence(investigation_id)
    result = await service.persist(first, dns_extraction(first.id))  # type: ignore[arg-type]
    address = next(e for e in result.entities if e.type is EntityType.IP_ADDRESS)

    async with uow_factory() as uow:
        assert address.id is not None  # noqa: S101 - persisted above
        await uow.entities.soft_delete(address.id)

    reputation = Evidence(
        id=uuid4(),
        investigation_id=investigation_id,
        type=EvidenceType.REPUTATION,
        subject=EntityRef(type=EntityType.IP_ADDRESS, value=_IP),
        source=_ABUSEIPDB_SOURCE,
        observed_at=None,
        retrieved_at=_RETRIEVED_AT,
        facts={},
        raw_payload=None,
    )
    with pytest.raises(SoftDeletedIdentityError):
        await service.persist(reputation, ExtractionResult())

    async with uow_factory() as uow:
        assert await entity_count(uow, "ip_address") == 1
        assert await table_count(uow, "evidence") == 1
        deleted_row = await count(
            uow,
            "SELECT deleted_at IS NOT NULL FROM ati.entity WHERE entity_type = 'ip_address'",
        )
        assert deleted_row == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_soft_deleted_relationship_rediscovery_fails_closed(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Rediscovering a soft-deleted edge never creates a duplicate edge."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)
    first = dns_evidence(investigation_id)
    result = await service.persist(first, dns_extraction(first.id))  # type: ignore[arg-type]

    async with uow_factory() as uow:
        await uow.relationships.soft_delete(result.relationships[0].id)

    second = dns_evidence(investigation_id)
    with pytest.raises(SoftDeletedIdentityError):
        await service.persist(second, dns_extraction(second.id))  # type: ignore[arg-type]

    async with uow_factory() as uow:
        assert await table_count(uow, "relationship") == 1
        assert await table_count(uow, "relationship_observation") == 1
        assert await table_count(uow, "evidence") == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_canonical_graph_is_reconstructed_from_durable_rows(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The persisted graph reconstructs without re-running extraction."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)
    dns = dns_evidence(investigation_id)
    await service.persist(dns, dns_extraction(dns.id))  # type: ignore[arg-type]
    threat = threatfox_evidence(investigation_id)
    await service.persist(threat, threatfox_extraction(threat.id))  # type: ignore[arg-type]

    async with uow_factory() as uow:
        assert uow.session is not None
        rows = (await uow.session.execute(text("""
                    SELECT source.entity_type, source.canonical_value,
                           r.relationship_type_urn,
                           target.entity_type, target.canonical_value
                    FROM ati.relationship r
                    JOIN ati.entity source ON source.id = r.source_entity_id
                    JOIN ati.entity target ON target.id = r.target_entity_id
                    WHERE r.deleted_at IS NULL
                    ORDER BY r.relationship_type_urn
                """))).fetchall()
    edges = {(row[0], row[1], row[2], row[3], row[4]) for row in rows}
    assert edges == {
        ("domain", _DOMAIN, RelationshipType.RESOLVES_TO.value, "ip_address", _IP),
        (
            "ip_address",
            _IP,
            RelationshipType.ASSOCIATED_WITH.value,
            "malware",
            _MALWARE,
        ),
    }


class _PausedReadEntityRepository(PostgresEntityRepository):
    """Test-only wrapper pausing after one active-entity pre-lock read."""

    def __init__(
        self,
        session: AsyncSession,
        batch_size: int,
        paused_identity: tuple[EntityType, str],
        read_done: asyncio.Event,
        delete_committed: asyncio.Event,
    ) -> None:
        super().__init__(session, batch_size)
        self._paused_identity = paused_identity
        self._read_done = read_done
        self._delete_committed = delete_committed
        self._resumed = False

    async def get_by_identity(
        self, entity_type: str, canonical_value: str, *, include_deleted: bool = False
    ) -> Entity | None:
        result = await super().get_by_identity(
            entity_type, canonical_value, include_deleted=include_deleted
        )
        if (
            EntityType(entity_type),
            canonical_value,
        ) == self._paused_identity and not self._resumed:
            self._resumed = True
            self._read_done.set()
            await asyncio.wait_for(self._delete_committed.wait(), 5)
        return result


class _EntityDeleteRaceUow(PostgresUnitOfWork):
    """Test-only UnitOfWork installing the pausing entity repository."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        paused_identity: tuple[EntityType, str],
        read_done: asyncio.Event,
        delete_committed: asyncio.Event,
    ) -> None:
        super().__init__(session_factory)
        self._paused_identity = paused_identity
        self._read_done = read_done
        self._delete_committed = delete_committed

    async def __aenter__(self) -> Self:
        entered = await super().__aenter__()
        assert self.session is not None  # noqa: S101 - the UoW is active
        self.entities = _PausedReadEntityRepository(
            self.session,
            self._batch_size,
            self._paused_identity,
            self._read_done,
            self._delete_committed,
        )
        return entered


class _SimulatedRaceEntityRepository(PostgresEntityRepository):
    """Test-only wrapper simulating one canonical-identity creation race."""

    def __init__(
        self,
        session: AsyncSession,
        batch_size: int,
        race_identity: tuple[EntityType, str],
    ) -> None:
        super().__init__(session, batch_size)
        self._race_identity = race_identity
        self._raised = False

    async def upsert(
        self, entity: Entity, *, expected_version: int | None = None
    ) -> Entity:
        if (entity.type, entity.value) == self._race_identity and not self._raised:
            self._raised = True
            raise IntegrityError(
                "SELECT ati.upsert_entity(...)",
                {},
                UniqueViolation("duplicate key value violates unique constraint"),
            )
        return await super().upsert(entity, expected_version=expected_version)


class _SimulatedRaceUow(PostgresUnitOfWork):
    """Test-only UnitOfWork installing the simulated-race entity repository."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        race_identity: tuple[EntityType, str],
    ) -> None:
        super().__init__(session_factory)
        self._race_identity = race_identity

    async def __aenter__(self) -> Self:
        entered = await super().__aenter__()
        assert self.session is not None  # noqa: S101 - the UoW is active
        self.entities = _SimulatedRaceEntityRepository(
            self.session, self._batch_size, self._race_identity
        )
        return entered


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_entity_soft_deletion_is_rejected_under_the_row_lock(
    session_factory: async_sessionmaker[AsyncSession],
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A soft deletion between the pre-lock read and the write fails closed."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
        subject = await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value=_DOMAIN)
        )

    read_done = asyncio.Event()
    delete_committed = asyncio.Event()
    paused_identity = (EntityType.DOMAIN, _DOMAIN)

    def racing_factory() -> _EntityDeleteRaceUow:
        return _EntityDeleteRaceUow(
            session_factory, paused_identity, read_done, delete_committed
        )

    evidence = dns_evidence(investigation_id)
    service = extraction_service(racing_factory)

    async def writer() -> object:
        try:
            await service.persist(evidence, dns_extraction(require_id(evidence)))
            return None
        except SoftDeletedIdentityError as error:
            return error

    writer_task = asyncio.create_task(writer())
    await asyncio.wait_for(read_done.wait(), 5)

    async with uow_factory() as uow:
        assert subject.id is not None  # noqa: S101 - persisted above
        await uow.entities.soft_delete(subject.id)

    delete_committed.set()
    outcome = await asyncio.wait_for(writer_task, 10)
    assert isinstance(outcome, SoftDeletedIdentityError)
    assert outcome.object_id == subject.id

    async with uow_factory() as uow:
        # Exactly one canonical row remains and it stays soft-deleted.
        assert await entity_count(uow, "domain") == 1
        deleted_only = await count(
            uow,
            "SELECT count(*) FROM ati.entity "
            "WHERE entity_type = 'domain' AND deleted_at IS NOT NULL",
        )
        assert deleted_only == 1
        assert await table_count(uow, "evidence") == 0
        assert await table_count(uow, "relationship") == 0
        assert await table_count(uow, "relationship_observation") == 0
        assert not await uow.evidence.list_for_investigation(investigation_id)
        # No same-transaction history: only the seed history and the
        # independent soft-deletion history exist.
        assert await _history_count(uow, "evidence") == 0
        assert await _history_count(uow, "relationship") == 0
        assert await _history_count(uow, "relationship_observation") == 0


@pytest.mark.asyncio
@pytest.mark.integration
async def test_canonical_race_recovery_rejects_a_soft_deleted_row(
    session_factory: async_sessionmaker[AsyncSession],
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A raced row that was soft-deleted before recovery is never returned."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)
    first = dns_evidence(investigation_id)
    dns_result = await service.persist(first, dns_extraction(require_id(first)))
    address = next(e for e in dns_result.entities if e.type is EntityType.IP_ADDRESS)

    async with uow_factory() as uow:
        assert address.id is not None  # noqa: S101 - persisted above
        await uow.entities.soft_delete(address.id)

    race_identity = (EntityType.IP_ADDRESS, _IP)

    def racing_factory() -> _SimulatedRaceUow:
        return _SimulatedRaceUow(session_factory, race_identity)

    reputation = Evidence(
        id=uuid4(),
        investigation_id=investigation_id,
        type=EvidenceType.REPUTATION,
        subject=EntityRef(type=EntityType.IP_ADDRESS, value=_IP),
        source=_ABUSEIPDB_SOURCE,
        observed_at=None,
        retrieved_at=_RETRIEVED_AT,
        facts={},
        raw_payload=None,
    )
    with pytest.raises(SoftDeletedIdentityError):
        await extraction_service(racing_factory).persist(reputation, ExtractionResult())

    async with uow_factory() as uow:
        assert await entity_count(uow, "ip_address") == 1
        assert await table_count(uow, "evidence") == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_soft_deleted_entity_write_is_database_enforced(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """The locked entity write itself rejects a soft-deleted identity."""
    async with uow_factory() as uow:
        written = await uow.entities.upsert(
            Entity(type=EntityType.DOMAIN, value=_DOMAIN)
        )
        assert written.id is not None  # noqa: S101 - persisted above
        await uow.entities.soft_delete(written.id)

    async with uow_factory() as uow:
        with pytest.raises(SoftDeletedIdentityError) as error:
            await uow.entities.upsert(Entity(type=EntityType.DOMAIN, value=_DOMAIN))
        assert error.value.object_id == written.id
        # No second canonical row was created.
        assert await entity_count(uow, "domain") == 1


@pytest.mark.asyncio
@pytest.mark.integration
async def test_relationship_soft_delete_uses_database_version_and_history(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Relationship soft deletion allocates a version and writes DELETE history."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)
    evidence = dns_evidence(investigation_id)
    result = await service.persist(evidence, dns_extraction(require_id(evidence)))
    relationship = result.relationships[0]

    async with uow_factory() as uow:
        row = (
            await uow.session.execute(  # type: ignore[union-attr]
                text("SELECT version FROM ati.relationship WHERE id = :id"),
                {"id": relationship.id},
            )
        ).scalar_one()
        assert await _history_count(uow, "relationship") == 1
    initial_version = int(row)

    actor_id = uuid4()
    async with uow_factory() as uow:
        deleted = await uow.relationships.soft_delete(
            relationship.id, actor_id=actor_id
        )
        assert deleted.id == relationship.id
        state = (
            await uow.session.execute(  # type: ignore[union-attr]
                text(
                    "SELECT version, deleted_at, deleted_by_actor_id, updated_at "
                    "FROM ati.relationship WHERE id = :id"
                ),
                {"id": relationship.id},
            )
        ).one()
        deleted_version, deleted_at, deleted_by, _updated = state
        assert int(deleted_version) > initial_version
        assert deleted_at is not None
        assert deleted_by == actor_id
        history = (
            await uow.session.execute(  # type: ignore[union-attr]
                text(
                    "SELECT operation, diff FROM ati.domain_object_history "
                    "WHERE object_type = 'relationship' AND object_id = :id "
                    "ORDER BY version"
                ),
                {"id": relationship.id},
            )
        ).fetchall()
        assert [h[0] for h in history] == ["CREATE", "DELETE"]
        delete_diff = history[-1][1]
        assert delete_diff["deleted_at"]["old"] is None
        assert delete_diff["deleted_at"]["new"] is not None
        # Exactly two history rows total: CREATE and DELETE.
        assert await _history_count(uow, "relationship") == 2

    async with uow_factory() as uow:
        hidden = await uow.relationships.get_by_identity(
            relationship.source_entity_id,
            relationship.type.value,
            relationship.target_entity_id,
        )
        assert hidden is None
        visible_deleted = await uow.relationships.get_by_identity(
            relationship.source_entity_id,
            relationship.type.value,
            relationship.target_entity_id,
            include_deleted=True,
        )
        assert visible_deleted is not None
        assert visible_deleted.id == relationship.id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_relationship_soft_delete_rejects_stale_missing_and_repeat(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """Stale, missing, and repeated soft deletions mutate nothing."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)
    evidence = dns_evidence(investigation_id)
    result = await service.persist(evidence, dns_extraction(require_id(evidence)))
    relationship = result.relationships[0]

    async with uow_factory() as uow:
        current = await uow.relationships.get_by_identity(
            relationship.source_entity_id,
            relationship.type.value,
            relationship.target_entity_id,
            include_deleted=True,
        )
        assert current is not None
        row_version = (
            await uow.session.execute(  # type: ignore[union-attr]
                text("SELECT version FROM ati.relationship WHERE id = :id"),
                {"id": relationship.id},
            )
        ).scalar_one()
        before_history = await _history_count(uow, "relationship")

    # Stale expected version: typed error, no mutation.
    async with uow_factory() as uow:
        with pytest.raises(ValueError, match="stale"):
            await uow.relationships.soft_delete(
                relationship.id, expected_version=int(row_version) + 999
            )

    # Missing relationship: typed error, no mutation.
    async with uow_factory() as uow:
        with pytest.raises(LookupError):
            await uow.relationships.soft_delete(uuid4())

    # Successful deletion, then a repeat delete: typed error, no extra history.
    async with uow_factory() as uow:
        await uow.relationships.soft_delete(relationship.id)
    async with uow_factory() as uow:
        with pytest.raises(LookupError):
            await uow.relationships.soft_delete(relationship.id)

    async with uow_factory() as uow:
        after_history = await _history_count(uow, "relationship")
    assert after_history == before_history + 1  # only the successful DELETE


@pytest.mark.asyncio
@pytest.mark.integration
async def test_observation_evidence_provenance_is_relationally_enforced(
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> None:
    """A dangling Evidence reference is rejected and leaves no partial rows."""
    async with uow_factory() as uow:
        investigation_id = await seed_investigation(uow)
    service = extraction_service(uow_factory)
    evidence = dns_evidence(investigation_id)
    result = await service.persist(evidence, dns_extraction(require_id(evidence)))
    relationship = result.relationships[0]

    async with uow_factory() as uow:
        dangling = RelationshipObservation(
            id=uuid4(),
            relationship_id=relationship.id,
            evidence_id=uuid4(),  # no such Evidence row exists
            investigation_id=investigation_id,
            observed_at=None,
            retrieved_at=_RETRIEVED_AT,
            source=evidence.source,
        )
        with pytest.raises(IntegrityError):
            await uow.relationship_observations.append(dangling)

    async with uow_factory() as uow:
        assert await table_count(uow, "relationship_observation") == 1
        assert await _history_count(uow, "relationship_observation") == 1
        assert await table_count(uow, "relationship") == 1
        assert await table_count(uow, "evidence") == 1
