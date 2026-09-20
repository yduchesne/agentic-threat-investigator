# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL repository telemetry structural coverage (PR 29A-1).

Every public method of every concrete PostgreSQL repository/resolver that can
execute PostgreSQL I/O must carry ``@postgres_repository_operation``
telemetry. Rather than parsing source text, the test:

- walks the actual classes of the postgresql package and compares their
  public methods to the ``@postgres_repository_operation`` registry filled at
  decoration time; and
- pins the result against a committed reviewed inventory so a new public I/O
  method (or a typo'd decorator) fails with a useful message.
"""

from __future__ import annotations

from functools import lru_cache
from types import FunctionType

from agentic_threat_investigator.telemetry.decorators import (
    registered_postgres_repository_operations,
)

_REVIEWED_INVENTORY: dict[str, frozenset[str]] = {
    "PostgresAssessmentRepository": frozenset(
        {"get_by_id", "insert", "list_for_investigation", "soft_delete"}
    ),
    "PostgresAuditEventRepository": frozenset({"append", "list_events"}),
    "PostgresCanonicalGeographyResolver": frozenset({"resolve"}),
    "PostgresCredentialRepository": frozenset({"create", "get_by_user_id", "replace"}),
    "PostgresDatasourceLogRepository": frozenset({"append"}),
    "PostgresDocumentChunkRepository": frozenset({"list_by_document", "replace_batch"}),
    "PostgresDocumentRepository": frozenset({"get_by_identity", "upsert_batch"}),
    "PostgresEntityLocationObservationRepository": frozenset(
        {"append", "get_by_id", "list_for_entity"}
    ),
    "PostgresEntityLocationRepository": frozenset({"get_by_entity_id"}),
    "PostgresEntityRepository": frozenset(
        {"get_by_id", "get_by_identity", "soft_delete", "upsert", "upsert_batch"}
    ),
    "PostgresEvidenceBatchRepository": frozenset({"persist_batch"}),
    "PostgresEvidenceObservationEntityRepository": frozenset(
        {"associate", "list_for_observation"}
    ),
    "PostgresEvidenceRepository": frozenset(
        {
            "get_observation",
            "get_stable_evidence",
            "list_for_investigation",
            "list_observations",
            "persist",
        }
    ),
    "PostgresGeoResolutionRepository": frozenset(
        {
            "claim_batch",
            "complete_resolved",
            "complete_unresolvable",
            "create_pending",
            "get_by_entity_evidence",
            "get_by_id",
            "record_failure",
        }
    ),
    "PostgresIdempotencyRepository": frozenset({"get", "insert_if_absent"}),
    "PostgresIngestionCheckpointRepository": frozenset({"get", "put", "reset"}),
    "PostgresInvestigationEvidenceRepository": frozenset(
        {"admit", "list_for_investigation"}
    ),
    "PostgresInvestigationJobRepository": frozenset(
        {"claim_next", "complete", "create", "get_by_investigation"}
    ),
    "PostgresInvestigationReportRepository": frozenset(
        {"append", "get_by_id", "soft_delete"}
    ),
    "PostgresInvestigationRepository": frozenset(
        {
            "create",
            "get_by_id",
            "set_analysis_result",
            "soft_delete",
            "update_assessment_reference",
            "update_budget",
            "update_coordinator_state",
            "update_report_reference",
            "update_status",
        }
    ),
    "PostgresInvestigationTimelineRepository": frozenset(
        {"append", "list_by_investigation"}
    ),
    "PostgresLocationRepository": frozenset(
        {"get_by_id", "get_by_identity", "upsert", "upsert_reference"}
    ),
    "PostgresRelationshipObservationRepository": frozenset(
        {"append", "get_by_id", "list_for_investigation"}
    ),
    "PostgresRelationshipRepository": frozenset(
        {"get_by_id", "get_by_identity", "soft_delete", "upsert"}
    ),
    "PostgresResearchResultRepository": frozenset(
        {"add", "get_by_id", "list_by_investigation"}
    ),
    "PostgresSessionRepository": frozenset(
        {
            "create",
            "get_by_token_hash",
            "revoke",
            "revoke_by_token_hash",
            "revoke_by_user_id",
            "touch",
        }
    ),
    "PostgresSourceRecordRepository": frozenset(
        {"get_by_id", "get_by_identity", "upsert_batch"}
    ),
    "PostgresUserRepository": frozenset(
        {"count", "count_enabled_admins", "create", "get_by_id", "get_by_username"}
    ),
}

#: Public methods that deliberately perform no database I/O and therefore
#: need no repository-operation telemetry. Currently empty; add an explicit
#: entry (with review) when such a helper is introduced on a repository class.
_PUBLIC_NON_IO_ALLOWLIST: dict[str, frozenset[str]] = {}


@lru_cache
def _walk_public_io_operations() -> frozenset[tuple[str, str]]:
    """Return ``(class name, public method)`` for every PostgreSQL repository.

    Imports each concrete adapter module (populating the decorator registry),
    then walks the classes *defined inside the postgresql package*, excluding
    ``PostgresUnitOfWork`` (instrumented separately) and the ORM ``models``.
    """
    import importlib
    import pkgutil

    import agentic_threat_investigator.infrastructure.persistence.postgresql as pkg

    module_names = [
        module.name
        for module in pkgutil.iter_modules(pkg.__path__)
        if module.name
        in {
            "assessment_repositories",
            "audit_repositories",
            "canonical_geography_resolver",
            "datasource_log_repositories",
            "evidence_batch_repositories",
            "evidence_repositories",
            "geoint_repositories",
            "identity_repositories",
            "investigation_job_repositories",
            "investigation_repositories",
            "rag_repositories",
            "relationship_repositories",
            "report_repositories",
            "repositories",
            "source_repositories",
            "timeline_repositories",
        }
    ]
    operations: set[tuple[str, str]] = set()
    for module_name in module_names:
        module = importlib.import_module(f"{pkg.__name__}.{module_name}")
        for _name, cls in vars(module).items():
            if not isinstance(cls, type) or not cls.__name__.startswith("Postgres"):
                continue
            if cls.__name__ == "PostgresUnitOfWork":
                continue
            if not cls.__module__.startswith(pkg.__name__):
                continue
            for method_name, member in cls.__dict__.items():
                if method_name.startswith("_"):
                    continue
                if not isinstance(member, FunctionType):
                    continue
                if method_name in _PUBLIC_NON_IO_ALLOWLIST.get(cls.__name__, ()):
                    continue
                operations.add((cls.__name__, method_name))
    return frozenset(operations)


def _reviewed_operations() -> frozenset[tuple[str, str]]:
    """Flatten the committed reviewed inventory into ``(class, method)`` pairs."""
    return frozenset(
        (cls_name, method)
        for cls_name, methods in _REVIEWED_INVENTORY.items()
        for method in methods
    )


class TestPostgresRepositoryCoverage:
    """Structural coverage of PostgreSQL repository operation telemetry."""

    def test_reviewed_inventory_matches_walk(self) -> None:
        """The committed inventory exactly matches the current repository surface.

        A mismatch means the inventory must be updated by review, or a public
        repository method was added/removed/renamed.
        """
        walk = _walk_public_io_operations()
        if walk != _reviewed_operations():
            missing = sorted(_reviewed_operations() - walk)
            unexpected = sorted(walk - _reviewed_operations())
            raise AssertionError(
                "postgres repository reviewed inventory out of date: "
                f"methods in inventory but absent from code={missing} "
                f"methods in code but absent from inventory={unexpected}"
            )

    def test_every_public_io_method_instrumented(self) -> None:
        """No public repository I/O method lacks repository telemetry (PG-R9)."""
        registered = registered_postgres_repository_operations()
        walk = _walk_public_io_operations()
        missing = sorted(walk - registered)
        assert not missing, (
            "PostgreSQL repository I/O methods without "
            "@postgres_repository_operation telemetry: "
            + ", ".join(f"{cls}.{op}" for cls, op in missing)
        )

    def test_no_unexpected_registrations(self) -> None:
        """Every real-class registry entry matches a real public method.

        Catches typo'd repository/operation names on real classes; entries
        registered by test-only fake classes outside the postgres package do
        not describe real repository operations and are intentionally allowed
        to exist for decorator unit tests.
        """
        registered = registered_postgres_repository_operations()
        walk = _walk_public_io_operations()
        real_classes = {cls for cls, _op in walk}
        bogus = sorted(
            (cls, op)
            for cls, op in registered
            if cls in real_classes and (cls, op) not in walk
        )
        assert not bogus, (
            "postgres_repository_operation registry names no real public "
            "repository method: " + ", ".join(f"{cls}.{op}" for cls, op in bogus)
        )
