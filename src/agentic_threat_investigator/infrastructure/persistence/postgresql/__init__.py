"""PostgreSQL persistence infrastructure."""

from .database import PostgresUnitOfWork, create_engine_and_session_factory
from .models import (
    Base,
    EntityRow,
    IngestionCheckpointRow,
    RelationshipObservationRow,
    RelationshipRow,
    SourceRecordRow,
)
from .repositories import PostgresEntityRepository
from .source_repositories import (
    PostgresIngestionCheckpointRepository,
    PostgresSourceRecordRepository,
)

__all__ = [
    "Base",
    "EntityRow",
    "IngestionCheckpointRow",
    "RelationshipObservationRow",
    "RelationshipRow",
    "SourceRecordRow",
    "PostgresIngestionCheckpointRepository",
    "PostgresSourceRecordRepository",
    "PostgresUnitOfWork",
    "create_engine_and_session_factory",
    "PostgresEntityRepository",
]
