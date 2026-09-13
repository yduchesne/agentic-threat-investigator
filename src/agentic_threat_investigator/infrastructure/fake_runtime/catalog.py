# SPDX-License-Identifier: AGPL-3.0-only
"""Versioned synthetic-world catalog and strict fixture loader (PR 23D).

The catalog is the single deterministic resolver between named fake
scenarios, provider lookups, and batch artifacts:

```text
scenario_for_root_indicator(entity)   -> scenario ID (stable entry point)
provider_response(provider_id, entity, retrieved_at)
                                      -> bounded fixture observations
batch_artifacts()                     -> packaged batch fixture bindings
```

Scenarios are entry points into one shared deterministic synthetic world,
not isolated bags of facts: provider lookups resolve against the shared
world keyed by canonical entity identity, so pivots to related entities keep
returning deterministic world data. The catalog is a local fixture lookup —
never a domain repository, never PostgreSQL persistence, and never a
simulation engine.

Loading is strict and fails closed on malformed or duplicate definitions so
a fixture error surfaces at startup/test loading instead of producing
silently inconsistent fake intelligence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import PurePosixPath
from typing import Any
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from agentic_threat_investigator.app.extraction.extractor import extract
from agentic_threat_investigator.app.providers import (
    ProviderError,
    ProviderErrorCode,
)
from agentic_threat_investigator.domain.entities import EntityType, canonicalize
from agentic_threat_investigator.domain.evidence import EntityRef as EvidenceEntityRef
from agentic_threat_investigator.domain.evidence import Evidence, EvidenceType
from agentic_threat_investigator.domain.identifiers import SourceId

FAKE_WORLD_SCHEMA_VERSION = 1
"""Supported synthetic-world schema version (PR 23D)."""

FAKE_WORLD_ID = "fake_world_v1"
"""Repository-owned synthetic-world identity (PR 23D)."""

_PACKAGE = "agentic_threat_investigator.infrastructure.fake_runtime"
_DATA_DIR = "data"
_WORLD_FILE = "v1/world.json"
_SCENARIOS_FILE = "v1/scenarios.json"

_LIVE_PROVIDER_SOURCE_IDS = frozenset(
    {
        SourceId.GOOGLE_PUBLIC_DNS.value,
        SourceId.RDAP.value,
        SourceId.IPINFO_LITE.value,
        SourceId.ABUSEIPDB.value,
        SourceId.THREATFOX.value,
        SourceId.URLHAUS.value,
    }
)
"""Source IDs supported by deterministic fake live providers (PR 23D)."""


class FakeWorldValidationError(ValueError):
    """Raised when a synthetic-world or scenario fixture is invalid.

    The message is a fixed safe string that never embeds fixture payloads.
    """


class FakeObservation(BaseModel):
    """One deterministic source-semantic observation for a provider lookup.

    ``observed_at`` is the time the source would have represented for this
    observation; the provider stamps ``retrieved_at`` separately from the
    injected clock. ``facts`` is the normalized fact payload the real
    provider contract produces for that evidence type.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_type: EvidenceType
    observed_at: datetime | None = None
    facts: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: datetime | None) -> datetime | None:
        """Require a timezone-aware observation time, normalized to UTC."""
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise FakeWorldValidationError(
                "fake observation timestamps must be timezone-aware"
            )
        return value.astimezone(UTC)


class FakeProviderErrorData(BaseModel):
    """Bounded provider-error fixture for deterministic error scenarios."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code: ProviderErrorCode
    message: str = Field(min_length=1)

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        """Trim and reject blank messages."""
        stripped = value.strip()
        if not stripped:
            raise FakeWorldValidationError(
                "fake provider error message must not be blank"
            )
        return stripped


class FakeProviderResultData(BaseModel):
    """World definition for one provider lookup on one canonical entity.

    Exactly one terminal shape is allowed per lookup: a non-empty
    ``observations`` list, an explicit ``no_result`` marker, or a typed
    ``error``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider_id: str
    entity_type: EntityType
    entity_value: str
    observations: tuple[FakeObservation, ...] = ()
    no_result: bool = False
    error: FakeProviderErrorData | None = None

    @field_validator("provider_id")
    @classmethod
    def validate_provider_id(cls, value: str) -> str:
        """Require a known live fake provider identity."""
        if value not in _LIVE_PROVIDER_SOURCE_IDS:
            raise FakeWorldValidationError(
                "fake provider result references an unsupported provider"
            )
        return value

    @field_validator("entity_value")
    @classmethod
    def validate_entity_value(cls, value: str) -> str:
        """Reject blank entity values; canonical form is checked per type."""
        if not value.strip():
            raise FakeWorldValidationError("fake entity value must not be blank")
        return value

    @model_validator(mode="after")
    def validate_lookup_shape(self) -> "FakeProviderResultData":
        """Require exactly one of observations, no-result, or error."""
        has_observations = bool(self.observations)
        markers = sum((has_observations, self.no_result, self.error is not None))
        if markers != 1:
            raise FakeWorldValidationError(
                "fake provider lookup must be observations, no_result, or error"
            )
        return self

    @model_validator(mode="after")
    def validate_canonical_identity(self) -> "FakeProviderResultData":
        """Require the entity value to already be in canonical form.

        The fake world keys lookups by canonical identity; a fixture value
        that canonicalizes differently would silently create an unreachable
        lookup and is a contract failure.
        """
        try:
            canonical = canonicalize(self.entity_type, self.entity_value)
        except ValueError as exc:
            raise FakeWorldValidationError(
                "fake entity value violates its type contract"
            ) from exc
        if canonical != self.entity_value:
            raise FakeWorldValidationError("fake entity value is not in canonical form")
        return self


class FakeBatchArtifactData(BaseModel):
    """Binding of one packaged batch fixture to a datasets-store location."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_id: str
    package_path: str
    dataset_path: str

    @field_validator("source_id")
    @classmethod
    def validate_source_id(cls, value: str) -> str:
        """Require a known batch-source identity."""
        if value != SourceId.MITRE_ATTACK.value:
            raise FakeWorldValidationError(
                "fake batch artifact references an unsupported source"
            )
        return value

    @field_validator("package_path", "dataset_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        """Reject absolute paths, traversal, and drive/backslash escapes."""
        candidate = value.strip()
        if not candidate:
            raise FakeWorldValidationError("fake artifact path must not be blank")
        if candidate.startswith("/") or "\\" in candidate:
            raise FakeWorldValidationError("fake artifact path must be relative")
        path = PurePosixPath(candidate)
        if ".." in path.parts:
            raise FakeWorldValidationError("fake artifact path must not traverse")
        if not path.parts:
            raise FakeWorldValidationError("fake artifact path must not be empty")
        return candidate


class FakeWorldData(BaseModel):
    """Top-level versioned synthetic-world definition."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int
    world_id: str
    provider_results: tuple[FakeProviderResultData, ...] = ()
    batch_artifacts: tuple[FakeBatchArtifactData, ...] = ()

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: int) -> int:
        """Reject unsupported schema versions."""
        if value != FAKE_WORLD_SCHEMA_VERSION:
            raise FakeWorldValidationError("unsupported fake world schema version")
        return value

    @field_validator("world_id")
    @classmethod
    def validate_world_id(cls, value: str) -> str:
        """Require the exact supported world identity."""
        if value != FAKE_WORLD_ID:
            raise FakeWorldValidationError("unsupported fake world identity")
        return value

    @model_validator(mode="after")
    def validate_duplicate_lookups(self) -> "FakeWorldData":
        """Reject duplicate provider/entity lookup keys."""
        seen: set[tuple[str, EntityType, str]] = set()
        for result in self.provider_results:
            key = (result.provider_id, result.entity_type, result.entity_value)
            if key in seen:
                raise FakeWorldValidationError(
                    "fake world contains duplicate provider lookups"
                )
            seen.add(key)
        return self


class FakeRootIndicatorData(BaseModel):
    """One canonical scenario root indicator."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: EntityType
    value: str

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        """Reject blank values."""
        if not value.strip():
            raise FakeWorldValidationError("scenario root indicator must not be blank")
        return value

    @model_validator(mode="after")
    def validate_canonical_value(self) -> "FakeRootIndicatorData":
        """Require the root indicator to be canonical."""
        try:
            canonical = canonicalize(self.type, self.value)
        except ValueError as exc:
            raise FakeWorldValidationError(
                "scenario root indicator violates its type contract"
            ) from exc
        if canonical != self.value:
            raise FakeWorldValidationError(
                "scenario root indicator is not in canonical form"
            )
        return self


class FakeScenarioData(BaseModel):
    """One named deterministic scenario entry point."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scenario_id: str
    description: str
    root_indicators: tuple[FakeRootIndicatorData, ...] = Field(min_length=1)

    @field_validator("scenario_id", "description")
    @classmethod
    def validate_nonblank(cls, value: str) -> str:
        """Trim and reject blank identifiers/descriptions."""
        stripped = value.strip()
        if not stripped:
            raise FakeWorldValidationError(
                "scenario id and description must not be blank"
            )
        return stripped

    @model_validator(mode="after")
    def validate_duplicate_roots(self) -> "FakeScenarioData":
        """Reject duplicate root indicator keys within one scenario."""
        seen: set[tuple[EntityType, str]] = set()
        for indicator in self.root_indicators:
            key = (indicator.type, indicator.value)
            if key in seen:
                raise FakeWorldValidationError(
                    "scenario contains duplicate root indicators"
                )
            seen.add(key)
        return self


class FakeScenarioCollection(BaseModel):
    """Top-level versioned scenario collection."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: int
    world_id: str
    scenarios: tuple[FakeScenarioData, ...] = ()

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, value: int) -> int:
        """Reject unsupported schema versions."""
        if value != FAKE_WORLD_SCHEMA_VERSION:
            raise FakeWorldValidationError("unsupported scenario schema version")
        return value

    @field_validator("world_id")
    @classmethod
    def validate_world_id(cls, value: str) -> str:
        """Require the world the scenario collection belongs to."""
        if value != FAKE_WORLD_ID:
            raise FakeWorldValidationError("unsupported scenario world identity")
        return value

    @model_validator(mode="after")
    def validate_unique_scenarios(self) -> "FakeScenarioCollection":
        """Reject duplicate scenario IDs and root indicator keys."""
        scenario_ids: set[str] = set()
        roots: set[tuple[EntityType, str]] = set()
        for scenario in self.scenarios:
            if scenario.scenario_id in scenario_ids:
                raise FakeWorldValidationError("duplicate scenario id")
            scenario_ids.add(scenario.scenario_id)
            for indicator in scenario.root_indicators:
                key = (indicator.type, indicator.value)
                if key in roots:
                    raise FakeWorldValidationError(
                        "duplicate root indicator across scenarios"
                    )
                roots.add(key)
        return self


@dataclass(frozen=True)
class FakeProviderResponse:
    """Deterministic provider lookup outcome from the catalog."""

    observations: tuple[FakeObservation, ...] = ()
    error: ProviderError | None = None


class FakeWorldCatalog:
    """Immutable deterministic resolver over the loaded synthetic world.

    The catalog is constructed from validated world/scenario definitions and
    then never mutates. Lookups are pure: no clock, random source, network,
    database, or LLM access.
    """

    def __init__(
        self,
        world: FakeWorldData,
        scenarios: FakeScenarioCollection,
    ) -> None:
        """Build the immutable lookup maps and validate world references.

        Every scenario root indicator must resolve to world provider data so
        a named scenario can never be an empty dead end by accident; unknown
        non-scenario indicators remain deterministic no-results.
        """
        results: dict[tuple[str, EntityType, str], FakeProviderResultData] = {}
        for result in world.provider_results:
            results[(result.provider_id, result.entity_type, result.entity_value)] = (
                result
            )
        self._results = results
        self._batch_artifacts = world.batch_artifacts

        roots: dict[tuple[EntityType, str], str] = {}
        for scenario in scenarios.scenarios:
            for indicator in scenario.root_indicators:
                key = (indicator.type, indicator.value)
                roots[key] = scenario.scenario_id
        self._roots = roots
        self._validate_scenario_references()

    @classmethod
    def load_packaged(cls) -> FakeWorldCatalog:
        """Load and validate the repository-owned packaged world version."""
        world_bytes = (
            resources.files(_PACKAGE)
            .joinpath(_DATA_DIR)
            .joinpath(_WORLD_FILE)
            .read_bytes()
        )
        scenarios_bytes = (
            resources.files(_PACKAGE)
            .joinpath(_DATA_DIR)
            .joinpath(_SCENARIOS_FILE)
            .read_bytes()
        )
        return cls.load(world_bytes, scenarios_bytes)

    @classmethod
    def load(cls, world_bytes: bytes, scenarios_bytes: bytes) -> FakeWorldCatalog:
        """Load and validate world/scenario fixtures from their JSON bytes."""
        try:
            world_json = json.loads(world_bytes.decode("utf-8"))
            scenarios_json = json.loads(scenarios_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FakeWorldValidationError(
                "fake world fixtures must be valid UTF-8 JSON"
            ) from exc
        if not isinstance(world_json, dict) or not isinstance(scenarios_json, dict):
            raise FakeWorldValidationError("fake world fixtures must be JSON objects")
        try:
            world = FakeWorldData.model_validate(world_json)
            scenarios = FakeScenarioCollection.model_validate(scenarios_json)
        except ValidationError as exc:
            raise FakeWorldValidationError(
                "fake world fixture validation failed"
            ) from exc
        catalog = cls(world, scenarios)
        catalog._validate_evidence_contracts(world)
        return catalog

    def _validate_scenario_references(self) -> None:
        """Require every scenario root to resolve to world data or research.

        A root either resolves to at least one provider lookup in the shared
        world or is a RESEARCHABLE entity type whose investigation path is the
        research lifecycle (never a provider call).
        """
        researchable = {
            EntityType.MALWARE,
            EntityType.ATTACK_TECHNIQUE,
            EntityType.VULNERABILITY,
        }
        for (entity_type, value), _scenario_id in self._roots.items():
            if entity_type in researchable:
                continue
            if not any(
                (provider_id, entity_type, value) in self._results
                for provider_id in _LIVE_PROVIDER_SOURCE_IDS
            ):
                raise FakeWorldValidationError(
                    "scenario root indicator does not resolve to world provider data"
                )

    def _validate_evidence_contracts(self, world: FakeWorldData) -> None:
        """Prove every observation is extractable through the real contracts.

        Each observation is built into an ``Evidence`` with a synthetic ID
        and dispatched through the production extraction dispatcher; a
        contract violation fails loading instead of surfacing mid-investigation.
        """
        retrieved_at = datetime(2026, 1, 1, tzinfo=UTC)
        for result in world.provider_results:
            for observation in result.observations:
                evidence = Evidence(
                    id=uuid4(),
                    investigation_id=uuid4(),
                    type=observation.evidence_type,
                    subject=EvidenceEntityRef(
                        type=result.entity_type, value=result.entity_value
                    ),
                    source=result.provider_id,
                    observed_at=observation.observed_at,
                    retrieved_at=retrieved_at,
                    facts=observation.facts,
                )
                try:
                    extract(evidence)
                except Exception as exc:
                    raise FakeWorldValidationError(
                        "fake observation violates the provider extraction contract"
                    ) from exc

    def scenario_for_root_indicator(
        self, entity_type: EntityType, value: str
    ) -> str | None:
        """Return the named scenario anchored at the canonical indicator, or None.

        An unknown indicator deterministically resolves to ``None`` (the
        catalog never fabricates scenario membership).
        """
        return self._roots.get((entity_type, value))

    def provider_response(
        self,
        provider_id: str,
        entity_type: EntityType,
        entity_value: str,
        retrieved_at: datetime,
    ) -> FakeProviderResponse:
        """Return the deterministic provider lookup for one canonical entity.

        Observations whose ``observed_at`` lies in the future of the injected
        retrieval clock are withheld, modeling a source with a semantic
        history; an unknown lookup or an all-future observation set is a
        deterministic no-result, never random or fabricated data.
        """
        result = self._results.get((provider_id, entity_type, entity_value))
        if result is None:
            return FakeProviderResponse()
        if result.no_result:
            return FakeProviderResponse()
        if result.error is not None:
            error = ProviderError(
                provider=provider_id,
                code=result.error.code,
                message=result.error.message,
                retryable=result.error.code.retryable,
            )
            return FakeProviderResponse(error=error)
        selected = tuple(
            observation
            for observation in result.observations
            if observation.observed_at is None
            or observation.observed_at <= retrieved_at
        )
        return FakeProviderResponse(observations=selected)

    def batch_artifacts(self) -> tuple[FakeBatchArtifactData, ...]:
        """Return the packaged batch fixture bindings for this world."""
        return self._batch_artifacts

    @staticmethod
    def load_batch_artifact_bytes(package_path: str) -> bytes:
        """Read one packaged batch fixture, rejecting unsafe paths."""
        path = PurePosixPath(package_path)
        if path.is_absolute() or ".." in path.parts:
            raise FakeWorldValidationError("unsafe fake batch artifact path")
        try:
            return (
                resources.files(_PACKAGE)
                .joinpath(_DATA_DIR)
                .joinpath(*path.parts)
                .read_bytes()
            )
        except FileNotFoundError as exc:
            raise FakeWorldValidationError("fake batch artifact is missing") from exc
