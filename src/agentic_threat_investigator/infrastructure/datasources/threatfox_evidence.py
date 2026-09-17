# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ThreatFox semantic-format Evidence conversion (PR 27D + PR 28A).

Owns the reference :class:`ThreatFoxToEvidenceConverter` for the
``urn:ati:datasource:semanticformat:threatfox`` semantic format and the
shared Evidence-specific ThreatFox mapping helpers. Both the legacy
``ThreatFoxProvider`` and this converter reuse the same timestamp
formatting and match-facts construction from this module — the mapping is
shared, never duplicated. The semantic parser
(``threatfox_semantics.py``) remains source validation only and constructs
no Evidence.

The converter maps one already-validated :class:`ThreatFoxRecord` plus the
explicit :class:`EvidenceConversionContext` to exactly one
``ConvertedEvidence``: a stable global ``THREAT_INTELLIGENCE``
:class:`Evidence` with a deterministic PR 28A identity pinned to
``semantic_format=THREATFOX``, ``source=THREATFOX`` and
``source_record_id=ThreatFoxRecord.id``, plus an
:class:`EvidenceObservationCandidate` carrying the credential-free source
reference, ``last_seen`` when present else ``first_seen`` as
``observed_at``, the acquisition retrieval time, normalized match facts,
and ``raw_payload=None``. Neither Investigation nor subject participates:
conversion is global and Investigation-independent. The converter performs
no I/O, no persistence, no clock/random reads, no secret lookup, never
allocates an observation version, and never synthesizes verdicts,
confidence, attribution, or relationships.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from agentic_threat_investigator.app.datasource_execution import (
    DatasourceExecutionRecorder,
)
from agentic_threat_investigator.app.datasource_provider import DatasourceProvider
from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStageError,
    SemanticAcquisitionResult,
)
from agentic_threat_investigator.app.evidence_conversion import (
    ConversionError,
    EvidenceConversionContext,
    ToEvidenceConverter,
    ToEvidenceConverterRegistry,
    convert_semantic_source_objects,
)
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.providers import (
    ProviderErrorCode,
    ProviderResult,
    provider_error_result,
)
from agentic_threat_investigator.domain.datasource import DatasourceDefinition
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceObservationCandidate,
    EvidenceType,
    evidence_id_for_source_record,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox import (
    ThreatFoxDatasource,
)
from agentic_threat_investigator.infrastructure.datasources.threatfox_semantics import (
    ThreatFoxRecord,
)

__all__ = [
    "ThreatFoxToEvidenceConverter",
    "build_threatfox_match_facts",
    "format_threatfox_fact_timestamp",
    "acquire_and_convert_threatfox_execution",
    "map_threatfox_stage_error",
    "build_threatfox_datasource_provider",
]


def format_threatfox_fact_timestamp(value: datetime) -> str:
    """Format an already validated timezone-aware UTC datetime as ``...Z``.

    Normalized ThreatFox fact timestamps use the canonical UTC ISO 8601
    form ending in ``Z``, for example ``2026-08-20T12:00:00Z``. Shared by
    the legacy provider and the PR 27D converter; the semantic parser
    remains source validation only.
    """
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_threatfox_match_facts(record: ThreatFoxRecord) -> dict[str, Any]:
    """Build one normalized match fact object from a validated record.

    Each match contains exactly the approved handoff keys. The malware
    machine identifier is retained verbatim as the canonical identity
    input for later deterministic entity discovery; the printable name is
    display metadata only. Timestamps are normalized to UTC ISO 8601,
    source order is preserved, and no derived risk labels, verdicts, or
    confidence weightings are ever synthesized. Source confidence remains
    a source fact.
    """
    return {
        "threatfox_id": record.id,
        "ioc": record.ioc,
        "ioc_type": record.ioc_type,
        "threat_type": record.threat_type,
        "threat_type_description": record.threat_type_desc,
        "malware": record.malware,
        "malware_printable": record.malware_printable,
        "confidence_level": record.confidence_level,
        "first_seen": format_threatfox_fact_timestamp(record.first_seen),
        "last_seen": (
            None
            if record.last_seen is None
            else format_threatfox_fact_timestamp(record.last_seen)
        ),
        "reference": record.reference,
        "tags": None if record.tags is None else list(record.tags),
    }


class ThreatFoxToEvidenceConverter(ToEvidenceConverter[ThreatFoxRecord]):
    """Semantic-format converter of validated ThreatFox records to Evidence.

    Consumes only already-validated :class:`ThreatFoxRecord` objects from
    the PR 27C ThreatFox semantic parser; it never re-parses raw JSON or
    re-runs semantic validation. One record maps to exactly one
    ``ConvertedEvidence``: a stable global ``THREAT_INTELLIGENCE``
    ``Evidence`` plus its ``EvidenceObservationCandidate``. The converter
    is stateless, deterministic, pure, and performs no I/O or persistence.
    """

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Return the ThreatFox semantic format owned by this converter."""
        return SemanticFormatId.THREATFOX

    def convert(
        self,
        source: ThreatFoxRecord,
        context: EvidenceConversionContext,
    ) -> tuple[ConvertedEvidence, ...]:
        """Convert one validated record into one global ConvertedEvidence.

        Fail-closed type guard: a non-``ThreatFoxRecord`` source raises a
        deterministic :class:`ConversionError` instead of guessing. The
        emitted Evidence carries the deterministic PR 28A identity pinned to
        the ThreatFox semantic format, source namespace, and the upstream
        ``source_record_id`` (``ThreatFoxRecord.id`` — never the IOC value,
        which is content/entity material, not identity). The observation
        candidate carries the credential-free source reference, the
        terminal or first-seen observation time as ``observed_at``, the
        semantic retrieval time, normalized match facts, and
        ``raw_payload=None``. No Investigation, subject, verdict,
        confidence, attribution, observation version, or diff is
        synthesized.
        """
        if not isinstance(source, ThreatFoxRecord):
            raise ConversionError(
                "ThreatFox converter requires a validated ThreatFoxRecord"
            )
        semantic = context.semantic_source
        evidence = Evidence(
            id=evidence_id_for_source_record(
                SemanticFormatId.THREATFOX,
                semantic.source_id,
                source.id,
            ),
            type=EvidenceType.THREAT_INTELLIGENCE,
            source=semantic.source_id.value,
            source_record_id=source.id,
        )
        candidate = EvidenceObservationCandidate(
            evidence_id=evidence.id,
            source_url=semantic.source_reference,
            observed_at=(
                source.last_seen if source.last_seen is not None else source.first_seen
            ),
            retrieved_at=semantic.retrieved_at,
            facts={"matches": [build_threatfox_match_facts(source)]},
            raw_payload=None,
        )
        return (ConvertedEvidence(evidence=evidence, observation=candidate),)


def build_threatfox_conversion_registry() -> ToEvidenceConverterRegistry:
    """Build the explicit production converter registry for ThreatFox.

    A tiny explicit factory; no global mutable registry, no decorator
    registration, no import-time side effect, and no plugin discovery.
    Only the ThreatFox reference converter is registered; additional
    semantic-format converters are added here as they land.
    """
    return ToEvidenceConverterRegistry(converters=(ThreatFoxToEvidenceConverter(),))


_DATASOURCE_STAGE_CODE_TO_PROVIDER_CODE: dict[str, ProviderErrorCode] = {
    "timeout": ProviderErrorCode.TIMEOUT,
    "rate_limited": ProviderErrorCode.RATE_LIMITED,
    "authentication_failed": ProviderErrorCode.AUTHENTICATION_FAILED,
    "forbidden": ProviderErrorCode.FORBIDDEN,
    "not_found": ProviderErrorCode.NOT_FOUND,
    "provider_unavailable": ProviderErrorCode.PROVIDER_UNAVAILABLE,
    "acquisition_failed": ProviderErrorCode.INVALID_RESPONSE,
    "serialization_failed": ProviderErrorCode.INVALID_RESPONSE,
    "semantic_validation_failed": ProviderErrorCode.INVALID_RESPONSE,
    "unsupported_indicator": ProviderErrorCode.UNSUPPORTED_INDICATOR,
}
"""Deterministic ThreatFox datasource-stage failure classification (PR 27E).

    Maps the typed bounded source-stage error codes emitted by the PR 27C
    ThreatFox acquirer onto the existing legacy ``ProviderErrorCode``
    vocabulary with no message-text parsing. Acquisition transport/status
    failures keep their natural codes; serialization, semantic-validation,
    and unknown acquisition-stage failures map to INVALID_RESPONSE exactly
    like the legacy provider's malformed-response classification. There is
    deliberately no "conversion_failed" entry: a conversion violation
    raises out of the adapter after recording the bounded
    ``conversion_failed`` lifecycle code and surfaces through the generic
    provider-error outcome path.
    """

_THREATFOX_ERROR_MESSAGE_BY_PROVIDER_CODE: dict[ProviderErrorCode, str] = {
    ProviderErrorCode.TIMEOUT: "ThreatFox request timed out",
    ProviderErrorCode.RATE_LIMITED: "ThreatFox rate limited",
    ProviderErrorCode.AUTHENTICATION_FAILED: "ThreatFox authentication failed",
    ProviderErrorCode.FORBIDDEN: "ThreatFox request forbidden",
    ProviderErrorCode.NOT_FOUND: "ThreatFox resource not found",
    ProviderErrorCode.PROVIDER_UNAVAILABLE: "ThreatFox provider unavailable",
    ProviderErrorCode.INVALID_RESPONSE: "invalid ThreatFox response",
    ProviderErrorCode.UNSUPPORTED_INDICATOR: "unsupported ThreatFox indicator",
}
"""Fixed safe message text per classified error code.

    Messages are constant per code and never interpolate exception text,
    response bodies, URLs, or credentials. Classification never parses
    free-form messages.
    """


def map_threatfox_stage_error(stage_error: DatasourceStageError) -> ProviderResult:
    """Map one typed bounded ThreatFox stage failure onto a legacy error result.

    The mapping is keyed only by the validated ``DatasourceStageError.code``
    (never by message text); an unknown code fails closed with a
    ``ValueError`` instead of misclassifying. The returned single-error
    ``ProviderResult`` carries the code's natural retryability and any
    provider-directed ``retry_after_seconds``.
    """
    provider_code = _DATASOURCE_STAGE_CODE_TO_PROVIDER_CODE.get(stage_error.code)
    if provider_code is None:
        raise ValueError(
            f"unmappable ThreatFox datasource error code: {stage_error.code}"
        )
    return provider_error_result(
        SourceId.THREATFOX.value,
        provider_code,
        _THREATFOX_ERROR_MESSAGE_BY_PROVIDER_CODE[provider_code],
        retry_after_seconds=stage_error.retry_after_seconds,
    )


def build_threatfox_datasource_provider(
    *,
    definition: DatasourceDefinition,
    datasource: ThreatFoxDatasource,
    uow_factory: Callable[[], UnitOfWork],
    clock: Callable[[], datetime] | None = None,
    registry: ToEvidenceConverterRegistry | None = None,
) -> DatasourceProvider[ThreatFoxRecord]:
    """Compose the production datasource-backed ThreatFox provider (PR 27E).

    Wraps the configured definition, the owned PR 27C acquirer, and the
    PR 27D semantic-format converter registry into the generic
    :class:`DatasourceProvider` adapter with the ThreatFox error mapping.
    ``uow_factory`` backs the PR 27B recorder's short lifecycle
    transactions; the adapter itself records no Observation persistence and
    performs no provider composition.
    """
    return DatasourceProvider(
        definition=definition,
        acquirer=datasource,
        registry=registry or build_threatfox_conversion_registry(),
        uow_factory=uow_factory,
        error_mapper=map_threatfox_stage_error,
        clock=clock,
    )


async def _best_effort_terminal(
    recorder: DatasourceExecutionRecorder,
    *,
    cancelled: bool,
    error_code: str = "unexpected_error",
) -> None:
    """Best-effort terminal recording that never masks the original outcome.

    Cancellation appends CANCELLED; other terminal recording appends FAILED
    with the given bounded safe code (``conversion_failed`` for conversion
    violations). A database failure during the append is ignored so the
    original outcome always propagates (mirrors the PR 27B recorder
    contract).
    """
    try:
        if cancelled:
            await recorder.cancel()
        else:
            await recorder.fail(error_code=error_code)
    except Exception:  # noqa: BLE001 - best-effort terminal recording must not mask the original outcome
        return


async def acquire_and_convert_threatfox_execution(
    *,
    datasource: ThreatFoxDatasource,
    definition: DatasourceDefinition,
    entity: Entity,
    registry: ToEvidenceConverterRegistry,
    uow_factory: Callable[[], UnitOfWork],
    clock: Callable[[], datetime] | None = None,
) -> tuple[SemanticAcquisitionResult[ThreatFoxRecord], tuple[ConvertedEvidence, ...]]:
    """Run one complete ThreatFox acquisition + conversion execution.

    Exercises the full PR 27D+28A lifecycle over one recorder and one
    ``execution_id``: STARTED, the acquirer's ACQUIRED/DECODED stage
    appends, pure in-memory conversion through the semantic-format-selected
    converter into global :class:`ConvertedEvidence` values, CONVERTED with
    the exact produced count, then COMPLETED. Conversion carries no
    Investigation and no subject binding: it is global and
    Investigation-independent. A valid no-result records CONVERTED
    item_count=0 as success; a typed acquisition failure records FAILED with
    the bounded safe code and returns no ConvertedEvidence; a conversion
    violation records FAILED with ``conversion_failed`` and never CONVERTED;
    ``CancelledError`` records CANCELLED (best effort) and always
    propagates. No exception text, source body, or credential is ever
    persisted, and no Evidence is persisted by this runner.
    """
    recorder = DatasourceExecutionRecorder(
        definition.datasource_id,
        uow_factory=uow_factory,
        clock=clock,
    )
    await recorder.start()
    try:
        result = await datasource.acquire(
            definition=definition, entity=entity, recorder=recorder
        )
    except asyncio.CancelledError:
        await _best_effort_terminal(recorder, cancelled=True)
        raise
    except Exception:
        await _best_effort_terminal(recorder, cancelled=False)
        raise

    if result.error is not None:
        await recorder.fail(error_code=result.error.code)
        return result, ()

    context = EvidenceConversionContext(semantic_source=result.context)
    try:
        converted = convert_semantic_source_objects(result.objects, context, registry)
    except asyncio.CancelledError:
        await _best_effort_terminal(recorder, cancelled=True)
        raise
    except Exception:
        await _best_effort_terminal(
            recorder, cancelled=False, error_code="conversion_failed"
        )
        raise

    await recorder.converted(item_count=len(converted))
    await recorder.complete()
    return result, converted
