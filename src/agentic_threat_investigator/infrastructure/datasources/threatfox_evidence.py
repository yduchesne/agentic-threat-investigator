# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ThreatFox semantic-format Evidence conversion (PR 27D).

Owns the reference :class:`ThreatFoxToEvidenceConverter` for the
``urn:ati:datasource:semanticformat:threatfox`` semantic format and the
shared Evidence-specific ThreatFox mapping helpers. Both the legacy
``ThreatFoxProvider`` and this converter reuse the same timestamp
formatting and match-facts construction from this module — the mapping is
shared, never duplicated. The semantic parser
(``threatfox_semantics.py``) remains source validation only and constructs
no Evidence.

The converter maps one already-validated :class:`ThreatFoxRecord` plus the
explicit :class:`EvidenceConversionContext` to exactly one immutable
``THREAT_INTELLIGENCE`` Evidence with exact provenance: the context's
Investigation and canonical subject, the semantic source URN and retrieval
time, the credential-free source reference, ``last_seen`` when present
else ``first_seen`` as ``observed_at``, normalized match facts, and
``raw_payload=None``. ``source_record_id`` carries the upstream
ThreatFox record identity (``ThreatFoxRecord.id``) as a plain provenance
fact; it never assigns ATI persistent identity. The converter performs no
I/O, no persistence, no clock/random reads, no secret lookup, and never
synthesizes verdicts, confidence, attribution, or relationships.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from agentic_threat_investigator.app.datasource_execution import (
    DatasourceExecutionRecorder,
)
from agentic_threat_investigator.app.datasource_semantics import (
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
from agentic_threat_investigator.domain.datasource import DatasourceDefinition
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import SemanticFormatId
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
    re-runs semantic validation. One record maps to exactly one immutable
    ``THREAT_INTELLIGENCE`` Evidence carrying the exact conversion context
    provenance. The converter is stateless, deterministic, pure, and
    performs no I/O or persistence.
    """

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Return the ThreatFox semantic format owned by this converter."""
        return SemanticFormatId.THREATFOX

    def convert(
        self,
        source: ThreatFoxRecord,
        context: EvidenceConversionContext,
    ) -> tuple[Evidence, ...]:
        """Convert one validated record into one immutable Evidence.

        Fail-closed type guard: a non-``ThreatFoxRecord`` source raises a
        deterministic :class:`ConversionError` instead of guessing. The
        emitted Evidence retains the exact Investigation, subject (the
        canonical acquisition entity binding), semantic source URN,
        retrieval time, credential-free source reference, and the upstream
        ``source_record_id``; the terminal or first-seen observation time
        is preserved as ``observed_at``. No ATI Evidence ID is assigned,
        no verdict/confidence/attribution is synthesized, and
        ``raw_payload`` stays ``None``.
        """
        if not isinstance(source, ThreatFoxRecord):
            raise ConversionError(
                "ThreatFox converter requires a validated ThreatFoxRecord"
            )
        semantic = context.semantic_source
        evidence = Evidence(
            investigation_id=context.investigation_id,
            type=EvidenceType.THREAT_INTELLIGENCE,
            subject=context.subject,
            source=semantic.source_id.value,
            source_record_id=source.id,
            source_url=semantic.source_reference,
            observed_at=(
                source.last_seen if source.last_seen is not None else source.first_seen
            ),
            retrieved_at=semantic.retrieved_at,
            facts={"matches": [build_threatfox_match_facts(source)]},
            raw_payload=None,
        )
        return (evidence,)


def build_threatfox_conversion_registry() -> ToEvidenceConverterRegistry:
    """Build the explicit production converter registry for ThreatFox.

    A tiny explicit factory; no global mutable registry, no decorator
    registration, no import-time side effect, and no plugin discovery.
    Only the ThreatFox reference converter is registered; additional
    semantic-format converters are added here as they land.
    """
    return ToEvidenceConverterRegistry(converters=(ThreatFoxToEvidenceConverter(),))


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
    investigation_id: UUID,
    subject: EntityRef,
    registry: ToEvidenceConverterRegistry,
    uow_factory: Callable[[], UnitOfWork],
    clock: Callable[[], datetime] | None = None,
) -> tuple[SemanticAcquisitionResult[ThreatFoxRecord], tuple[Evidence, ...]]:
    """Run one complete ThreatFox acquisition + conversion execution.

    Exercises the full PR 27D lifecycle over one recorder and one
    ``execution_id``: STARTED, the acquirer's ACQUIRED/DECODED stage
    appends, pure in-memory conversion through the semantic-format-selected
    converter, CONVERTED with the exact produced Evidence count, then
    COMPLETED. A valid no-result records CONVERTED item_count=0 as success;
    a typed acquisition failure records FAILED with the bounded safe code
    and returns no Evidence; a conversion violation records FAILED with
    ``conversion_failed`` and never CONVERTED; ``CancelledError`` records
    CANCELLED (best effort) and always propagates. No exception text,
    source body, or credential is ever persisted, and no Evidence is
    persisted by this runner.
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

    context = EvidenceConversionContext(
        investigation_id=investigation_id,
        subject=subject,
        semantic_source=result.context,
    )
    try:
        evidence = convert_semantic_source_objects(result.objects, context, registry)
    except asyncio.CancelledError:
        await _best_effort_terminal(recorder, cancelled=True)
        raise
    except Exception:
        await _best_effort_terminal(
            recorder, cancelled=False, error_code="conversion_failed"
        )
        raise

    await recorder.converted(item_count=len(evidence))
    await recorder.complete()
    return result, evidence
