# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the Report Writer execution service (PR 23B).

A scripted :class:`FakeLlmClient` drives the model boundary, a deterministic
accounting fake records every durable reservation, and a recording
persistence fake captures every persisted report. No real external model or
database participates.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import cast
from uuid import UUID

import pytest

from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.app.persistence.repositories import UnitOfWork
from agentic_threat_investigator.app.report_writer.errors import (
    ReportProvenanceError,
)
from agentic_threat_investigator.app.report_writer.input_loader import (
    ReportWriterInputLoader,
)
from agentic_threat_investigator.app.report_writer.persistence import (
    InvestigationReportPersistenceService,
)
from agentic_threat_investigator.app.report_writer.prompts import (
    OPERATION_REPORT_WRITING,
)
from agentic_threat_investigator.app.report_writer.writer import ReportWriter
from agentic_threat_investigator.domain.report import (
    InvestigationReport,
    ReportWriterInput,
)
from tests.support.llm_fixtures import FakeLlmClient
from tests.support.report_writer_unit import ReportWriterUnitWorld


class FakeLoader(ReportWriterInputLoader):
    """Loader stand-in serving a prebuilt input and optional failure."""

    def __init__(self, report_input: ReportWriterInput) -> None:
        """Bind the deterministic input; the base factory stays unused."""
        super().__init__(cast(Callable[[], UnitOfWork], lambda: None))
        self._report_input = report_input
        self.fail: Exception | None = None
        self.calls = 0

    async def load(self, investigation_id: UUID) -> ReportWriterInput:
        """Return the prebuilt input, raising when configured to fail."""
        self.calls += 1
        if self.fail is not None:
            raise self.fail
        return self._report_input


class FakeAccounting(LlmAccountingService):
    """Records every durable reservation and returns incrementing versions."""

    def __init__(self) -> None:
        """Bind a dummy factory; reservations are tracked locally."""
        super().__init__(cast(Callable[[], UnitOfWork], lambda: None))
        self.reservations: list[tuple[UUID, int | None]] = []
        self._version = 10

    async def reserve_call(
        self,
        investigation_id: UUID,
        *,
        expected_version: int | None = None,
    ) -> int:
        """Record and return the next durable Investigation version."""
        self.reservations.append((investigation_id, expected_version))
        self._version += 1
        return self._version


class FakePersistence(InvestigationReportPersistenceService):
    """Records every persisted report candidate."""

    def __init__(self) -> None:
        """Bind a dummy factory; persistence is recorded locally."""
        super().__init__(cast(Callable[[], UnitOfWork], lambda: None))
        self.persisted: list[InvestigationReport] = []
        self.fail: Exception | None = None

    async def persist(
        self,
        report: InvestigationReport,
        *,
        actor_id: UUID | None = None,
        request_id: UUID | None = None,
        expected_investigation_version: int | None = None,
    ) -> InvestigationReport:
        """Record the candidate and return it with stamped metadata."""
        if self.fail is not None:
            raise self.fail
        self.persisted.append(report)
        return report.model_copy(update={"id": UUID(int=7), "version": 1})


def _writer(
    world: ReportWriterUnitWorld,
    fake_llm: FakeLlmClient,
    *,
    loader_fail: Exception | None = None,
) -> tuple[ReportWriter, FakeLoader, FakeAccounting, FakePersistence]:
    """Build the fully-bound writer plus every observable fake."""
    loader = FakeLoader(world.input())
    loader.fail = loader_fail
    accounting = FakeAccounting()
    persistence = FakePersistence()
    writer = ReportWriter(
        input_loader=loader,
        llm_client=fake_llm,
        report_persistence=persistence,
        llm_accounting=accounting,
        max_structured_output_attempts=2,
    )
    return writer, loader, accounting, persistence


@pytest.mark.asyncio
async def test_u31_valid_first_output_single_call() -> None:
    """23B-U31: a valid first structured output costs exactly one model call."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    fake_llm.set_default(world.output())
    writer, loader, accounting, persistence = _writer(world, fake_llm)

    report = await writer.write(world.investigation_id)

    assert len(fake_llm.calls) == 1
    assert fake_llm.calls[0].operation_name == OPERATION_REPORT_WRITING
    assert len(accounting.reservations) == 1
    assert len(persistence.persisted) == 1
    assert report.verdict.value == "malicious"
    assert report.confidence.value == "high"


@pytest.mark.asyncio
async def test_u32_retryable_invalid_then_valid_one_repair() -> None:
    """23B-U32: a retryable invalid output is repaired exactly once."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    fake_llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
    fake_llm.set_default(world.output())
    writer, _loader, accounting, persistence = _writer(world, fake_llm)

    await writer.write(world.investigation_id)

    assert len(fake_llm.calls) == 2
    assert len(accounting.reservations) == 2
    assert "failed structured-schema validation" in fake_llm.calls[1].user_prompt
    assert len(persistence.persisted) == 1


@pytest.mark.asyncio
async def test_u33_repair_invalid_typed_llm_failure() -> None:
    """23B-U33: an invalid repair output is a typed LLM failure, no persistence."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    fake_llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
    fake_llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
    writer, _loader, accounting, persistence = _writer(world, fake_llm)

    with pytest.raises(LlmError):
        await writer.write(world.investigation_id)

    assert len(fake_llm.calls) == 2
    assert len(accounting.reservations) == 2
    assert persistence.persisted == []


@pytest.mark.asyncio
async def test_u34_nonretryable_provider_failure_no_repair() -> None:
    """23B-U34: a non-retryable provider failure is never repaired."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    fake_llm.enqueue(LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=False))
    writer, _loader, accounting, persistence = _writer(world, fake_llm)

    with pytest.raises(LlmError) as excinfo:
        await writer.write(world.investigation_id)

    assert excinfo.value.code is LlmErrorCode.PROVIDER_FAILURE
    assert len(fake_llm.calls) == 1
    assert len(accounting.reservations) == 1
    assert persistence.persisted == []


@pytest.mark.asyncio
async def test_u35_cancellation_propagates() -> None:
    """23B-U35: cooperative cancellation propagates unchanged."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    fake_llm.enqueue(asyncio.CancelledError())
    writer, _loader, accounting, persistence = _writer(world, fake_llm)

    with pytest.raises(asyncio.CancelledError):
        await writer.write(world.investigation_id)

    assert len(accounting.reservations) == 1
    assert persistence.persisted == []


@pytest.mark.asyncio
async def test_u36_input_failure_zero_reservations() -> None:
    """23B-U36: input failure before invocation costs zero model calls."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    fake_llm.set_default(world.output())
    writer, _loader, accounting, persistence = _writer(
        world,
        fake_llm,
        loader_fail=ValueError("no current assessment"),
    )

    with pytest.raises(ValueError, match="no current assessment"):
        await writer.write(world.investigation_id)

    assert fake_llm.calls == []
    assert accounting.reservations == []
    assert persistence.persisted == []


@pytest.mark.asyncio
async def test_u37_one_invocation_one_reservation() -> None:
    """23B-U37: one real invocation produces exactly one durable reservation."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    fake_llm.set_default(world.output())
    writer, _loader, accounting, _persistence = _writer(world, fake_llm)

    await writer.write(world.investigation_id)

    assert len(accounting.reservations) == 1
    assert accounting.reservations[0][0] == world.investigation_id


@pytest.mark.asyncio
async def test_u38_repair_invocation_second_reservation() -> None:
    """23B-U38: the repair invocation is a separately durable reservation."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    fake_llm.enqueue(LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=True))
    fake_llm.set_default(world.output())
    writer, _loader, accounting, _persistence = _writer(world, fake_llm)

    await writer.write(world.investigation_id)

    assert len(accounting.reservations) == 2
    assert accounting.reservations[1][1] == 11


@pytest.mark.asyncio
async def test_u39_unsupported_refs_no_repair_deterministic_validation() -> None:
    """23B-U39: unsupported refs after valid schema fail without repair."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    fake_llm.set_default(world.unsupported_output())
    writer, _loader, accounting, persistence = _writer(world, fake_llm)

    with pytest.raises(ReportProvenanceError):
        await writer.write(world.investigation_id)

    assert len(fake_llm.calls) == 1
    assert len(accounting.reservations) == 1
    assert persistence.persisted == []


@pytest.mark.asyncio
async def test_u40_raw_model_content_never_persisted() -> None:
    """23B-U40: only the stamped authoritative report reaches persistence."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    fake_llm.set_default(world.output())
    writer, _loader, _accounting, persistence = _writer(world, fake_llm)

    await writer.write(world.investigation_id)

    persisted = persistence.persisted[0]
    assert persisted.verdict is world.assessment.verdict
    assert persisted.confidence is world.assessment.confidence
    assert persisted.assessment_id == world.assessment_id
    assert persisted.investigation_id == world.investigation_id
    assert persisted.findings[0].assessment_finding_ordinal == 1
    assert persisted.source_evidence_ids == (world.evidence_id,)


@pytest.mark.asyncio
async def test_repeated_explicit_write_is_a_new_generation() -> None:
    """Repeated explicit generation persists a new candidate each time."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    fake_llm.set_default(world.output())
    writer, _loader, _accounting, persistence = _writer(world, fake_llm)

    await writer.write(world.investigation_id)
    await writer.write(world.investigation_id)

    assert len(persistence.persisted) == 2


@pytest.mark.asyncio
async def test_max_structured_output_attempts_bounded() -> None:
    """The structured-output attempt policy is hard-limited to 1..2."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    with pytest.raises(ValueError):
        ReportWriter(
            input_loader=FakeLoader(world.input()),
            llm_client=fake_llm,
            report_persistence=FakePersistence(),
            llm_accounting=FakeAccounting(),
            max_structured_output_attempts=3,
        )


@pytest.mark.asyncio
async def test_no_free_form_fallback_after_schema_failure() -> None:
    """Schema failure never falls back to free-form output."""
    world = ReportWriterUnitWorld()
    fake_llm = FakeLlmClient()
    fake_llm.set_default("free-form prose")  # type: ignore[arg-type]
    writer, _loader, _accounting, persistence = _writer(world, fake_llm)

    with pytest.raises(AssertionError):
        await writer.write(world.investigation_id)

    assert persistence.persisted == []
