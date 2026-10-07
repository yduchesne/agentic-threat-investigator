# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for authoritative LLM usage, pricing, and accounting (PR 38-9).

Covers the adapter/accounting matrix LU-U01..LU-U20: exact normalization,
cached/reasoning retention, unknown stays unknown, exact Decimal cost from
versioned pricing, scope validation, bounded metric dimensions, durable
append, and the explicit fail-open accounting policy.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from uuid import uuid4

import pytest
from langchain_core.messages import AIMessage

from agentic_threat_investigator.app.llm_pricing import (
    DEFAULT_PRICING_CATALOG,
    ModelPrice,
    PricingCatalog,
    bounded_model_label,
)
from agentic_threat_investigator.app.llm_usage import (
    LlmUsage,
    LlmUsageScope,
    validate_scope_urn,
)
from agentic_threat_investigator.app.llm_usage_service import LlmUsageService
from agentic_threat_investigator.app.persistence.repositories import (
    LlmUsageAppendResult,
    LlmUsageConflictError,
    LlmUsageRecord,
    LlmUsageRepository,
    UnitOfWork,
)
from agentic_threat_investigator.infrastructure.llm.langchain_client import (
    _extract_usage_metadata,
)
from agentic_threat_investigator.telemetry.metrics import Metrics
from tests.support.otel import counter_value, metric_data_points, metrics_by_name

_NOW = datetime(2026, 5, 1, tzinfo=UTC)


class _FakeLlmUsageRepository(LlmUsageRepository):
    """In-memory usage repository with explicit append dispositions.

    ``dispositions`` controls each ``append`` result: ``True`` records a new
    row, ``False`` models an exact replay, and an exception instance is raised
    from ``append``. Once the script is exhausted, appends default to newly
    created. Unit tests control disposition explicitly so application-service
    semantics are isolated from PostgreSQL semantics.
    """

    def __init__(self, dispositions: Sequence[bool | BaseException] = ()) -> None:
        self.records: list[LlmUsageRecord] = []
        self._dispositions = list(dispositions)

    async def append(self, record: LlmUsageRecord) -> LlmUsageAppendResult:
        disposition: bool | BaseException = (
            self._dispositions.pop(0) if self._dispositions else True
        )
        if isinstance(disposition, BaseException):
            raise disposition
        if disposition:
            self.records.append(record)
            return LlmUsageAppendResult(record=record, created=True)
        existing = self.records[-1] if self.records else record
        return LlmUsageAppendResult(record=existing, created=False)


class _FakeUnitOfWork(UnitOfWork):
    """Minimal UnitOfWork exposing only the usage repository seam."""

    def __init__(self, repository: LlmUsageRepository) -> None:
        self.llm_usage = repository

    async def __aenter__(self) -> "_FakeUnitOfWork":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


def _service(
    repository: LlmUsageRepository,
    pricing: PricingCatalog = DEFAULT_PRICING_CATALOG,
) -> LlmUsageService:
    return LlmUsageService(
        lambda: _FakeUnitOfWork(repository),
        provider="openai",
        model="gpt-4o-mini",
        pricing_catalog=pricing,
    )


_USAGE_METRICS = (
    Metrics.LLM_CALLS,
    Metrics.LLM_TOKENS_INPUT,
    Metrics.LLM_TOKENS_OUTPUT,
    Metrics.LLM_TOKENS_CACHED,
    Metrics.LLM_TOKENS_REASONING,
    Metrics.LLM_TOKENS_TOTAL,
    Metrics.LLM_COST,
)


def _usage_counters(telemetry: SimpleNamespace) -> dict[str, int]:
    """Return the recorded aggregate usage counters (missing means zero)."""
    recorded = metrics_by_name(telemetry.reader)
    return {
        metric: counter_value(recorded[metric]) if metric in recorded else 0
        for metric in _USAGE_METRICS
    }


class TestLlmUsageModel:
    """LU-U01..U04: authoritative usage representation."""

    def test_lu_u04_missing_field_is_none_not_zero(self) -> None:
        """An unreported field stays ``None`` and is never zero (LU-U04)."""
        usage = LlmUsage(input_tokens=10)
        assert usage.output_tokens is None
        assert usage.cached_tokens is None
        assert usage.total_tokens is None
        assert usage.has_any is True
        assert LlmUsage().has_any is False

    def test_lu_p06_negative_tokens_rejected(self) -> None:
        """Negative token values are rejected at the model boundary (LU-P06)."""
        with pytest.raises(ValueError, match="negative"):
            LlmUsage(input_tokens=-1)

    def test_lu_u13_scope_urn_validated(self) -> None:
        """Scope URNs are restricted to the controlled namespace (LU-U13)."""
        assert (
            validate_scope_urn(LlmUsageScope.REPORT_ANALYST.value)
            == "urn:ati:llm:usage:investigations:scope:report_analyst"
        )
        with pytest.raises(ValueError, match="controlled namespace"):
            validate_scope_urn("not-a-scope-urn")


class TestPricing:
    """LU-U10..U12: deterministic versioned pricing."""

    def test_lu_u10_known_price_computes_exact_decimal_cost(self) -> None:
        """Known pricing computes an exact Decimal cost (LU-U10)."""
        price = DEFAULT_PRICING_CATALOG.resolve("openai", "gpt-4o-mini")
        assert price is not None
        cost = DEFAULT_PRICING_CATALOG.compute_cost(
            LlmUsage(input_tokens=1000, output_tokens=500, total_tokens=1500), price
        )
        assert cost.input_cost == Decimal("0.00015")
        assert cost.output_cost == Decimal("0.00030")
        assert cost.total_cost == Decimal("0.00045")
        assert cost.currency == "USD"
        assert isinstance(cost.total_cost, Decimal)

    def test_lu_u02_u03_cached_and_reasoning_retained(self) -> None:
        """Cached/reasoning tokens are retained and priced separately (U02/U03)."""
        catalog = PricingCatalog(
            (
                ModelPrice(
                    provider="openai",
                    model="gpt-4o-mini",
                    effective_from=datetime(2024, 1, 1).date(),
                    input_price="0.000001",
                    output_price="0.000002",
                    cached_input_price="0.0000005",
                    reasoning_price="0.000003",
                    currency="USD",
                    pricing_id="p",
                    pricing_version="v",
                ),
            )
        )
        price = catalog.resolve("openai", "gpt-4o-mini")
        assert price is not None
        cost = catalog.compute_cost(
            LlmUsage(cached_tokens=100, reasoning_tokens=50), price
        )
        assert cost.cached_cost == Decimal("0.00005")
        assert cost.reasoning_cost == Decimal("0.00015")
        assert cost.total_cost == Decimal("0.00020")

    def test_lu_u11_unknown_price_leaves_cost_absent(self) -> None:
        """Unknown pricing leaves cost ``None``, never zero (LU-U11)."""
        catalog = PricingCatalog()
        assert catalog.resolve("openai", "unknown-model") is None

    def test_lu_u14_arbitrary_model_collapses(self) -> None:
        """Arbitrary model strings collapse to a bounded label (LU-U14)."""
        assert bounded_model_label("gpt-4o-mini") == "gpt-4o-mini"
        assert bounded_model_label("made-up-model") == "other"

    def test_lu_p10_no_mutation_api(self) -> None:
        """The repository exposes only append (append-only ledger) (LU-P10)."""
        assert LlmUsageRepository.__abstractmethods__ == frozenset({"append"})


class TestAdapterNormalization:
    """LU-U01..U05: provider usage normalization only from reported metadata."""

    def test_lu_u01_u02_u03_normalizes_reported_metadata(self) -> None:
        """Input/output/total/cached/reasoning normalize exactly (U01..U03)."""
        message = AIMessage(
            content="x",
            usage_metadata={
                "input_tokens": 11,
                "output_tokens": 7,
                "total_tokens": 18,
                "input_token_details": {"cache_read": 3},
                "output_token_details": {"reasoning": 4},
            },
        )
        usage = _extract_usage_metadata(message)
        assert usage == LlmUsage(
            input_tokens=11,
            output_tokens=7,
            total_tokens=18,
            cached_tokens=3,
            reasoning_tokens=4,
        )

    def test_lu_u05_no_metadata_yields_none(self) -> None:
        """No usage metadata yields unknown (``None``), not zero (LU-U05)."""
        assert _extract_usage_metadata(AIMessage(content="x")) is None
        assert _extract_usage_metadata(object()) is None


class TestLlmUsageService:
    """LU-P01..P09, U15..U19: durable accounting and bounded metrics."""

    @pytest.mark.asyncio
    async def test_lu_p01_append_one_usage_event(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """One recorded event appends exactly one row (LU-P01)."""
        repository = _FakeLlmUsageRepository()
        usage = LlmUsage(input_tokens=10, output_tokens=5, total_tokens=15)
        record = await _service(repository).record_usage(
            investigation_id=uuid4(),
            scope_urn=LlmUsageScope.REPORT_ANALYST.value,
            operation_name="urn:ati:llm:report_writing",
            invocation_id=uuid4(),
            usage=usage,
            occurred_at=_NOW,
        )
        assert record is not None
        assert len(repository.records) == 1
        assert repository.records[0].total_tokens == 15
        assert repository.records[0].total_cost == Decimal("0.00000450")

    @pytest.mark.asyncio
    async def test_lu_u01_u12_metrics_and_pricing_version(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Usage metrics are bounded; pricing version is persisted (U01/U12)."""
        repository = _FakeLlmUsageRepository()
        await _service(repository).record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.EVIDENCE_ANALYST.value,
            operation_name="urn:ati:llm:evidence_analysis",
            invocation_id=uuid4(),
            usage=LlmUsage(input_tokens=100, output_tokens=20, total_tokens=120),
            occurred_at=_NOW,
        )
        recorded = metrics_by_name(in_memory_persistence_telemetry.reader)
        assert counter_value(recorded[Metrics.LLM_CALLS]) == 1
        assert counter_value(recorded[Metrics.LLM_TOKENS_INPUT]) == 100
        assert counter_value(recorded[Metrics.LLM_TOKENS_OUTPUT]) == 20
        assert counter_value(recorded[Metrics.LLM_TOKENS_TOTAL]) == 120
        assert repository.records[0].pricing_version == "2024-07-18"

    @pytest.mark.asyncio
    async def test_lu_u15_no_prompt_or_output_persisted(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """The durable record exposes no prompt/output content (LU-U15)."""
        repository = _FakeLlmUsageRepository()
        await _service(repository).record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.RESEARCH_AGENT.value,
            operation_name="urn:ati:llm:research_synthesis",
            invocation_id=uuid4(),
            usage=LlmUsage(),
            occurred_at=_NOW,
        )
        fields = set(LlmUsageRecord.__dataclass_fields__)
        assert not {"prompt", "output", "response", "content"} & fields
        assert repository.records[0].total_tokens is None

    @pytest.mark.asyncio
    async def test_lu_u19_durable_failure_is_fail_open(self) -> None:
        """A ledger append failure is fail-open and never raises (LU-U19)."""

        class _FailingRepository(LlmUsageRepository):
            async def append(self, record: LlmUsageRecord) -> LlmUsageAppendResult:
                raise RuntimeError("database unavailable")

        offset = await _service(_FailingRepository()).record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.REPORT_ANALYST.value,
            operation_name="urn:ati:llm:report_writing",
            invocation_id=uuid4(),
            usage=LlmUsage(input_tokens=1),
            occurred_at=_NOW,
        )
        assert offset is None

    @pytest.mark.asyncio
    async def test_scope_rejected_before_persistence(self) -> None:
        """An out-of-namespace scope is rejected before any append."""
        repository = _FakeLlmUsageRepository()
        with pytest.raises(ValueError, match="controlled namespace"):
            await _service(repository).record_usage(
                investigation_id=None,
                scope_urn="not-a-scope-urn",
                operation_name="urn:ati:llm:report_writing",
                invocation_id=uuid4(),
                usage=LlmUsage(),
                occurred_at=_NOW,
            )
        assert repository.records == []


class TestMetricAcceptance:
    """A1..A9: aggregate metrics follow durable acceptance (PR 38-9 Amd #1)."""

    @pytest.mark.asyncio
    async def test_a1_new_event_emits_once(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A new durable event emits each applicable counter once (A1)."""
        repository = _FakeLlmUsageRepository([True])
        record = await _service(repository).record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.REPORT_ANALYST.value,
            operation_name="urn:ati:llm:report_writing",
            invocation_id=uuid4(),
            usage=LlmUsage(input_tokens=100, output_tokens=20, total_tokens=120),
            occurred_at=_NOW,
        )
        assert record is not None
        counters = _usage_counters(in_memory_persistence_telemetry)
        assert counters[Metrics.LLM_CALLS] == 1
        assert counters[Metrics.LLM_TOKENS_INPUT] == 100
        assert counters[Metrics.LLM_TOKENS_OUTPUT] == 20
        assert counters[Metrics.LLM_TOKENS_TOTAL] == 120
        cost_points = metric_data_points(
            metrics_by_name(in_memory_persistence_telemetry.reader)[Metrics.LLM_COST]
        )
        assert float(cost_points[0].value) > 0

    @pytest.mark.asyncio
    async def test_a2_exact_replay_emits_nothing(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """An exact replay emits no aggregate usage metrics (A2)."""
        repository = _FakeLlmUsageRepository([False])
        record = await _service(repository).record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.REPORT_ANALYST.value,
            operation_name="urn:ati:llm:report_writing",
            invocation_id=uuid4(),
            usage=LlmUsage(input_tokens=100, output_tokens=20, total_tokens=120),
            occurred_at=_NOW,
        )
        assert record is not None
        assert all(
            value == 0
            for value in _usage_counters(in_memory_persistence_telemetry).values()
        )

    @pytest.mark.asyncio
    async def test_a3_first_then_replay_counts_once(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """First event plus exact replay yields exactly one contribution (A3)."""
        invocation_id = uuid4()
        usage = LlmUsage(input_tokens=100, output_tokens=20, total_tokens=120)
        repository = _FakeLlmUsageRepository([True, False])
        first = await _service(repository).record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.EVIDENCE_ANALYST.value,
            operation_name="urn:ati:llm:evidence_analysis",
            invocation_id=invocation_id,
            usage=usage,
            occurred_at=_NOW,
        )
        second = await _service(repository).record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.EVIDENCE_ANALYST.value,
            operation_name="urn:ati:llm:evidence_analysis",
            invocation_id=invocation_id,
            usage=usage,
            occurred_at=_NOW,
        )
        assert first is not None and second is not None
        counters = _usage_counters(in_memory_persistence_telemetry)
        assert counters[Metrics.LLM_CALLS] == 1
        assert counters[Metrics.LLM_TOKENS_INPUT] == 100
        assert counters[Metrics.LLM_TOKENS_OUTPUT] == 20
        assert counters[Metrics.LLM_TOKENS_TOTAL] == 120

    @pytest.mark.asyncio
    async def test_a4_conflicting_replay_emits_nothing(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A conflicting replay emits no aggregate usage metrics (A4)."""
        repository = _FakeLlmUsageRepository([LlmUsageConflictError(uuid4())])
        result = await _service(repository).record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.REPORT_ANALYST.value,
            operation_name="urn:ati:llm:report_writing",
            invocation_id=uuid4(),
            usage=LlmUsage(input_tokens=100, total_tokens=100),
            occurred_at=_NOW,
        )
        assert result is None
        assert all(
            value == 0
            for value in _usage_counters(in_memory_persistence_telemetry).values()
        )

    @pytest.mark.asyncio
    async def test_a5_persistence_failure_emits_nothing(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A persistence failure is fail-open with no metric emission (A5)."""
        repository = _FakeLlmUsageRepository([RuntimeError("database unavailable")])
        result = await _service(repository).record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.REPORT_ANALYST.value,
            operation_name="urn:ati:llm:report_writing",
            invocation_id=uuid4(),
            usage=LlmUsage(input_tokens=100),
            occurred_at=_NOW,
        )
        assert result is None
        assert all(
            value == 0
            for value in _usage_counters(in_memory_persistence_telemetry).values()
        )

    @pytest.mark.asyncio
    async def test_a6_cancellation_propagates_without_metrics(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Cancellation during append propagates and emits nothing (A6)."""
        repository = _FakeLlmUsageRepository([asyncio.CancelledError()])
        with pytest.raises(asyncio.CancelledError):
            await _service(repository).record_usage(
                investigation_id=None,
                scope_urn=LlmUsageScope.REPORT_ANALYST.value,
                operation_name="urn:ati:llm:report_writing",
                invocation_id=uuid4(),
                usage=LlmUsage(input_tokens=100),
                occurred_at=_NOW,
            )
        assert all(
            value == 0
            for value in _usage_counters(in_memory_persistence_telemetry).values()
        )

    @pytest.mark.asyncio
    async def test_a7_unknown_fields_are_absent(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Only authoritative fields emit; unknown fields stay absent (A7)."""
        repository = _FakeLlmUsageRepository([True])
        await _service(repository).record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.REPORT_ANALYST.value,
            operation_name="urn:ati:llm:report_writing",
            invocation_id=uuid4(),
            usage=LlmUsage(input_tokens=10),
            occurred_at=_NOW,
        )
        counters = _usage_counters(in_memory_persistence_telemetry)
        assert counters[Metrics.LLM_CALLS] == 1
        assert counters[Metrics.LLM_TOKENS_INPUT] == 10
        assert counters[Metrics.LLM_TOKENS_OUTPUT] == 0
        assert counters[Metrics.LLM_TOKENS_CACHED] == 0
        assert counters[Metrics.LLM_TOKENS_REASONING] == 0
        assert counters[Metrics.LLM_TOKENS_TOTAL] == 0

    @pytest.mark.asyncio
    async def test_a8_unknown_pricing_has_no_cost_counter(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """Unknown pricing emits token metrics but no fabricated cost (A8)."""
        repository = _FakeLlmUsageRepository([True])
        await _service(repository, PricingCatalog()).record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.REPORT_ANALYST.value,
            operation_name="urn:ati:llm:report_writing",
            invocation_id=uuid4(),
            usage=LlmUsage(input_tokens=100, total_tokens=100),
            occurred_at=_NOW,
        )
        counters = _usage_counters(in_memory_persistence_telemetry)
        assert counters[Metrics.LLM_CALLS] == 1
        assert counters[Metrics.LLM_TOKENS_INPUT] == 100
        assert counters[Metrics.LLM_COST] == 0

    @pytest.mark.asyncio
    async def test_a9_replay_does_not_fabricate_zero_counts(
        self, in_memory_persistence_telemetry: SimpleNamespace
    ) -> None:
        """A replay of zero/unknown fields adds no increments (A9)."""
        invocation_id = uuid4()
        repository = _FakeLlmUsageRepository([True, False])
        service = _service(repository)
        await service.record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.REPORT_ANALYST.value,
            operation_name="urn:ati:llm:report_writing",
            invocation_id=invocation_id,
            usage=LlmUsage(input_tokens=0),
            occurred_at=_NOW,
        )
        await service.record_usage(
            investigation_id=None,
            scope_urn=LlmUsageScope.REPORT_ANALYST.value,
            operation_name="urn:ati:llm:report_writing",
            invocation_id=invocation_id,
            usage=LlmUsage(input_tokens=0),
            occurred_at=_NOW,
        )
        counters = _usage_counters(in_memory_persistence_telemetry)
        assert counters[Metrics.LLM_CALLS] == 1
        assert counters[Metrics.LLM_TOKENS_INPUT] == 0
        assert counters[Metrics.LLM_TOKENS_TOTAL] == 0
        assert counters[Metrics.LLM_COST] == 0
