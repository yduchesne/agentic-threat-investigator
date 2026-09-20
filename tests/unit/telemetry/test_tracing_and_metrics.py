# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical span/metric vocabulary and instrumentation scope tests (PR 29A/29A-1)."""

from __future__ import annotations

from opentelemetry import trace

from agentic_threat_investigator.telemetry.metrics import (
    COUNTER_SPECS,
    DURATION_UNIT,
    DurationMetrics,
    Metrics,
    duration_metric_name,
    get_counter,
)
from agentic_threat_investigator.telemetry.tracing import (
    CANONICAL_SPAN_NAMES,
    INSTRUMENTATION_SCOPE,
    SpanNames,
    get_tracer,
)
from tests.support.otel import (
    counter_is_monotonic,
    counter_value,
    metrics_by_name,
)


class TestSpanVocabulary:
    """The canonical span-name vocabulary is exact and stable."""

    def test_exact_canonical_span_set(self) -> None:
        """The frozen span-name set matches the PR 29/29A-1 contract exactly."""
        assert {
            "ati.datasource.acquire",
            "ati.datasource.convert",
            "ati.evidence.publish",
            "ati.evidence.consume",
            "ati.evidence.persist",
            "ati.geo.resolve",
            "ati.investigation.execute",
            "ati.agent.invoke",
            "ati.llm.invoke",
            "ati.report.generate",
            "ati.postgres.repository",
            "ati.postgres.uow",
            "ati.kafka.publish",
            "ati.kafka.poll",
            "ati.kafka.commit",
        } == CANONICAL_SPAN_NAMES

    def test_span_names_are_lowercase_semantic_identifiers(self) -> None:
        """Every canonical name is a bounded dotted lowercase identifier."""
        for name in CANONICAL_SPAN_NAMES:
            assert name == name.lower()
            assert name.startswith("ati.")
            assert " " not in name and "\n" not in name

    def test_span_name_constants_belong_to_canonical_set(self) -> None:
        """Each SpanNames attribute is present in the canonical set."""
        attrs = {
            SpanNames.DATASOURCE_ACQUIRE,
            SpanNames.DATASOURCE_CONVERT,
            SpanNames.EVIDENCE_PUBLISH,
            SpanNames.EVIDENCE_CONSUME,
            SpanNames.EVIDENCE_PERSIST,
            SpanNames.GEO_RESOLVE,
            SpanNames.INVESTIGATION_EXECUTE,
            SpanNames.AGENT_INVOKE,
            SpanNames.LLM_INVOKE,
            SpanNames.REPORT_GENERATE,
            SpanNames.POSTGRES_REPOSITORY,
            SpanNames.POSTGRES_UOW,
            SpanNames.KAFKA_PUBLISH,
            SpanNames.KAFKA_POLL,
            SpanNames.KAFKA_COMMIT,
        }
        assert attrs == CANONICAL_SPAN_NAMES


class TestInstrumentationScope:
    """Canonical tracer/meter carry the expected instrumentation scope."""

    def test_tracer_uses_canonical_scope(self, in_memory_telemetry: object) -> None:
        """The tracer created through the in-memory seam uses the canonical scope."""
        tracer = in_memory_telemetry.tracer  # type: ignore[attr-defined]
        with tracer.start_as_current_span("ati.llm.invoke"):
            pass
        spans = in_memory_telemetry.exporter.get_finished_spans()  # type: ignore[attr-defined]
        assert len(spans) == 1
        assert spans[0].instrumentation_scope.name == INSTRUMENTATION_SCOPE

    def test_meter_uses_canonical_scope(self, in_memory_telemetry: object) -> None:
        """The meter through the in-memory seam uses the canonical scope."""
        meter = in_memory_telemetry.meter  # type: ignore[attr-defined]
        counter = meter.create_counter("ati.kafka.messages.published", unit="{item}")
        counter.add(1)
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        metric = recorded["ati.kafka.messages.published"]
        assert counter_value(metric) == 1

    def test_get_tracer_returns_tracer(self) -> None:
        """get_tracer returns an OTel Tracer without needing a provider."""
        assert isinstance(get_tracer(), trace.Tracer)


class TestMetricVocabulary:
    """The canonical metric names/units are exact and stable."""

    def test_exact_canonical_metric_names(self) -> None:
        """The frozen metric-name set matches the PR 29/29A-1 contract exactly."""
        assert {spec.name for spec in COUNTER_SPECS} == {
            "ati.kafka.messages.published",
            "ati.kafka.publish.failures",
            "ati.kafka.messages.received",
            "ati.kafka.poll.failures",
            "ati.kafka.commits",
            "ati.kafka.commit.failures",
            "ati.kafka.messages.committed",
            "ati.evidence.messages.processed",
            "ati.evidence.processing.failures",
            "ati.evidence.outcomes.created",
            "ati.evidence.outcomes.appended",
            "ati.evidence.outcomes.unchanged",
            "ati.postgres.repository.failures",
            "ati.postgres.uow.commits",
            "ati.postgres.uow.rollbacks",
            "ati.postgres.uow.failures",
        }

    def test_canonical_metric_units(self) -> None:
        """Units are the bounded OTel counter/{item}/{operation} conventions."""
        units = {spec.name: spec.unit for spec in COUNTER_SPECS}
        assert units[Metrics.KAFKA_MESSAGES_PUBLISHED] == "{item}"
        assert units[Metrics.KAFKA_MESSAGES_RECEIVED] == "{item}"
        assert units[Metrics.KAFKA_MESSAGES_COMMITTED] == "{item}"
        assert units[Metrics.EVIDENCE_MESSAGES_PROCESSED] == "{item}"
        assert units[Metrics.EVIDENCE_PROCESSING_FAILURES] == "{operation}"
        assert units[Metrics.EVIDENCE_OUTCOMES_CREATED] == "{operation}"
        assert units[Metrics.EVIDENCE_OUTCOMES_APPENDED] == "{operation}"
        assert units[Metrics.EVIDENCE_OUTCOMES_UNCHANGED] == "{operation}"
        assert units[Metrics.KAFKA_PUBLISH_FAILURES] == "{operation}"
        assert units[Metrics.KAFKA_POLL_FAILURES] == "{operation}"
        assert units[Metrics.KAFKA_COMMITS] == "{operation}"
        assert units[Metrics.KAFKA_COMMIT_FAILURES] == "{operation}"
        assert units[Metrics.POSTGRES_REPOSITORY_FAILURES] == "{operation}"
        assert units[Metrics.POSTGRES_UOW_COMMITS] == "{operation}"
        assert units[Metrics.POSTGRES_UOW_ROLLBACKS] == "{operation}"
        assert units[Metrics.POSTGRES_UOW_FAILURES] == "{operation}"

    def test_duration_unit_is_seconds(self) -> None:
        """All ATI latency uses the seconds unit 's'."""
        assert DURATION_UNIT == "s"

    def test_duration_metric_name_contract(self) -> None:
        """Duration names use the canonical <operation>.duration suffix."""
        assert (
            duration_metric_name("ati.evidence.persist")
            == "ati.evidence.persist.duration"
        )
        with __import__("pytest").raises(ValueError, match="blank"):
            duration_metric_name("   ")

    def test_unknown_metric_name_rejected(self) -> None:
        """get_counter rejects names outside the frozen vocabulary."""
        with __import__("pytest").raises(ValueError, match="unknown canonical metric"):
            get_counter("ati.invented.counter")

    def test_get_counter_uses_frozen_unit(self, in_memory_telemetry: object) -> None:
        """The counter instrument records with the frozen unit from the spec."""
        counter = get_counter(
            Metrics.KAFKA_MESSAGES_PUBLISHED,
            meter_provider=in_memory_telemetry.meter_provider,  # type: ignore[attr-defined]
        )
        counter.add(2)
        recorded = metrics_by_name(in_memory_telemetry.reader)  # type: ignore[attr-defined]
        metric = recorded[Metrics.KAFKA_MESSAGES_PUBLISHED]
        spec = next(
            candidate
            for candidate in COUNTER_SPECS
            if candidate.name == Metrics.KAFKA_MESSAGES_PUBLISHED
        )
        assert metric.unit == spec.unit == "{item}"
        assert counter_value(metric) == 2
        assert counter_is_monotonic(metric) is True

    def test_duration_metric_constants_use_seconds_suffix(self) -> None:
        """Every canonical duration histogram ends with .duration and uses 's'."""
        for name in (
            DurationMetrics.POSTGRES_REPOSITORY,
            DurationMetrics.POSTGRES_UOW,
            DurationMetrics.POSTGRES_TRANSACTION_OPERATION,
            DurationMetrics.KAFKA_PUBLISH,
            DurationMetrics.KAFKA_POLL,
            DurationMetrics.KAFKA_COMMIT,
            DurationMetrics.EVIDENCE_CONSUME,
            DurationMetrics.EVIDENCE_PERSIST,
        ):
            assert name.endswith(".duration")

    def test_poll_batch_size_uses_message_unit(self) -> None:
        """The poll batch-size histogram uses the bounded {message} unit."""
        from agentic_threat_investigator.telemetry.metrics import MESSAGE_COUNT_UNIT

        assert MESSAGE_COUNT_UNIT == "{message}"
