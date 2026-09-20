# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical meter access and metric vocabulary (PR 29A/29A-1).

The canonical metric names/units are frozen here so call-site instrumentation
adds counters using semantic names instead of inventing them. These are
OpenTelemetry semantic names; how a backend (for example Prometheus in PR 29C)
renders a ``_total`` suffix is a backend concern and is not baked into the ATI
API.

The vocabulary covers the operational chain defined by PR 29A-1:

.. code-block:: text

    Kafka publish -> poll -> Evidence processing -> PostgreSQL UoW -> repository
"""

from __future__ import annotations

from dataclasses import dataclass

from opentelemetry import metrics
from opentelemetry.metrics import Counter, Histogram, Meter, MeterProvider

from agentic_threat_investigator.telemetry.tracing import INSTRUMENTATION_SCOPE

_TELEMETRY_VERSION = "0.1.0"

# Duration unit: seconds (UCUM "s"). All ATI latency histograms use this.
DURATION_UNIT = "s"
# Batch-size histogram unit: bounded count of Evidence messages per poll.
MESSAGE_COUNT_UNIT = "{message}"


@dataclass(frozen=True)
class CounterSpec:
    """One canonical monotonic counter's name, unit, and description."""

    name: str
    unit: str
    description: str


class Metrics:
    """Canonical telemetry metric names (frozen by PR 29A/29A-1).

    Kafka/Redpanda transport:
    - ``kafka.messages.published``: broker-acknowledged Evidence messages.
    - ``kafka.publish.failures``: publish operations that failed.
    - ``kafka.messages.received``: decoded/admitted Evidence messages.
    - ``kafka.poll.failures``: poll operations that failed.
    - ``kafka.commits``: successful broker offset commits.
    - ``kafka.commit.failures``: offset commits that failed.
    - ``kafka.messages.committed``: records in successfully committed batches.

    Evidence flow:
    - ``evidence.messages.processed``: fully processed Evidence messages
      (prepare + PostgreSQL persist commit + Kafka consumer commit).
    - ``evidence.processing.failures``: Evidence processing runs that
      terminated in a bounded failure outcome.
    - ``evidence.outcomes.created`` / ``appended`` / ``unchanged``:
      persistence outcomes reported by the batch persistence API.

    PostgreSQL:
    - ``postgres.repository.failures``: repository operations that failed.
    - ``postgres.uow.commits`` / ``rollbacks`` / ``failures``:
      UnitOfWork transaction outcomes.
    """

    KAFKA_MESSAGES_PUBLISHED = "ati.kafka.messages.published"
    KAFKA_PUBLISH_FAILURES = "ati.kafka.publish.failures"
    KAFKA_MESSAGES_RECEIVED = "ati.kafka.messages.received"
    KAFKA_POLL_FAILURES = "ati.kafka.poll.failures"
    KAFKA_COMMITS = "ati.kafka.commits"
    KAFKA_COMMIT_FAILURES = "ati.kafka.commit.failures"
    KAFKA_MESSAGES_COMMITTED = "ati.kafka.messages.committed"
    EVIDENCE_MESSAGES_PROCESSED = "ati.evidence.messages.processed"
    EVIDENCE_PROCESSING_FAILURES = "ati.evidence.processing.failures"
    EVIDENCE_OUTCOMES_CREATED = "ati.evidence.outcomes.created"
    EVIDENCE_OUTCOMES_APPENDED = "ati.evidence.outcomes.appended"
    EVIDENCE_OUTCOMES_UNCHANGED = "ati.evidence.outcomes.unchanged"
    POSTGRES_REPOSITORY_FAILURES = "ati.postgres.repository.failures"
    POSTGRES_UOW_COMMITS = "ati.postgres.uow.commits"
    POSTGRES_UOW_ROLLBACKS = "ati.postgres.uow.rollbacks"
    POSTGRES_UOW_FAILURES = "ati.postgres.uow.failures"


class DurationMetrics:
    """Canonical seconds-unit duration histogram names."""

    POSTGRES_REPOSITORY = "ati.postgres.repository.duration"
    POSTGRES_UOW = "ati.postgres.uow.duration"
    POSTGRES_TRANSACTION_OPERATION = "ati.postgres.transaction_operation.duration"
    KAFKA_PUBLISH = "ati.kafka.publish.duration"
    KAFKA_POLL = "ati.kafka.poll.duration"
    KAFKA_COMMIT = "ati.kafka.commit.duration"
    EVIDENCE_CONSUME = "ati.evidence.consume.duration"
    EVIDENCE_PERSIST = "ati.evidence.persist.duration"
    KAFKA_POLL_BATCH_SIZE = "ati.kafka.poll.batch_size"


COUNTER_SPECS: tuple[CounterSpec, ...] = (
    CounterSpec(
        Metrics.KAFKA_MESSAGES_PUBLISHED,
        "{item}",
        "Evidence messages broker-acknowledged by the Evidence publisher",
    ),
    CounterSpec(
        Metrics.KAFKA_PUBLISH_FAILURES,
        "{operation}",
        "Evidence publish operations that failed",
    ),
    CounterSpec(
        Metrics.KAFKA_MESSAGES_RECEIVED,
        "{item}",
        "Evidence messages decoded and admitted by a poll",
    ),
    CounterSpec(
        Metrics.KAFKA_POLL_FAILURES,
        "{operation}",
        "Evidence poll operations that failed",
    ),
    CounterSpec(
        Metrics.KAFKA_COMMITS,
        "{operation}",
        "Successful broker offset commits",
    ),
    CounterSpec(
        Metrics.KAFKA_COMMIT_FAILURES,
        "{operation}",
        "Broker offset commits that failed",
    ),
    CounterSpec(
        Metrics.KAFKA_MESSAGES_COMMITTED,
        "{item}",
        "Evidence messages in successfully committed batches",
    ),
    CounterSpec(
        Metrics.EVIDENCE_MESSAGES_PROCESSED,
        "{item}",
        "Evidence messages fully processed through broker commit",
    ),
    CounterSpec(
        Metrics.EVIDENCE_PROCESSING_FAILURES,
        "{operation}",
        "Evidence processing runs that terminated in a bounded failure outcome",
    ),
    CounterSpec(
        Metrics.EVIDENCE_OUTCOMES_CREATED,
        "{operation}",
        "Evidence persistence outcomes that created new current state",
    ),
    CounterSpec(
        Metrics.EVIDENCE_OUTCOMES_APPENDED,
        "{operation}",
        "Evidence persistence outcomes that appended a new observation/version",
    ),
    CounterSpec(
        Metrics.EVIDENCE_OUTCOMES_UNCHANGED,
        "{operation}",
        "Evidence persistence outcomes that required no state change",
    ),
    CounterSpec(
        Metrics.POSTGRES_REPOSITORY_FAILURES,
        "{operation}",
        "PostgreSQL repository operations that failed",
    ),
    CounterSpec(
        Metrics.POSTGRES_UOW_COMMITS,
        "{operation}",
        "UnitOfWork transactions that committed",
    ),
    CounterSpec(
        Metrics.POSTGRES_UOW_ROLLBACKS,
        "{operation}",
        "UnitOfWork transactions that rolled back",
    ),
    CounterSpec(
        Metrics.POSTGRES_UOW_FAILURES,
        "{operation}",
        "UnitOfWork transactions that ended in a failure outcome",
    ),
)

_METRIC_BY_NAME: dict[str, CounterSpec] = {spec.name: spec for spec in COUNTER_SPECS}


def duration_metric_name(operation: str) -> str:
    """Return the canonical seconds-unit latency metric name for ``operation``.

    For example ``ati.evidence.persist`` becomes ``ati.evidence.persist.duration``.
    """
    if not operation.strip():
        raise ValueError("duration metric operation must not be blank")
    return f"{operation}.duration"


def get_meter(*, meter_provider: MeterProvider | None = None) -> Meter:
    """Return the canonical ATI meter bound to ``meter_provider``.

    Passing ``meter_provider`` explicitly is the deterministic unit-test and
    29C composition seam; it never manipulates global OpenTelemetry state.
    With no provider configured the meter is a no-op proxy.
    """
    if meter_provider is not None:
        return metrics.get_meter(
            INSTRUMENTATION_SCOPE,
            _TELEMETRY_VERSION,
            meter_provider=meter_provider,
        )
    return metrics.get_meter(INSTRUMENTATION_SCOPE, _TELEMETRY_VERSION)


def get_counter(
    name: str,
    *,
    meter_provider: MeterProvider | None = None,
) -> Counter:
    """Return the canonical counter for ``name`` with its frozen unit.

    ``name`` must be one of :data:`Metrics` values so call sites cannot invent
    metric names. The returned instrument is created through the current or
    explicit meter; with no meter provider it is a no-op counter.
    """
    spec = _METRIC_BY_NAME.get(name)
    if spec is None:
        raise ValueError(f"unknown canonical metric name: {name}")
    meter = get_meter(meter_provider=meter_provider)
    return meter.create_counter(
        spec.name,
        unit=spec.unit,
        description=spec.description,
    )


def get_histogram(
    name: str,
    *,
    unit: str = DURATION_UNIT,
    description: str = "",
    meter_provider: MeterProvider | None = None,
) -> Histogram:
    """Return a histogram for a duration/metric name with its canonical unit.

    Duration histograms use the canonical seconds unit by default; callers
    pass an explicit unit for non-duration histograms such as poll batch size.
    """
    meter = get_meter(meter_provider=meter_provider)
    return meter.create_histogram(name, unit=unit, description=description)


__all__ = [
    "COUNTER_SPECS",
    "DURATION_UNIT",
    "DurationMetrics",
    "MESSAGE_COUNT_UNIT",
    "Metrics",
    "duration_metric_name",
    "get_counter",
    "get_histogram",
    "get_meter",
]
