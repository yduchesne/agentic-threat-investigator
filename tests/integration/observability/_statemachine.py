# SPDX-License-Identifier: AGPL-3.0-only
"""Pure readiness/convergence state machine of the PR 34 observability harness.

The state machine owns the deterministic ordered convergence contract
(PR 34 section 7): topology readiness of the five pinned services, emission
of the diagnostic signal set, per-backend convergence (Prometheus, Jaeger,
Loki), Grafana provisioning/health verification, and only then the terminal
``READY_FOR_ASSERTIONS`` gate. The machine is deliberately pure (no I/O) so
deterministic unit tests drive every transition with fabricated probes; the
real harness builds probe snapshots from live HTTP probes against the real
backends (bounded polling — never fixed acceptance sleeps).

Every probe is **run-scoped**: the caller polls exactly the unique run ID's
counter series, trace, and log, so stale telemetry from other runs can never
advance this run (T34-F08).
"""

from __future__ import annotations

import time as _time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from time import monotonic

# The exact terminal failure-stage vocabulary of the plan's failure taxonomy
# (PR 34 section 20).
FAILURE_STAGE_TOPOLOGY_START = "TOPOLOGY_START"
FAILURE_STAGE_COLLECTOR_READY = "COLLECTOR_READY"
FAILURE_STAGE_PROMETHEUS_READY = "PROMETHEUS_READY"
FAILURE_STAGE_JAEGER_READY = "JAEGER_READY"
FAILURE_STAGE_LOKI_READY = "LOKI_READY"
FAILURE_STAGE_GRAFANA_READY = "GRAFANA_READY"
FAILURE_STAGE_GENERATOR = "GENERATOR"
FAILURE_STAGE_OTLP_EXPORT = "OTLP_EXPORT"
FAILURE_STAGE_PROMETHEUS_CONVERGENCE = "PROMETHEUS_CONVERGENCE"
FAILURE_STAGE_JAEGER_CONVERGENCE = "JAEGER_CONVERGENCE"
FAILURE_STAGE_LOKI_CONVERGENCE = "LOKI_CONVERGENCE"
FAILURE_STAGE_GRAFANA_PROVISIONING = "GRAFANA_PROVISIONING"
FAILURE_STAGE_CROSS_SIGNAL_CORRELATION = "CROSS_SIGNAL_CORRELATION"
FAILURE_STAGE_READINESS_TIMEOUT = "READINESS_TIMEOUT"

# The exact failure-classification vocabulary of the plan (section 20).
FAILURE_CLASS_REGRESSION = "introduced_regression"
FAILURE_CLASS_FEATURE_DEFECT = "feature_implementation_defect"
FAILURE_CLASS_PRE_EXISTING = "deterministic_pre_existing_failure"
FAILURE_CLASS_FLAKY = "nondeterministic_flaky_failure"
FAILURE_CLASS_ENVIRONMENT = "environment_harness_failure"
FAILURE_CLASS_UNCLASSIFIED = "unclassified"


class ObservabilityStage(StrEnum):
    """Ordered convergence stages of one PR 34 harness run.

    The strings are stable machine-readable stage identifiers used by the
    bounded wait loop and the run-state artifact.
    """

    TOPOLOGY_READY = "TOPOLOGY_READY"
    SIGNALS_EMITTED = "SIGNALS_EMITTED"
    PROMETHEUS_CONVERGED = "PROMETHEUS_CONVERGED"
    JAEGER_CONVERGED = "JAEGER_CONVERGED"
    LOKI_CONVERGED = "LOKI_CONVERGED"
    GRAFANA_VERIFIED = "GRAFANA_VERIFIED"
    READY_FOR_ASSERTIONS = "READY_FOR_ASSERTIONS"


#: Ordered display chain, topology readiness first, terminal READY last.
STAGE_ORDER = tuple(stage for stage in ObservabilityStage)


@dataclass(frozen=True)
class ProbeSnapshot:
    """Run-scoped backend observations the state machine needs.

    Every field is derived from live probes correlated to the unique run ID,
    never from wall-clock timing or unrelated global traffic:

    - ``topology_ready``: all five pinned services pass their readiness probe.
    - ``signals_emitted``: the generator process completed successfully.
    - ``prometheus_converged``: the run's counter/duration series are
      queryable with the exact expected values.
    - ``jaeger_converged``: the run's root/child trace is queryable with the
      expected parentage/attributes.
    - ``loki_converged``: the run's structured log is queryable with the
      expected event/run ID and the Jaeger trace identity (cross-signal).
    - ``grafana_verified``: the three exact datasource UIDs are provisioned
      and healthy/queryable through Grafana.
    - ``terminal_failure``: bounded classification/cause of a terminal failure.
    - ``terminal_stage``: the failed convergence stage (section 20 taxonomy).
    """

    topology_ready: bool = False
    signals_emitted: bool = False
    prometheus_converged: bool = False
    jaeger_converged: bool = False
    loki_converged: bool = False
    grafana_verified: bool = False
    terminal_failure: str | None = None
    terminal_stage: str | None = None


@dataclass(frozen=True)
class StageResult:
    """The deterministic outcome of one probe evaluation."""

    stage: ObservabilityStage
    terminal_failure: str | None = None
    terminal_stage: str | None = None

    @property
    def ready(self) -> bool:
        """True exactly when the assertion suite may run."""
        return self.stage is ObservabilityStage.READY_FOR_ASSERTIONS

    @property
    def failed(self) -> bool:
        """True when the run reached a terminal (non-timeout) failure."""
        return self.terminal_failure is not None

    @property
    def timed_out(self) -> bool:
        """True when the bounded wait expired before readiness."""
        return self.terminal_stage == FAILURE_STAGE_READINESS_TIMEOUT


def evaluate(probe: ProbeSnapshot) -> StageResult:
    """Return the current stage from one run-scoped probe snapshot.

    A terminal failure always wins over progress (never read assertions when
    the generator failed or a backend is missing). Otherwise the machine
    returns the earliest not-yet-satisfied gate; convergence of every signal
    AND Grafana verification must all hold before READY_FOR_ASSERTIONS
    (T34-I14: success only after convergence).
    """
    if probe.terminal_failure is not None:
        return StageResult(
            stage=ObservabilityStage.TOPOLOGY_READY,
            terminal_failure=probe.terminal_failure,
            terminal_stage=probe.terminal_stage or FAILURE_STAGE_TOPOLOGY_START,
        )
    if not probe.topology_ready:
        return StageResult(stage=ObservabilityStage.TOPOLOGY_READY)
    if not probe.signals_emitted:
        return StageResult(stage=ObservabilityStage.SIGNALS_EMITTED)
    if not probe.prometheus_converged:
        return StageResult(stage=ObservabilityStage.PROMETHEUS_CONVERGED)
    if not probe.jaeger_converged:
        return StageResult(stage=ObservabilityStage.JAEGER_CONVERGED)
    if not probe.loki_converged:
        return StageResult(stage=ObservabilityStage.LOKI_CONVERGED)
    if not probe.grafana_verified:
        return StageResult(stage=ObservabilityStage.GRAFANA_VERIFIED)
    return StageResult(stage=ObservabilityStage.READY_FOR_ASSERTIONS)


def wait_for_stage(
    probe_callable: Callable[[], ProbeSnapshot],
    *,
    until: ObservabilityStage,
    timeout_seconds: float,
    interval_seconds: float = 2.0,
    clock: Callable[[], float] | None = None,
) -> StageResult:
    """Poll one probe callable until ``until``, a terminal failure, or timeout.

    Always returns a :class:`StageResult`; the caller maps terminal-failure
    and timeout results to a non-zero exit plus diagnostics, and only a
    ``ready``/``until`` result may start the next harness phase. The probe is
    invoked at a bounded interval; cancellation (KeyboardInterrupt) is
    propagated unchanged so operators can interrupt a wait.
    """
    started = monotonic() if clock is None else clock()
    result = evaluate(probe_callable())
    until_index = STAGE_ORDER.index(until)
    while STAGE_ORDER.index(result.stage) < until_index and not result.failed:
        elapsed = (monotonic() - started) if clock is None else (clock() - started)
        if elapsed >= timeout_seconds:
            return StageResult(
                stage=result.stage,
                terminal_failure=(
                    f"readiness timeout expired waiting for {until.value}; "
                    f"latest stage {result.stage.value}"
                ),
                terminal_stage=FAILURE_STAGE_READINESS_TIMEOUT,
            )
        _time.sleep(interval_seconds)
        result = evaluate(probe_callable())
    return result


__all__ = [
    "FAILURE_CLASS_ENVIRONMENT",
    "FAILURE_CLASS_FEATURE_DEFECT",
    "FAILURE_CLASS_FLAKY",
    "FAILURE_CLASS_PRE_EXISTING",
    "FAILURE_CLASS_REGRESSION",
    "FAILURE_CLASS_UNCLASSIFIED",
    "FAILURE_STAGE_COLLECTOR_READY",
    "FAILURE_STAGE_CROSS_SIGNAL_CORRELATION",
    "FAILURE_STAGE_GENERATOR",
    "FAILURE_STAGE_GRAFANA_PROVISIONING",
    "FAILURE_STAGE_GRAFANA_READY",
    "FAILURE_STAGE_JAEGER_CONVERGENCE",
    "FAILURE_STAGE_JAEGER_READY",
    "FAILURE_STAGE_LOKI_CONVERGENCE",
    "FAILURE_STAGE_LOKI_READY",
    "FAILURE_STAGE_OTLP_EXPORT",
    "FAILURE_STAGE_PROMETHEUS_CONVERGENCE",
    "FAILURE_STAGE_PROMETHEUS_READY",
    "FAILURE_STAGE_READINESS_TIMEOUT",
    "FAILURE_STAGE_TOPOLOGY_START",
    "ObservabilityStage",
    "ProbeSnapshot",
    "STAGE_ORDER",
    "StageResult",
    "evaluate",
    "wait_for_stage",
]
