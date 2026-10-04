# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic PR 34 harness state-machine/verifier logic tests.

Pure tests of the observability harness orchestration (no containers, no
backends, no network) proving the convergence gate ordering (T34-I14), the
failure taxonomy (T34-F01..F10), run-scoped matching (F08: stale other runs
can never satisfy this run), bounded malformed-response classification (F02),
and secret-safe summaries (F10). Backend HTTP contact points are replaced by
recording doubles/fabricated payloads.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.integration.observability import backend
from tests.integration.observability._statemachine import (
    FAILURE_STAGE_CROSS_SIGNAL_CORRELATION,
    ObservabilityStage,
    ProbeSnapshot,
    evaluate,
    wait_for_stage,
)
from tests.integration.observability.topology import ObsTopology
from tests.integration.observability.verifier import (
    PROMETHEUS_COUNTER_NAME,
    JaegerRunTrace,
    jaeger_run_trace,
    loki_snapshot,
    probe,
    prometheus_snapshot,
)

pytestmark = pytest.mark.unit

RUN_ID = "01234567-89ab-cdef-0123-456789abcdef"
OTHER_RUN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

TOPOLOGY = ObsTopology(
    run_id=RUN_ID,
    collector_health_url="http://collector:13131",
    prometheus_url="http://prometheus:9090",
    jaeger_url="http://jaeger:16686",
    loki_url="http://loki:3100",
    grafana_url="http://grafana:3000",
    grafana_admin_user="admin",
    grafana_admin_password="synthetic-password",
)


def _ready() -> ProbeSnapshot:
    """Return a fully converged probe snapshot (all gates satisfied)."""
    return ProbeSnapshot(
        topology_ready=True,
        signals_emitted=True,
        prometheus_converged=True,
        jaeger_converged=True,
        loki_converged=True,
        grafana_verified=True,
    )


class TestConvergenceOrdering:
    """T34-I14: success only after every convergence/verification gate."""

    def test_readiness_only_after_all_gates(self) -> None:
        """Every signal must converge AND Grafana verify before READY."""
        result = evaluate(_ready())
        assert result.ready
        assert result.stage is ObservabilityStage.READY_FOR_ASSERTIONS

    def test_topology_not_ready_waits(self) -> None:
        """Topology readiness is the first gate."""
        result = evaluate(ProbeSnapshot(topology_ready=False))
        assert result.stage is ObservabilityStage.TOPOLOGY_READY
        assert not result.ready

    def test_signals_not_emitted_waits(self) -> None:
        """SIGNALS_EMITTED is the second gate."""
        result = evaluate(ProbeSnapshot(topology_ready=True, signals_emitted=False))
        assert result.stage is ObservabilityStage.SIGNALS_EMITTED

    def test_prometheus_gate_before_jaeger(self) -> None:
        """Prometheus convergence precedes the later signal gates."""
        result = evaluate(
            ProbeSnapshot(
                topology_ready=True,
                signals_emitted=True,
                prometheus_converged=False,
            )
        )
        assert result.stage is ObservabilityStage.PROMETHEUS_CONVERGED

    def test_jaeger_gate_before_loki(self) -> None:
        """Jaeger convergence precedes the Loki gate."""
        result = evaluate(
            ProbeSnapshot(
                topology_ready=True,
                signals_emitted=True,
                prometheus_converged=True,
                jaeger_converged=False,
            )
        )
        assert result.stage is ObservabilityStage.JAEGER_CONVERGED

    def test_loki_gate_before_grafana(self) -> None:
        """Loki convergence precedes the Grafana verification gate."""
        result = evaluate(
            ProbeSnapshot(
                topology_ready=True,
                signals_emitted=True,
                prometheus_converged=True,
                jaeger_converged=True,
                loki_converged=False,
            )
        )
        assert result.stage is ObservabilityStage.LOKI_CONVERGED

    def test_grafana_gate_is_last_before_ready(self) -> None:
        """Grafana verification is the last non-terminal gate."""
        result = evaluate(
            ProbeSnapshot(
                topology_ready=True,
                signals_emitted=True,
                prometheus_converged=True,
                jaeger_converged=True,
                loki_converged=True,
                grafana_verified=False,
            )
        )
        assert result.stage is ObservabilityStage.GRAFANA_VERIFIED

    def test_terminal_failure_wins_over_progress(self) -> None:
        """A terminal failure always beats progress (never assert then)."""
        result = evaluate(
            ProbeSnapshot(
                topology_ready=True,
                signals_emitted=True,
                prometheus_converged=True,
                jaeger_converged=True,
                loki_converged=True,
                grafana_verified=True,
                terminal_failure="generator failed",
                terminal_stage="GENERATOR",
            )
        )
        assert result.failed
        assert not result.ready


class TestWaitForStage:
    """Bounded polling semantics and the timeout taxonomy (F01/F03/F04/F05)."""

    def test_wait_returns_when_target_reached(self) -> None:
        """wait_for_stage stops once the target (or later) stage is reached."""
        calls: list[ProbeSnapshot] = []

        def probe_callable() -> ProbeSnapshot:
            """Return the ready snapshot after two not-ready probes."""
            calls.append(ProbeSnapshot())
            if len(calls) < 3:
                return ProbeSnapshot()
            return _ready()

        result = wait_for_stage(
            probe_callable,
            until=ObservabilityStage.READY_FOR_ASSERTIONS,
            timeout_seconds=10,
            interval_seconds=0.01,
        )
        assert result.ready

    def test_missing_prometheus_times_out(self) -> None:
        """F03: a permanently missing Prometheus series ends in timeout."""
        result = wait_for_stage(
            lambda: ProbeSnapshot(
                topology_ready=True,
                signals_emitted=True,
                prometheus_converged=False,
            ),
            until=ObservabilityStage.READY_FOR_ASSERTIONS,
            timeout_seconds=0.05,
            interval_seconds=0.01,
        )
        assert result.timed_out
        assert result.stage is ObservabilityStage.PROMETHEUS_CONVERGED
        assert not result.ready

    def test_missing_jaeger_times_out(self) -> None:
        """F04: a missing Jaeger trace ends in a bounded timeout."""
        result = wait_for_stage(
            lambda: ProbeSnapshot(
                topology_ready=True,
                signals_emitted=True,
                prometheus_converged=True,
                jaeger_converged=False,
            ),
            until=ObservabilityStage.READY_FOR_ASSERTIONS,
            timeout_seconds=0.05,
            interval_seconds=0.01,
        )
        assert result.timed_out
        assert result.stage is ObservabilityStage.JAEGER_CONVERGED

    def test_missing_loki_times_out(self) -> None:
        """F05: a missing Loki log ends in a bounded timeout."""
        result = wait_for_stage(
            lambda: ProbeSnapshot(
                topology_ready=True,
                signals_emitted=True,
                prometheus_converged=True,
                jaeger_converged=True,
                loki_converged=False,
            ),
            until=ObservabilityStage.READY_FOR_ASSERTIONS,
            timeout_seconds=0.05,
            interval_seconds=0.01,
        )
        assert result.timed_out
        assert result.stage is ObservabilityStage.LOKI_CONVERGED

    def test_missing_grafana_times_out(self) -> None:
        """F06: missing Grafana datasource provisioning ends in a timeout."""
        result = wait_for_stage(
            lambda: ProbeSnapshot(
                topology_ready=True,
                signals_emitted=True,
                prometheus_converged=True,
                jaeger_converged=True,
                loki_converged=True,
                grafana_verified=False,
            ),
            until=ObservabilityStage.READY_FOR_ASSERTIONS,
            timeout_seconds=0.05,
            interval_seconds=0.01,
        )
        assert result.timed_out
        assert result.stage is ObservabilityStage.GRAFANA_VERIFIED


class TestProbeClassification:
    """Live-probe mapping: BackendError -> not-converged, mismatch -> terminal."""

    def _patched(self, monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> None:
        """Patch the verifier snapshot functions for one probe evaluation."""
        defaults: dict[str, Any] = {
            "topology_ready": (
                True,
                {
                    "collector": True,
                    "prometheus": True,
                    "jaeger": True,
                    "loki": True,
                    "grafana": True,
                },
            ),
            "prometheus_snapshot": {
                "counter_value": 1,
                "duration_count": 1,
                "duration_sum": 0.125,
            },
            "jaeger_snapshot": {
                "trace_id": "abc",
                "root_name": "ati.telemetry.test",
                "child_name": "ati.telemetry.test.child",
                "child_parented": True,
            },
            "loki_snapshot": {
                "line_count": 1,
                "trace_ids": ["abc"],
                "span_ids": ["def"],
            },
            "grafana_snapshot": {
                "datasource_uids": ["ati-prometheus", "ati-jaeger", "ati-loki"]
            },
        }
        defaults.update(overrides)
        import tests.integration.observability.verifier as verifier

        monkeypatch.setattr(
            verifier, "topology_ready", lambda _t: defaults["topology_ready"]
        )
        for name in (
            "prometheus_snapshot",
            "jaeger_snapshot",
            "loki_snapshot",
            "grafana_snapshot",
        ):
            monkeypatch.setattr(verifier, name, lambda _t, _n=name: defaults[_n])

    def test_f01_collector_unavailable_never_ready(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F01: Collector unavailable => the delivery gate fails, not ready."""
        self._patched(
            monkeypatch,
            topology_ready=(
                False,
                {
                    "collector": False,
                    "prometheus": False,
                    "jaeger": False,
                    "loki": False,
                    "grafana": False,
                },
            ),
        )
        snapshot = probe(TOPOLOGY, signals_emitted=True)
        assert snapshot.topology_ready is False
        assert evaluate(snapshot).stage is ObservabilityStage.TOPOLOGY_READY

    def test_f03_missing_prometheus_series_keeps_waiting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F03: missing Prometheus series keeps polling (never advances)."""
        self._patched(monkeypatch, prometheus_snapshot=None)
        snapshot = probe(TOPOLOGY, signals_emitted=True)
        assert snapshot.prometheus_converged is False
        result = evaluate(snapshot)
        assert result.stage is ObservabilityStage.PROMETHEUS_CONVERGED

    def test_f02_malformed_backend_response_is_bounded_stage_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F02: malformed backend response raises, mapped to not-converged."""

        def bad_response(*_a: Any, **_k: Any) -> Any:
            """Return a response whose contract is malformed."""
            raise backend.BackendError("Prometheus query returned a non-vector result")

        monkeypatch.setattr(
            "tests.integration.observability.verifier.prometheus_snapshot",
            bad_response,
        )
        snapshot = probe(TOPOLOGY, signals_emitted=True)
        assert snapshot.prometheus_converged is False
        assert snapshot.terminal_failure is None  # transient: keep polling

    def test_f07_wrong_trace_correlation_is_terminal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F07: Jaeger/Loki trace mismatch is a terminal cross-signal failure."""
        self._patched(
            monkeypatch,
            jaeger_snapshot={"trace_id": "abc", "child_parented": True},
            loki_snapshot={"line_count": 1, "trace_ids": ["zzz"], "span_ids": []},
        )
        snapshot = probe(TOPOLOGY, signals_emitted=True)
        assert snapshot.loki_converged
        assert snapshot.terminal_failure is not None
        assert snapshot.terminal_stage == FAILURE_STAGE_CROSS_SIGNAL_CORRELATION
        assert evaluate(snapshot).failed

    def test_f09_wrong_service_is_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F09: wrong-service telemetry cannot advance the run."""
        self._patched(
            monkeypatch,
            jaeger_snapshot=None,
            loki_snapshot=None,
            prometheus_snapshot=None,
        )
        snapshot = probe(TOPOLOGY, signals_emitted=True)
        result = evaluate(snapshot)
        assert result.stage is ObservabilityStage.PROMETHEUS_CONVERGED


class TestRunScopedMatching:
    """F08: stale/other-run telemetry can never satisfy the run."""

    def test_jaeger_matching_requires_exact_run_id(self) -> None:
        """A trace from another run is not matched for this run."""
        spans: list[dict[str, Any]] = [
            {
                "name": "ati.telemetry.test",
                "traceId": "abc",
                "spanId": "root1",
                "attributes": [
                    {
                        "key": "ati.telemetry.test.run_id",
                        "value": {"stringValue": OTHER_RUN_ID},
                    }
                ],
            },
            {
                "name": "ati.telemetry.test.child",
                "traceId": "abc",
                "spanId": "ch1",
                "parentSpanId": "root1",
                "attributes": [
                    {
                        "key": "ati.telemetry.test.run_id",
                        "value": {"stringValue": OTHER_RUN_ID},
                    }
                ],
            },
        ]
        from tests.integration.observability.verifier import (
            _spans_with_run_id,
        )

        assert _spans_with_run_id(spans, RUN_ID) is None
        matched = _spans_with_run_id(spans, OTHER_RUN_ID)
        assert isinstance(matched, JaegerRunTrace)
        assert matched.child_parented_to_root

    def test_jaeger_matching_rejects_missing_run_attribute(self) -> None:
        """Spans without the run attribute never match any run."""
        spans: list[dict[str, Any]] = [
            {
                "name": "ati.telemetry.test",
                "traceId": "abc",
                "spanId": "root1",
                "attributes": [],
            },
            {
                "name": "ati.telemetry.test.child",
                "traceId": "abc",
                "spanId": "ch1",
                "parentSpanId": "root1",
                "attributes": [],
            },
        ]
        from tests.integration.observability.verifier import _spans_with_run_id

        assert _spans_with_run_id(spans, RUN_ID) is None

    def test_loki_snapshot_filters_by_run_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Loki matching is run-scoped: only the exact run's lines count."""
        monkeypatch.setattr(
            "tests.integration.observability.verifier.backend.loki_query_range",
            lambda *_a, **_k: [
                (
                    "1",
                    f"telemetry_test_signal run_id={OTHER_RUN_ID}",
                    {"service_name": "ati-telemetry-test"},
                ),
                (
                    "2",
                    f"telemetry_test_signal run_id={RUN_ID}",
                    {
                        "service_name": "ati-telemetry-test",
                        "trace_id": "t2",
                        "span_id": "s2",
                    },
                ),
            ],
        )
        monkeypatch.setattr(
            "tests.integration.observability.verifier.time.time_ns", lambda: 1
        )
        snapshot = loki_snapshot(TOPOLOGY)
        assert snapshot is not None
        assert snapshot["line_count"] == 1
        assert "t2" in snapshot["trace_ids"]
        assert "s2" in snapshot["span_ids"]


class TestSecretSafeSummaries:
    """F10: secret-like inputs never leak into errors or summaries."""

    def test_backend_error_never_contains_response_body(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A 500 response body never leaks into the raised error message."""

        class _FakeResponse:
            """Return status 500 with a body carrying a would-be secret."""

            status_code = 500

            def json(self) -> Any:
                return {"secret": "ATI_OPENAI_API_KEY=hidden-value"}

        class _FakeClient:
            """Record-free client double returning the 500 response."""

            def __enter__(self) -> "_FakeClient":
                """Context entry returns self."""
                return self

            def __exit__(self, *_a: Any) -> None:
                """Context exit is a no-op."""
                return

            def get(self, *_a: Any, **_k: Any) -> _FakeResponse:
                """Return the fabricated 500 response."""
                return _FakeResponse()

        monkeypatch.setattr(backend.httpx, "Client", lambda **kw: _FakeClient())  # type: ignore[attr-defined]  # httpx is intentionally not a public backend export
        with pytest.raises(backend.BackendError) as excinfo:
            backend.get_json("http://jaeger:16686/api/v3/extra")
        assert "hidden-value" not in str(excinfo.value)

    def test_loki_summary_omits_line_body(self) -> None:
        """The Loki run-state summary never carries the raw log line."""
        from tests.integration.observability.verifier import LokiRunLog

        run_log = LokiRunLog(
            lines=(("1", "telemetry_test_signal run_id=... body would-be-secret"),),
            trace_ids=frozenset({"abc"}),
            span_ids=frozenset({"def"}),
        )
        summary = run_log.to_json()
        assert summary["line_count"] == 1
        assert "would-be-secret" not in str(summary)


class TestPrometheusParsing:
    """Prometheus contract parsing is deterministic and bounded."""

    def test_prometheus_snapshot_reads_exact_values(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A fabricated Prometheus vector maps to counter=1, count=1, sum=0.125."""

        def fake_query(_url: str, query: str, **_k: Any) -> list[Any]:
            """Return a fabricated instant vector for any query."""
            if "_count" in query:
                value = 1.0
            elif "_sum" in query:
                value = 0.125
            else:
                value = 1.0
            return [
                {
                    "metric": {"__name__": PROMETHEUS_COUNTER_NAME},
                    "value": [1700000000, str(value)],
                }
            ]

        monkeypatch.setattr(
            "tests.integration.observability.verifier.backend.prometheus_query",
            fake_query,
        )
        snapshot = prometheus_snapshot(TOPOLOGY)
        assert snapshot is not None
        assert snapshot["counter_value"] == 1
        assert snapshot["duration_count"] == 1
        assert abs(snapshot["duration_sum"] - 0.125) < 1e-9

    def test_prometheus_missing_series_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An empty result vector means not-yet-converged, never an error."""
        monkeypatch.setattr(
            "tests.integration.observability.verifier.backend.prometheus_query",
            lambda *_a, **_k: [],
        )
        assert prometheus_snapshot(TOPOLOGY) is None

    def test_jaeger_run_trace_resolves_run_scoped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Search + OTLP parse selects the run's exact root/child pair."""
        run_spans: list[dict[str, Any]] = [
            {
                "name": "ati.telemetry.test",
                "traceId": "trace-a",
                "spanId": "root-a",
                "attributes": [
                    {
                        "key": "ati.telemetry.test.run_id",
                        "value": {"stringValue": RUN_ID},
                    }
                ],
            },
            {
                "name": "ati.telemetry.test.child",
                "traceId": "trace-a",
                "spanId": "child-a",
                "parentSpanId": "root-a",
                "attributes": [
                    {
                        "key": "ati.telemetry.test.run_id",
                        "value": {"stringValue": RUN_ID},
                    }
                ],
            },
        ]

        def fake_search(
            _url: str, *, service_name: str, **kwargs: object
        ) -> list[dict[str, Any]]:
            """Return the run spans; assert run-scoped search parameters."""
            assert service_name == "ati-telemetry-test"
            assert str(kwargs["attributes"]).startswith("{")
            return run_spans

        monkeypatch.setattr(
            "tests.integration.observability.verifier.backend.jaeger_search",
            fake_search,
        )
        trace = jaeger_run_trace(TOPOLOGY)
        assert trace is not None
        assert trace.trace_id == "trace-a"
        assert trace.child_parented_to_root
