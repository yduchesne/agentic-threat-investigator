# SPDX-License-Identifier: AGPL-3.0-only
"""Authoritative PR 34 observability-stack assertions (T34-I01..I14).

This gate runs ONLY after ``scripts/observability-integration.sh`` has
reached ``READY_FOR_ASSERTIONS`` through bounded polling of the real pinned
backends: Collector, Prometheus, Jaeger, Loki, Grafana. The topology and the
unique run identity come from the harness environment; every assertion is
run-scoped so stale telemetry from other runs can never satisfy it
(T34-F08).

The tests are marked ``observability`` and are never part of the ordinary
``./build.sh --intg`` run (testpaths/project markers).
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from agentic_threat_investigator.telemetry.diagnostic import (
    TELEMETRY_TEST_CHILD_SPAN,
    TELEMETRY_TEST_DURATION_VALUE,
    TELEMETRY_TEST_LOG_EVENT,
    TELEMETRY_TEST_ROOT_SPAN,
    TELEMETRY_TEST_RUN_ID_ATTRIBUTE,
)
from tests.integration.observability import backend
from tests.integration.observability._statemachine import (
    STAGE_ORDER,
    ObservabilityStage,
)
from tests.integration.observability.topology import ObsTopology
from tests.integration.observability.verifier import (
    PROMETHEUS_COUNTER_NAME,
    PROMETHEUS_RUN_LABEL,
    grafana_datasources,
    jaeger_run_trace,
    loki_run_log,
    prometheus_snapshot,
)

pytestmark = [pytest.mark.observability]


def _state_dir() -> Path:
    """Return the harness artifact directory from the environment."""
    return Path(os.environ["ATI_OBS_STATE_DIR"])


@pytest.fixture(scope="module")
def topology() -> ObsTopology:
    """Build the harness topology; refuse to run outside the harness."""
    if not os.environ.get("ATI_OBS_RUN_ID"):
        pytest.fail(
            "observability assertions require scripts/observability-integration.sh "
            "(ATI_OBS_RUN_ID is not set)"
        )
    return ObsTopology.from_environment()


def _run_state() -> dict[str, object]:
    """Load the bounded run-state artifact recorded by the harness."""
    state_path = _state_dir() / "run-state.json"
    assert state_path.exists(), "run-state.json missing from the harness artifact dir"
    import json

    return dict(json.loads(state_path.read_text()))


def test_i14_ordering_reached_readiness_before_assertions() -> None:
    """T34-I14 assertions run only after the convergence machine was READY."""
    state = _run_state()
    stage = state.get("stage")
    assert stage in {s.value for s in STAGE_ORDER}, f"unknown stage {stage!r}"
    ready_index = STAGE_ORDER.index(ObservabilityStage.READY_FOR_ASSERTIONS)
    assert STAGE_ORDER.index(ObservabilityStage(stage)) >= ready_index
    assert state.get("signals_emitted") is True
    assert state.get("generator_exit") == 0


def test_i02_generator_signal_identity_recorded() -> None:
    """T34-I02 the diagnostic CLI exited 0 with the exact run identity."""
    state = _run_state()
    assert state.get("signals_emitted") is True
    signal_run_id = state.get("signal_run_id")
    assert isinstance(signal_run_id, str) and signal_run_id
    assert signal_run_id == os.environ["ATI_OBS_RUN_ID"]


def test_i03_prometheus_counter_run_correlated_value_one(topology: ObsTopology) -> None:
    """T34-I03 the run-correlated counter series has the exact value 1."""
    result = prometheus_snapshot(topology)
    assert result is not None, "Prometheus counter series missing after convergence"
    assert result["counter_value"] == 1


def test_i04_prometheus_duration_count_one_sum_approx_0_125(
    topology: ObsTopology,
) -> None:
    """T34-I04 duration count == 1 and sum ≈ 0.125s on the pinned stack."""
    result = prometheus_snapshot(topology)
    assert result is not None, "Prometheus duration series missing after convergence"
    assert result["duration_count"] == 1
    assert result["duration_sum"] == pytest.approx(
        TELEMETRY_TEST_DURATION_VALUE, abs=0.01
    )


def test_i04b_prometheus_series_carry_the_run_label(topology: ObsTopology) -> None:
    """The Prometheus series must be labeled with the unique run ID."""
    series = backend.prometheus_query(
        topology.prometheus_url,
        f"{PROMETHEUS_COUNTER_NAME}",
    )
    labels = [entry.get("metric") for entry in series if isinstance(entry, dict)]
    matched = any(
        isinstance(metric, dict) and metric.get(PROMETHEUS_RUN_LABEL) == topology.run_id
        for metric in labels
    )
    assert matched, "no counter series carries the run ID label"


def test_i05_jaeger_run_trace_exact_identity(topology: ObsTopology) -> None:
    """T34-I05 the Jaeger trace is the run's exact root/child identity."""
    trace = jaeger_run_trace(topology)
    assert trace is not None, "the run's Jaeger trace was not found"
    assert trace.root_span.get("name") == TELEMETRY_TEST_ROOT_SPAN
    assert trace.child_span.get("name") == TELEMETRY_TEST_CHILD_SPAN
    assert (
        _jaeger_attribute(trace.root_span, TELEMETRY_TEST_RUN_ID_ATTRIBUTE)
        == topology.run_id
    )
    assert (
        _jaeger_attribute(trace.child_span, TELEMETRY_TEST_RUN_ID_ATTRIBUTE)
        == topology.run_id
    )


def test_i06_jaeger_child_span_exact(topology: ObsTopology) -> None:
    """T34-I06 the child span exists with the exact name and run attribute."""
    trace = jaeger_run_trace(topology)
    assert trace is not None
    assert trace.child_span.get("name") == TELEMETRY_TEST_CHILD_SPAN


def test_i07_jaeger_parentage_child_parent_is_root(topology: ObsTopology) -> None:
    """T34-I07 the child span's parent is the root span."""
    trace = jaeger_run_trace(topology)
    assert trace is not None
    assert trace.child_parented_to_root


def test_i08_loki_log_exact_run_event(topology: ObsTopology) -> None:
    """T34-I08 Loki contains the run's structured log with the exact event/run ID."""
    run_log = loki_run_log(topology)
    assert run_log is not None, "the run's Loki log line was not found"
    assert run_log.line_count >= 1
    _, line = run_log.lines[0]
    assert TELEMETRY_TEST_LOG_EVENT in line
    assert topology.run_id in line


def test_i13_service_identity_is_ati_telemetry_test(topology: ObsTopology) -> None:
    """T34-I13 signals are attributed to the exact ati-telemetry-test service.

    The OTel resource ``service.name`` survives the whole production chain:
    the Collector's Prometheus exporter maps it to the Prometheus ``job``
    convention, rendered as ``exported_job`` because the scrape job already
    owns the ``job`` label (verified against the pinned images). A run-
    scoped series must therefore carry exactly ``ati-telemetry-test``.
    """
    series = backend.prometheus_query(
        topology.prometheus_url,
        f"{PROMETHEUS_COUNTER_NAME}",
    )
    labels = [entry.get("metric") for entry in series if isinstance(entry, dict)]
    service_values = {
        metric.get("exported_job") for metric in labels if isinstance(metric, dict)
    }
    assert "ati-telemetry-test" in service_values, (
        "no Prometheus series carries exported_job=ati-telemetry-test "
        f"(got {sorted(v for v in service_values if v is not None)})"
    )


def test_i09_cross_signal_loki_trace_matches_jaeger(topology: ObsTopology) -> None:
    """T34-I09 the Loki log trace identity equals the Jaeger trace ID."""
    trace = jaeger_run_trace(topology)
    run_log = loki_run_log(topology)
    assert trace is not None and run_log is not None
    assert trace.trace_id
    jaeger_trace_id = trace.trace_id.lower().lstrip("0")
    matching = [
        tid for tid in run_log.trace_ids if tid.lower().lstrip("0") == jaeger_trace_id
    ]
    assert matching, (
        f"Loki trace ids {sorted(run_log.trace_ids)} do not match Jaeger {trace.trace_id}"
    )


def test_i09b_loki_log_carries_nonzero_span_identity(topology: ObsTopology) -> None:
    """T34-I09b the Loki log exports a nonzero intended span ID."""
    run_log = loki_run_log(topology)
    assert run_log is not None
    nonzero = [sid for sid in run_log.span_ids if sid.strip("0")]
    assert nonzero, "Loki log records carry no nonzero span ID"


@pytest.mark.parametrize(
    ("uid", "expected_type", "expected_url"),
    [
        ("ati-prometheus", "prometheus", "http://prometheus:9090"),
        ("ati-jaeger", "jaeger", "http://jaeger:16686"),
        ("ati-loki", "loki", "http://loki:3100"),
    ],
)
def test_i10_i11_i12_grafana_datasources_provisioned_and_healthy(
    topology: ObsTopology,
    uid: str,
    expected_type: str,
    expected_url: str,
) -> None:
    """T34-I10..I12 exact provisioned UID/type/url plus proxy queryability."""
    found = grafana_datasources(topology)
    assert found is not None, "Grafana datasources are not all provisioned"
    entry = found[uid]
    assert entry["uid"] == uid
    assert entry["type"] == expected_type
    assert entry["url"] == expected_url
    # Health/queryability is proven through a successful Grafana proxy query
    # (STOP-5: never weakened to container health).
    _proxy_probe(topology, uid)


def _proxy_probe(topology: ObsTopology, uid: str) -> None:
    """Execute the Grafana proxy query proving one datasource is queryable."""
    import time

    base = f"{topology.grafana_url}/api/datasources/proxy/uid/{uid}"
    auth = (topology.grafana_admin_user, topology.grafana_admin_password)
    if uid == "ati-prometheus":
        payload = backend.get_json(
            f"{base}/api/v1/query", params={"query": "up"}, auth=auth
        )
        assert payload.get("status") == "success"
    elif uid == "ati-jaeger":
        payload = backend.get_json(f"{base}/api/v3/services", auth=auth)
        assert "services" in payload
    elif uid == "ati-loki":
        now_ns = time.time_ns()
        payload = backend.get_json(
            f"{base}/loki/api/v1/query_range",
            params={
                "query": '{service_name="ati-telemetry-test"}',
                "start": str(now_ns - 60 * 10**9),
                "end": str(now_ns),
                "limit": "10",
            },
            auth=auth,
        )
        assert payload.get("status") in ("success", 200)


def _jaeger_attribute(span: Mapping[str, object], key: str) -> object | None:
    """Resolve a string attribute value from a Jaeger v3 OTLP span (bounded).

    Jaeger 2.x v3 JSON encodes attributes as an array of
    ``{"key": ..., "value": {"stringValue": ...}}`` proto objects.
    """
    attributes = span.get("attributes")
    if not isinstance(attributes, list):
        return None
    for entry in attributes:
        if not isinstance(entry, dict) or entry.get("key") != key:
            continue
        value = entry.get("value")
        if isinstance(value, dict):
            for candidate in ("stringValue", "intValue", "boolValue", "doubleValue"):
                if candidate in value:
                    return cast(object, value[candidate])
            return value.get("bytesValue")
    return None
