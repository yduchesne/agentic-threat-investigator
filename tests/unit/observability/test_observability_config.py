# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic offline validation of the PR 29C observability config assets.

PR 29C deliberately adds no telemetry integration-test phase: these tests
prove only that ATI-owned source-controlled configuration files are present,
parse cleanly, and carry the stable contracts (datasource UIDs, scrape
jobs/targets, Collector pipelines). Proving the third-party products run is
left to the manual developer smoke procedure in ``docs/OBSERVABILITY.md``,
never to CI.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]  # PyYAML ships no type stubs; test-only parser

_OBSERVABILITY = Path(__file__).resolve().parents[3] / "infra" / "observability"


def _load_yaml(relative: str) -> dict[str, Any]:
    """Load a YAML config file under infra/observability as a JSON-ish dict."""
    data = yaml.safe_load((_OBSERVABILITY / relative).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _load_list(relative: str, key: str) -> list[dict[str, Any]]:
    """Return a list-valued key from a YAML config file."""
    data = _load_yaml(relative)
    assert isinstance(data[key], list)
    return list(data[key])


def test_grafana_datasource_uids_are_unique_and_stable() -> None:
    """INF-C21 datasource UIDs are present, unique, and stable."""
    entries = _load_list(
        "grafana/provisioning/datasources/datasources.yaml", "datasources"
    )
    uids = [entry["uid"] for entry in entries]
    assert len(uids) == len(set(uids)) == 3
    assert set(uids) == {"ati-prometheus", "ati-jaeger", "ati-loki"}
    kinds = {entry["type"] for entry in entries}
    assert kinds == {"prometheus", "jaeger", "loki"}


def test_observability_config_files_are_present_and_yaml_parses() -> None:
    """INF-C19/C20 config assets exist and parse as YAML (no field reads)."""
    for relative in (
        "otel-collector/config.yaml",
        "prometheus/prometheus.yml",
        "loki/config.yaml",
    ):
        assert _load_yaml(relative)


def test_collector_config_defines_the_three_signal_pipelines() -> None:
    """INF-C19 Collector routes traces, metrics, and logs uniquely."""
    config = _load_yaml("otel-collector/config.yaml")
    pipelines: dict[str, Any] = config["service"]["pipelines"]
    assert set(pipelines) == {"traces", "metrics", "logs"}
    for signal, expected in {
        "traces": {"otlphttp/jaeger"},
        "metrics": {"prometheus"},
        "logs": {"otlphttp/loki"},
    }.items():
        exporters: list[object] = list(pipelines[signal]["exporters"])
        assert exporters == [expected.pop()]


def test_prometheus_config_defines_required_scrape_jobs() -> None:
    """INF-C20 Prometheus scrapes ATI, Redpanda, and postgres pods."""
    config = _load_yaml("prometheus/prometheus.yml")
    jobs = {job["job_name"]: job for job in config["scrape_configs"]}
    assert {"ati-otel", "redpanda", "postgres"} <= set(jobs)
    assert jobs["ati-otel"]["metrics_path"] == "/metrics"
    assert jobs["redpanda"]["metrics_path"] == "/public_metrics"
    assert jobs["postgres"]["metrics_path"] == "/metrics"
