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


def test_loki_config_freeze_retention_contract() -> None:
    """LOKI-C1/C3/C4/C5: PR 29C-1 retention contract for the pinned Loki runtime.

    Covers the global 14-day retention period (``retention_period: 336h``), the
    absence of the obsolete ``storage_retention_days`` key, and Compactor-managed
    filesystem retention. These selectors freeze the ATI-owned contract only;
    PyYAML parsing does not prove Loki accepts the configuration -- that is the
    pinned ``grafana/loki:3.7.8 -verify-config=true`` developer/reviewer check.
    """
    config = _load_yaml("loki/config.yaml")
    limits = config["limits_config"]
    assert limits["retention_period"] == "336h"  # LOKI-C1
    assert "storage_retention_days" not in limits  # LOKI-C3
    compactor = config["compactor"]
    assert compactor["retention_enabled"] is True  # LOKI-C4
    assert compactor["delete_request_store"] == "filesystem"  # LOKI-C5


def test_loki_config_freeze_structured_metadata_and_topology() -> None:
    """LOKI-C2/C6/C7: structured metadata and local TSDB/v13 topology.

    Holds the retention prerequisites: structured metadata stays enabled, the
    schema is TSDB v13 with a 24h index period, and the object store remains
    filesystem. These mirror the PR 29C topology; retention relies on them.
    """
    config = _load_yaml("loki/config.yaml")
    assert config["limits_config"]["allow_structured_metadata"] is True  # LOKI-C2
    schemas = config["schema_config"]["configs"]
    assert len(schemas) == 1
    (schema,) = schemas
    assert schema["store"] == "tsdb"  # LOKI-C6
    assert schema["object_store"] == "filesystem"  # LOKI-C7
    assert schema["schema"] == "v13"  # LOKI-C6
    assert schema["index"]["period"] == "24h"  # LOKI-C6
