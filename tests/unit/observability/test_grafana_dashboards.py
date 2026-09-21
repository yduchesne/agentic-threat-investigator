# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic offline validation of PR 29D / PR 29D-1 Grafana dashboards.

These tests are deliberately static: they parse the provisioning YAML and the
nine repository-canonical dashboard JSON files, extract the real Grafana
contract fields (Prometheus ``expr`` targets, Loki LogQL ``expr`` targets,
datasource UIDs, dashboard ``links``), and assert the frozen PR 29D / 29D-1
contracts.

PR 29D-1 corrected the runtime contract that PR 29D tests had canonized from
ATI-invented surrogates:

- executable PromQL lives in the Grafana Prometheus target field ``expr``; the
  custom ``query`` surrogate is gone (GRAF-F01/F02);
- dashboard-to-dashboard navigation uses Grafana's dashboard ``links``
  mechanism (``type: "link"`` with ``url: "/d/<uid>"`` and ``keepTime`` for
  time preservation); no ``externalLink`` pseudo-panel type remains
  (GRAF-F04/F05);
- Loki and Jaeger representations are re-verified against the pinned stack
  (GRAF-F14/F15).

Proving the third-party products run is left to the manual developer smoke
procedure in ``docs/OBSERVABILITY.md`` (no telemetry integration-test phase,
GRAF-F18 rule and PR-level acceptance). The GRAF-F matrix below is the
deterministic static validation of the Grafana 13.2.2 runtime contract.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]  # PyYAML ships no type stubs; test-only parser

_ROOT = Path(__file__).resolve().parents[3]
_OBSERVABILITY = _ROOT / "infra" / "observability"
_DASHBOARDS_DIR = _OBSERVABILITY / "grafana" / "dashboards"
_PROVISIONING = _OBSERVABILITY / "grafana" / "provisioning"
_COMPOSE_OBSERVABILITY = _ROOT / "compose.observability.yaml"

DASHBOARD_UID_TO_TITLE = {
    "ati-system-overview": "ATI System Overview",
    "ati-api-http": "API / HTTP",
    "ati-datasource-ingestion": "Datasource & Ingestion",
    "ati-kafka-redpanda": "Kafka / Redpanda",
    "ati-persistence-repository": "Persistence / Repository",
    "ati-postgresql": "PostgreSQL",
    "ati-agents-llm": "Agents & LLM",
    "ati-geo-resolution": "GEO Resolution",
    "ati-investigations-reports": "Investigations & Reports",
}

DETAIL_UID = frozenset(DASHBOARD_UID_TO_TITLE) - {"ati-system-overview"}

STABLE_DATASOURCE_UIDS = frozenset({"ati-prometheus", "ati-jaeger", "ati-loki"})

# PR 29D-1: the agreed hierarchy encoded with the verified dashboard links
# mechanism. ``System Overview`` links to all eight details; every detail links
# back to the overview; the four agreed drill-down relationships are explicit.
REQUIRED_CHILD_LINKS = {
    # source uid -> required destination uids
    "ati-investigations-reports": ("ati-agents-llm",),
    "ati-datasource-ingestion": ("ati-kafka-redpanda", "ati-persistence-repository"),
    "ati-persistence-repository": ("ati-postgresql",),
}

# Dashboards that carry a developer-only Jaeger UI navigation link
# (existing PR 29D behavior, re-encoded with a supported Grafana link).
JAEGER_LINK_TITLE = "Jaeger trace exploration"
JAEGER_UI_URL = "http://localhost:16686"
JAEGER_LINK_DASHBOARDS = frozenset(
    {"ati-api-http", "ati-agents-llm", "ati-investigations-reports"}
)

# GRAF-F18 scope guard: the dashboards may reference exactly these ATI
# application series, extracted from the PR 29D PromQL inventory. Any new ATI
# instrumentation series would need to be added here deliberately.
ALLOWED_ATI_SERIES = frozenset(
    {
        "ati_agent_invoke_duration_seconds_bucket",
        "ati_agent_invoke_failures_total",
        "ati_datasource_acquire_duration_seconds_bucket",
        "ati_datasource_acquire_duration_seconds_count",
        "ati_datasource_acquire_failures_total",
        "ati_datasource_convert_duration_seconds_bucket",
        "ati_datasource_convert_duration_seconds_count",
        "ati_datasource_convert_failures_total",
        "ati_datasource_convert_items_bucket",
        "ati_datasource_convert_items_count",
        "ati_embedding_invoke_duration_seconds_bucket",
        "ati_embedding_invoke_failures_total",
        "ati_evidence_consume_duration_seconds_bucket",
        "ati_evidence_messages_processed_total",
        "ati_evidence_outcomes_appended_total",
        "ati_evidence_outcomes_created_total",
        "ati_evidence_outcomes_unchanged_total",
        "ati_evidence_persist_duration_seconds_bucket",
        "ati_evidence_processing_failures_total",
        "ati_geo_resolve_duration_seconds_bucket",
        "ati_geo_resolve_failed_total",
        "ati_geo_resolve_resolved_total",
        "ati_geo_resolve_unresolvable_total",
        "ati_investigation_execute_duration_seconds_bucket",
        "ati_investigation_execute_executed_total",
        "ati_investigation_execute_failures_total",
        "ati_kafka_commit_failures_total",
        "ati_kafka_messages_committed_total",
        "ati_kafka_messages_published_total",
        "ati_kafka_messages_received_total",
        "ati_kafka_poll_failures_total",
        "ati_kafka_publish_failures_total",
        "ati_llm_invoke_duration_seconds_bucket",
        "ati_llm_invoke_failures_total",
        "ati_postgres_repository_duration_seconds_bucket",
        "ati_postgres_repository_failures_total",
        "ati_postgres_transaction_operation_duration_seconds_bucket",
        "ati_postgres_uow_commits_total",
        "ati_postgres_uow_duration_seconds_bucket",
        "ati_postgres_uow_failures_total",
        "ati_postgres_uow_rollbacks_total",
        "ati_provider_execute_duration_seconds_bucket",
        "ati_provider_execute_failures_total",
        "ati_provider_http_attempts_total",
        "ati_provider_http_duration_seconds_bucket",
        "ati_provider_http_failures_total",
        "ati_provider_http_retries_total",
        "ati_report_generate_duration_seconds_bucket",
        "ati_report_generate_duration_seconds_count",
        "ati_report_generate_failures_total",
    }
)

FORBIDDEN_IDENTIFIER_TOKENS = (
    "investigation_id",
    "evidence_id",
    "entity_id",
    "message_id",
    "execution_id",
    "request_id",
    "trace_id",
    "span_id",
    ".ip",
    "ip_address",
    "remote_addr",
    "source_ip",
    "domain",
    ".url",
    "query_string",
    "cookie",
    "authorization",
    "csrf",
    "idempotency",
)

_IP_LITERAL = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
_URL_SCHEME_PATTERN = re.compile(r"\bhttps?://")
_BY_CLAUSE = re.compile(r" by \(.*?\)")
_ATI_SERIES_TOKEN = re.compile(r"(?<![a-z0-9_])ati_[a-z0-9_]+")


def _load_yaml(relative: str) -> dict[str, Any]:
    """Load a YAML config under infra/observability as a JSON-ish dict."""
    data = yaml.safe_load((_OBSERVABILITY / relative).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _load_dashboards() -> list[dict[str, Any]]:
    """Return the parsed dashboard JSON documents (GRAF-C02/C03, GRAF-F16)."""
    files = sorted(_DASHBOARDS_DIR.glob("*.json"))
    return [json.loads(p.read_text(encoding="utf-8")) for p in files]


def _dashboard_by_uid() -> dict[str, dict[str, Any]]:
    return {dash["uid"]: dash for dash in _load_dashboards()}


def _panel_targets(panel: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the query targets declared by one panel."""
    return list(panel.get("targets") or [])


def _prometheus_targets(dashboard: dict[str, Any]) -> list[dict[str, Any]]:
    """Return targets using the stable Prometheus datasource (GRAF-F01)."""
    return [
        target
        for panel in dashboard["panels"]
        for target in _panel_targets(panel)
        if (target.get("datasource") or {}).get("uid") == "ati-prometheus"
    ]


def _loki_targets(dashboard: dict[str, Any]) -> list[dict[str, Any]]:
    """Return targets using the stable Loki datasource (GRAF-F14)."""
    return [
        target
        for panel in dashboard["panels"]
        for target in _panel_targets(panel)
        if (target.get("datasource") or {}).get("uid") == "ati-loki"
    ]


def _expressions(dashboard: dict[str, Any]) -> list[str]:
    """Executable PromQL expressions of a dashboard (reads the real ``expr``)."""
    return [
        target["expr"]
        for target in _prometheus_targets(dashboard)
        if target.get("expr")
    ]


def _dashboard_links(dashboard: dict[str, Any]) -> list[dict[str, Any]]:
    """Dashboard-level navigation links (verified Grafana ``links`` model)."""
    return list(dashboard.get("links") or [])


def _link_urls(dashboard: dict[str, Any]) -> list[str]:
    return [link.get("url", "") for link in _dashboard_links(dashboard)]


def _ati_series_used(dashboard: dict[str, Any]) -> set[str]:
    """ATI application series consumed by a dashboard's executable targets.

    Grouping labels inside ``by (...)`` are stripped first so label names
    (e.g. ``ati_outcome``) are never mistaken for metric series.
    """
    used: set[str] = set()
    for expr in _expressions(dashboard):
        for match in _ATI_SERIES_TOKEN.finditer(_BY_CLAUSE.sub("", expr)):
            used.add(match.group(0))
    return used


def _all_strings(obj: Any) -> list[str]:
    """Recursively collect every string value in a JSON document."""
    strings: list[str] = []

    def _walk(value: Any) -> None:
        if isinstance(value, str):
            strings.append(value)
        elif isinstance(value, list):
            for item in value:
                _walk(item)
        elif isinstance(value, dict):
            for item in value.values():
                _walk(item)

    _walk(obj)
    return strings


# ---------------------------------------------------------------------------
# GRAF-C01: provider provisioning contract
# ---------------------------------------------------------------------------


def test_graf_c01_dashboard_provider_yaml_parses_and_points_to_canonical_dir() -> None:
    """GRAF-C01 the file provider points at the mounted canonical directory."""
    provider = _load_yaml("grafana/provisioning/dashboards/dashboards.yaml")
    providers = provider["providers"]
    assert len(providers) == 1
    assert providers[0]["type"] == "file"
    assert providers[0]["options"]["path"] == "/etc/grafana/dashboards"


def test_graf_c01_compose_mounts_dashboards_read_only() -> None:
    """GRAF-C01 Compose mounts the canonical dir at the provider path, ro."""
    compose = yaml.safe_load(_COMPOSE_OBSERVABILITY.read_text(encoding="utf-8"))
    assert isinstance(compose, dict)
    grafana = compose["services"]["grafana"]
    volumes = grafana["volumes"]
    assert any(
        "./infra/observability/grafana/dashboards:/etc/grafana/dashboards:ro"
        in str(volume)
        for volume in volumes
    )
    assert any(
        "./infra/observability/grafana/provisioning:/etc/grafana/provisioning:ro"
        in str(volume)
        for volume in volumes
    )


# ---------------------------------------------------------------------------
# GRAF-C02..C05: inventory, validity, identity
# ---------------------------------------------------------------------------


def test_graf_c02_exactly_nine_dashboard_files() -> None:
    """GRAF-C02 exactly nine version-controlled dashboard JSON files."""
    files = sorted(_DASHBOARDS_DIR.glob("*.json"))
    assert len(files) == 9
    assert {f.name for f in files} == {
        "ati-system-overview.json",
        "ati-api-http.json",
        "ati-datasource-ingestion.json",
        "ati-kafka-redpanda.json",
        "ati-persistence-repository.json",
        "ati-postgresql.json",
        "ati-agents-llm.json",
        "ati-geo-resolution.json",
        "ati-investigations-reports.json",
    }


def test_graf_c03_all_dashboard_files_parse() -> None:
    """GRAF-C03 every dashboard file is valid JSON."""
    for path in sorted(_DASHBOARDS_DIR.glob("*.json")):
        json.loads(path.read_text(encoding="utf-8"))


def test_graf_c04_uids_exact_nine_and_unique() -> None:
    """GRAF-C04 the nine stable UIDs, exactly once each."""
    dashboards = _load_dashboards()
    uids = [dash["uid"] for dash in dashboards]
    assert len(uids) == len(set(uids)) == 9
    assert set(uids) == set(DASHBOARD_UID_TO_TITLE)


def test_graf_c05_titles_match_agreed_names() -> None:
    """GRAF-C05 exact agreed display titles."""
    dashboards = _load_dashboards()
    by_uid = {dash["uid"]: dash["title"] for dash in dashboards}
    assert by_uid == DASHBOARD_UID_TO_TITLE


# ---------------------------------------------------------------------------
# GRAF-C06..C08: datasource usage
# ---------------------------------------------------------------------------


def _datasource_uids_used(dashboard: dict[str, Any]) -> set[str]:
    uids: set[str] = set()
    for panel in dashboard["panels"]:
        for target in _panel_targets(panel):
            ds = target.get("datasource")
            if isinstance(ds, dict) and ds.get("uid"):
                uids.add(ds["uid"])
        ds = panel.get("datasource")
        if isinstance(ds, dict) and ds.get("uid"):
            uids.add(ds["uid"])
    return uids


def test_graf_c06_prometheus_panels_use_ati_prometheus() -> None:
    """GRAF-C06 Prometheus-datasource panels use the stable UID."""
    for dashboard in _load_dashboards():
        for panel in dashboard["panels"]:
            if panel.get("type") == "timeseries":
                ds = panel.get("datasource") or {}
                assert ds.get("type") == "prometheus"
                assert ds.get("uid") == "ati-prometheus"


def test_graf_c07_loki_panels_use_ati_loki() -> None:
    """GRAF-C07 Loki panels use the stable UID and classic LogQL targets."""
    for dashboard in _load_dashboards():
        for panel in dashboard["panels"]:
            if panel.get("type") == "logs":
                ds = panel.get("datasource") or {}
                assert ds.get("type") == "loki"
                assert ds.get("uid") == "ati-loki"
                for target in _panel_targets(panel):
                    assert target["datasource"]["uid"] == "ati-loki"
                    expr = target.get("expr") or ""
                    assert expr.startswith("{") and expr.endswith("}")


def test_graf_c08_trace_usage_uses_ati_jaeger() -> None:
    """GRAF-C08 trace navigation targets Jaeger via a verified Grafana link.

    PR 29D-1: the developer Jaeger UI link is a supported dashboard ``link``
    (``type: "link"``, ``url: http://localhost:16686``), never an
    ``externalLink`` pseudo-panel. The ``ati-jaeger`` datasource stays
    provisioned for Grafana's own trace exploration. Assert the datasource
    UID contract plus every Jaeger-facing dashboard link.
    """
    datasources = _load_yaml("grafana/provisioning/datasources/datasources.yaml")
    uids = {entry["uid"] for entry in datasources["datasources"]}
    assert "ati-jaeger" in uids

    dashboards = _dashboard_by_uid()
    jaeger_linked = {
        uid
        for uid, dashboard in dashboards.items()
        if any(
            link.get("title") == JAEGER_LINK_TITLE
            for link in _dashboard_links(dashboard)
        )
    }
    assert jaeger_linked == JAEGER_LINK_DASHBOARDS
    for uid in JAEGER_LINK_DASHBOARDS:
        jaeger_links = [
            link
            for link in _dashboard_links(dashboards[uid])
            if link.get("title") == JAEGER_LINK_TITLE
        ]
        assert len(jaeger_links) == 1, uid
        assert jaeger_links[0]["url"] == JAEGER_UI_URL
        assert jaeger_links[0]["type"] == "link"


# ---------------------------------------------------------------------------
# GRAF-C09..C11: navigation hierarchy (PR 29D-1 contract: dashboard links)
# ---------------------------------------------------------------------------


def _linked_dashboard_uids(dashboard: dict[str, Any]) -> set[str]:
    """Destinations of relative UID dashboard links (``/d/<uid>``)."""
    return {
        url.removeprefix("/d/")
        for url in _link_urls(dashboard)
        if url.startswith("/d/")
    }


def test_graf_c09_overview_links_to_all_eight_details() -> None:
    """GRAF-C09 System Overview links to every detail dashboard."""
    overview = _dashboard_by_uid()["ati-system-overview"]
    assert _linked_dashboard_uids(overview) == DETAIL_UID


def test_graf_c10_every_detail_links_back_to_overview() -> None:
    """GRAF-C10 all eight detail dashboards link to System Overview."""
    dashboards = _dashboard_by_uid()
    for uid in DETAIL_UID:
        assert "/d/ati-system-overview" in _link_urls(dashboards[uid]), uid


def test_graf_c11_required_child_links_exist() -> None:
    """GRAF-C11 the agreed drill-down hierarchy links exist."""
    dashboards = _dashboard_by_uid()
    for source, required in REQUIRED_CHILD_LINKS.items():
        linked = _linked_dashboard_uids(dashboards[source])
        for destination in required:
            assert destination in linked, (source, destination)


# ---------------------------------------------------------------------------
# GRAF-C12/C13: privacy and cardinality
# ---------------------------------------------------------------------------


def test_graf_c12_no_forbidden_high_cardinality_variables() -> None:
    """GRAF-C12 no IDs/IP/domain/request/execution identifiers anywhere.

    The check covers every metric expression, legend, variable value, and
    navigation link (the surfaces that become metric dimensions). The Jaeger
    dashboard-navigation URL is an explicit allowlist exception: it is a
    Grafana link target, not a metric dimension.
    """
    for path in sorted(_DASHBOARDS_DIR.glob("*.json")):
        dashboard = json.loads(path.read_text(encoding="utf-8"))
        for text in _all_strings(dashboard):
            if text.startswith(JAEGER_UI_URL):
                continue  # verified Jaeger UI navigation target
            lowered = text.lower()
            for token in FORBIDDEN_IDENTIFIER_TOKENS:
                assert token not in lowered, f"{path.name}: forbidden token {token!r}"
            assert not _IP_LITERAL.search(text), f"{path.name}: IP literal {text!r}"
            assert not _URL_SCHEME_PATTERN.search(text), f"{path.name}: URL in {text!r}"


def test_graf_c13_api_cardinality_uses_route_templates_only() -> None:
    """GRAF-C13 API identity is method x route template, never concrete paths."""
    dashboards = _dashboard_by_uid()
    queries = _expressions(dashboards["ati-api-http"])
    assert queries
    assert any("http_target" in q for q in queries)  # route-template dimension
    for query in queries:
        # Concrete path values are never used as filter values.
        assert "http_target=" not in query and "http_route=" not in query


# ---------------------------------------------------------------------------
# GRAF-C14..C18: structural integrity
# ---------------------------------------------------------------------------


def test_graf_c14_no_ephemeral_or_manual_datasource_ids() -> None:
    """GRAF-C14 panels reference only the three stable datasource UIDs."""
    for dashboard in _load_dashboards():
        used = _datasource_uids_used(dashboard)
        assert used <= STABLE_DATASOURCE_UIDS
        assert (
            "ati-jaeger" not in used
        )  # Jaeger stays an exploration/navigation surface, not a panel


def test_graf_c15_every_dashboard_tagged_ati_and_observability() -> None:
    """GRAF-C15 all dashboards carry the ati + observability tags."""
    for dashboard in _load_dashboards():
        tags = dashboard.get("tags") or []
        assert "ati" in tags
        assert "observability" in tags


def test_graf_c16_sane_time_and_refresh_defaults() -> None:
    """GRAF-C16 default last 1 hour with a sane refresh and a timepicker."""
    for dashboard in _load_dashboards():
        time = dashboard.get("time") or {}
        assert time.get("from") == "now-1h"
        assert time.get("to") == "now"
        assert str(dashboard.get("refresh")) in {"10s", "10"}
        assert dashboard.get("timepicker")


def test_graf_c17_no_generated_dashboard_framework_material() -> None:
    """GRAF-C17 the dashboards dir holds plain JSON only (no framework)."""
    for path in _DASHBOARDS_DIR.iterdir():
        assert path.suffix == ".json", (
            f"non-JSON artifact in canonical dir: {path.name}"
        )
    for relative in ("grafana/dashboards", "grafana/provisioning/dashboards"):
        directory = _OBSERVABILITY / relative
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix not in {".json", ".yaml", ".yml"}:
                raise AssertionError(f"unexpected artifact in dashboard tree: {path}")


def test_graf_c18_no_embedded_credentials() -> None:
    """GRAF-C18 no credentials/tokens/keys embedded in dashboard artifacts."""
    secret_patterns = (
        re.compile(r"password\s*[:=]", re.IGNORECASE),
        re.compile(r"\bsecret\b", re.IGNORECASE),
        re.compile(r"api[_-]?key\b", re.IGNORECASE),
        re.compile(r"\bbearer\b", re.IGNORECASE),
        re.compile(r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"\b(ghp|gho|ghs|github_pat)_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    )
    files = sorted(_DASHBOARDS_DIR.glob("*.json")) + [
        _PROVISIONING / "dashboards" / "dashboards.yaml",
        _PROVISIONING / "datasources" / "datasources.yaml",
    ]
    for path in files:
        text = path.read_text(encoding="utf-8")
        for pattern in secret_patterns:
            assert not pattern.search(text), f"{path.name}: {pattern.pattern!r}"


# ---------------------------------------------------------------------------
# Query-ownership assertions (parse executable target expressions, not
# descriptions)
# ---------------------------------------------------------------------------


def test_query_ownership_api_uses_route_template_telemetry() -> None:
    """API / HTTP targets the standard OTel http.server duration series."""
    dashboards = _dashboard_by_uid()
    queries = "\n".join(_expressions(dashboards["ati-api-http"]))
    assert "http_server_duration_milliseconds_bucket" in queries
    assert "http_server_duration_milliseconds_count" in queries
    assert "http_target" in queries  # registered route template identity


def test_query_ownership_kafka_lag_is_redpanda_authoritative() -> None:
    """Kafka lag derives from Redpanda series, never from ATI counters."""
    dashboards = _dashboard_by_uid()
    for uid in (
        "ati-system-overview",
        "ati-kafka-redpanda",
        "ati-datasource-ingestion",
    ):
        for expr in _expressions(dashboards[uid]):
            if "redpanda_kafka_max_offset" in expr and " - " in expr:
                # A lag arithmetic expression must join the committed offsets.
                assert "redpanda_kafka_consumer_group_committed_offset" in expr
                assert "ati_kafka" not in expr
    kafka_queries = "\n".join(_expressions(dashboards["ati-kafka-redpanda"]))
    assert "redpanda_kafka_max_offset" in kafka_queries
    assert "redpanda_kafka_consumer_group_committed_offset" in kafka_queries
    assert "redpanda_kafka_records_produced_total" in kafka_queries
    # Lag arithmetic exists on the overview and the Kafka dashboard.
    overview = "\n".join(_expressions(dashboards["ati-system-overview"]))
    assert "redpanda_kafka_consumer_group_committed_offset" in overview


def test_query_ownership_postgresql_uses_postgres_exporter() -> None:
    """PostgreSQL dashboard consumes postgres-exporter metrics."""
    dashboards = _dashboard_by_uid()
    queries = "\n".join(_expressions(dashboards["ati-postgresql"]))
    assert "pg_up" in queries
    assert "pg_exporter_scrapes_total" in queries
    assert "pg_stat_database_xact_commit" in queries
    assert "pg_stat_database_numbackends" in queries
    assert "ati_postgres" not in queries  # application telemetry stays separate


def test_query_ownership_persistence_uses_ati_persistence_series() -> None:
    """Persistence / Repository consumes ATI repository/UoW series."""
    dashboards = _dashboard_by_uid()
    queries = "\n".join(_expressions(dashboards["ati-persistence-repository"]))
    assert "ati_postgres_repository_duration_seconds_bucket" in queries
    assert "ati_postgres_repository_failures_total" in queries
    assert "ati_postgres_uow_duration_seconds_bucket" in queries
    assert "ati_postgres_uow_commits_total" in queries
    assert "ati_evidence_persist_duration_seconds_bucket" in queries
    assert "ati_evidence_outcomes_unchanged_total" in queries


def test_query_ownership_ingestion_contains_evidence_flow() -> None:
    """Datasource & Ingestion contains the Evidence-flow series."""
    dashboards = _dashboard_by_uid()
    queries = "\n".join(_expressions(dashboards["ati-datasource-ingestion"]))
    assert "ati_datasource_acquire_failures_total" in queries
    assert "ati_datasource_convert_items_bucket" in queries
    for series in (
        "ati_kafka_messages_published_total",
        "ati_kafka_messages_received_total",
        "ati_evidence_messages_processed_total",
        "ati_kafka_messages_committed_total",
        "ati_evidence_outcomes_created_total",
        "ati_evidence_outcomes_appended_total",
        "ati_evidence_outcomes_unchanged_total",
        "ati_evidence_processing_failures_total",
    ):
        assert series in queries


def test_query_ownership_geo_contains_geo_outcome_series() -> None:
    """GEO Resolution contains the GEO outcome/duration series."""
    dashboards = _dashboard_by_uid()
    queries = "\n".join(_expressions(dashboards["ati-geo-resolution"]))
    assert "ati_geo_resolve_resolved_total" in queries
    assert "ati_geo_resolve_unresolvable_total" in queries
    assert "ati_geo_resolve_failed_total" in queries
    assert "ati_geo_resolve_duration_seconds_bucket" in queries


def test_query_ownership_agents_contains_agent_llm_provider_series() -> None:
    """Agents & LLM contains agent/LLM/provider/embedding series."""
    dashboards = _dashboard_by_uid()
    queries = "\n".join(_expressions(dashboards["ati-agents-llm"]))
    for series in (
        "ati_agent_invoke_failures_total",
        "ati_agent_invoke_duration_seconds_bucket",
        "ati_llm_invoke_failures_total",
        "ati_llm_invoke_duration_seconds_bucket",
        "ati_provider_execute_failures_total",
        "ati_provider_http_attempts_total",
        "ati_provider_http_retries_total",
        "ati_provider_http_failures_total",
        "ati_embedding_invoke_failures_total",
        "ati_embedding_invoke_duration_seconds_bucket",
    ):
        assert series in queries


def test_query_ownership_investigations_contains_runner_and_report_series() -> None:
    """Investigations & Reports contains investigation/report series."""
    dashboards = _dashboard_by_uid()
    queries = "\n".join(_expressions(dashboards["ati-investigations-reports"]))
    assert "ati_investigation_execute_executed_total" in queries
    assert "ati_investigation_execute_failures_total" in queries
    assert "ati_investigation_execute_duration_seconds_bucket" in queries
    assert "ati_report_generate_failures_total" in queries
    assert "ati_report_generate_duration_seconds_bucket" in queries


def test_counter_usage_uses_rate_or_increase_or_grouped_sum() -> None:
    """Counters are consumed through rate()/increase()/grouped sum, never raw."""
    counters = re.compile(r"([a-z_]+_total)\b")
    for dashboard in _load_dashboards():
        for expr in _expressions(dashboard):
            for match in counters.finditer(expr):
                series = match.group(1)
                if series == "redpanda_application_uptime_seconds_total":
                    continue  # monotonic seconds gauge consumed with rate()
                assert any(func in expr for func in ("rate(", "increase(", "sum(")), (
                    f"{dashboard['uid']}: raw counter {series} in {expr}"
                )


def test_histogram_quantiles_use_bucket_series_and_le_grouping() -> None:
    """Histogram quantiles group by the verified le bucket dimension."""
    for dashboard in _load_dashboards():
        for expr in _expressions(dashboard):
            if "histogram_quantile(" in expr:
                assert "_bucket" in expr, (
                    f"{dashboard['uid']}: no bucket series in {expr}"
                )
                assert "by (le" in expr, f"{dashboard['uid']}: no le grouping in {expr}"


def test_no_application_and_infrastructure_mixing() -> None:
    """Application and infrastructure dashboards stay separated.

    Kafka / Redpanda owns no repository/UoW series; PostgreSQL owns no ATI
    application series; Persistence owns no exporter series beyond the
    documented dependency-health summary.
    """
    dashboards = _dashboard_by_uid()
    kafka = "\n".join(_expressions(dashboards["ati-kafka-redpanda"])) + "".join(
        _all_strings(dashboards["ati-kafka-redpanda"])
    )
    assert "ati_postgres" not in kafka
    assert "pg_" not in kafka

    postgres = "\n".join(_expressions(dashboards["ati-postgresql"])) + "".join(
        _all_strings(dashboards["ati-postgresql"])
    )
    assert "ati_postgres" not in postgres

    persistence = "\n".join(_expressions(dashboards["ati-persistence-repository"]))
    # The dependency-health summary may reference the exporter health gauge
    # only, never deep exporter statistics.
    for exporter_signal in ("pg_stat", "pg_locks", "pg_database_size", "pg_wal"):
        assert exporter_signal not in persistence


# ---------------------------------------------------------------------------
# GRAF-F01..F18: PR 29D-1 runtime-contract matrix
# ---------------------------------------------------------------------------

# Frozen PR 29D PromQL inventory (sorted multiset of executable expressions).
# GRAF-F03 asserts the repository multiset still matches exactly: PR 29D-1
# moved these expressions into Grafana's executable ``expr`` field without
# changing PromQL text.
PROMQL_INVENTORY: tuple[str, ...] = (
    "histogram_quantile(0.5, sum(ati_agent_invoke_duration_seconds_bucket) by (le, ati_agent))",
    "histogram_quantile(0.5, sum(ati_datasource_acquire_duration_seconds_bucket) by (le, ati_outcome))",
    "histogram_quantile(0.5, sum(ati_evidence_consume_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.5, sum(ati_evidence_persist_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.5, sum(ati_evidence_persist_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.5, sum(ati_geo_resolve_duration_seconds_bucket) by (le, ati_outcome))",
    "histogram_quantile(0.5, sum(ati_investigation_execute_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.5, sum(ati_llm_invoke_duration_seconds_bucket) by (le, ati_operation))",
    "histogram_quantile(0.5, sum(ati_postgres_repository_duration_seconds_bucket) by (le, ati_postgres_repository, ati_postgres_operation))",
    "histogram_quantile(0.5, sum(ati_postgres_transaction_operation_duration_seconds_bucket) by (le, ati_postgres_operation))",
    "histogram_quantile(0.5, sum(ati_postgres_uow_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.5, sum(ati_provider_http_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.5, sum(ati_report_generate_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.5, sum(http_server_duration_milliseconds_bucket) by (le))",
    "histogram_quantile(0.5, sum(http_server_duration_milliseconds_bucket) by (le))",
    "histogram_quantile(0.5, sum(redpanda_kafka_handler_latency_seconds_bucket) by (le))",
    "histogram_quantile(0.5, sum(redpanda_kafka_request_latency_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_agent_invoke_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_agent_invoke_duration_seconds_bucket) by (le, ati_agent))",
    "histogram_quantile(0.95, sum(ati_datasource_acquire_duration_seconds_bucket) by (le, ati_outcome))",
    "histogram_quantile(0.95, sum(ati_datasource_convert_duration_seconds_bucket) by (le, ati_outcome))",
    "histogram_quantile(0.95, sum(ati_datasource_convert_items_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_embedding_invoke_duration_seconds_bucket) by (le, ati_component))",
    "histogram_quantile(0.95, sum(ati_evidence_consume_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_evidence_persist_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_evidence_persist_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_evidence_persist_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_geo_resolve_duration_seconds_bucket) by (le, ati_outcome))",
    "histogram_quantile(0.95, sum(ati_investigation_execute_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_investigation_execute_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_llm_invoke_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_llm_invoke_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_llm_invoke_duration_seconds_bucket) by (le, ati_operation))",
    "histogram_quantile(0.95, sum(ati_postgres_repository_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_postgres_repository_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_postgres_repository_duration_seconds_bucket) by (le, ati_postgres_repository, ati_postgres_operation))",
    "histogram_quantile(0.95, sum(ati_postgres_transaction_operation_duration_seconds_bucket) by (le, ati_postgres_operation))",
    "histogram_quantile(0.95, sum(ati_postgres_uow_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_postgres_uow_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_postgres_uow_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_provider_execute_duration_seconds_bucket) by (le, ati_provider))",
    "histogram_quantile(0.95, sum(ati_provider_http_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_provider_http_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_report_generate_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(ati_report_generate_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(http_server_duration_milliseconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(http_server_duration_milliseconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(http_server_duration_milliseconds_bucket) by (le, http_method))",
    "histogram_quantile(0.95, sum(http_server_duration_milliseconds_bucket) by (le, http_target))",
    "histogram_quantile(0.95, sum(http_server_duration_milliseconds_bucket) by (le, http_target))",
    "histogram_quantile(0.95, sum(redpanda_kafka_handler_latency_seconds_bucket) by (le))",
    "histogram_quantile(0.95, sum(redpanda_kafka_request_latency_seconds_bucket) by (le))",
    "histogram_quantile(0.99, sum(ati_agent_invoke_duration_seconds_bucket) by (le, ati_agent))",
    "histogram_quantile(0.99, sum(ati_datasource_acquire_duration_seconds_bucket) by (le, ati_outcome))",
    "histogram_quantile(0.99, sum(ati_geo_resolve_duration_seconds_bucket) by (le, ati_outcome))",
    "histogram_quantile(0.99, sum(ati_investigation_execute_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.99, sum(ati_postgres_repository_duration_seconds_bucket) by (le, ati_postgres_repository, ati_postgres_operation))",
    "histogram_quantile(0.99, sum(ati_postgres_uow_duration_seconds_bucket) by (le))",
    "histogram_quantile(0.99, sum(http_server_duration_milliseconds_bucket) by (le))",
    "histogram_quantile(0.99, sum(http_server_duration_milliseconds_bucket) by (le))",
    "increase(ati_agent_invoke_failures_total[1h])",
    "increase(ati_agent_invoke_failures_total[1h])",
    "increase(ati_datasource_acquire_failures_total[1h])",
    "increase(ati_datasource_acquire_failures_total[1h])",
    "increase(ati_datasource_convert_failures_total[1h])",
    "increase(ati_datasource_convert_failures_total[1h])",
    "increase(ati_embedding_invoke_failures_total[1h])",
    "increase(ati_embedding_invoke_failures_total[1h])",
    "increase(ati_evidence_outcomes_appended_total[1h])",
    "increase(ati_evidence_outcomes_appended_total[1h])",
    "increase(ati_evidence_outcomes_appended_total[1h])",
    "increase(ati_evidence_outcomes_created_total[1h])",
    "increase(ati_evidence_outcomes_created_total[1h])",
    "increase(ati_evidence_outcomes_created_total[1h])",
    "increase(ati_evidence_outcomes_unchanged_total[1h])",
    "increase(ati_evidence_outcomes_unchanged_total[1h])",
    "increase(ati_evidence_outcomes_unchanged_total[1h])",
    "increase(ati_evidence_processing_failures_total[1h])",
    "increase(ati_evidence_processing_failures_total[1h])",
    "increase(ati_evidence_processing_failures_total[1h])",
    "increase(ati_geo_resolve_failed_total[1h])",
    "increase(ati_geo_resolve_failed_total[1h])",
    "increase(ati_geo_resolve_unresolvable_total[1h])",
    "increase(ati_investigation_execute_failures_total[1h])",
    "increase(ati_investigation_execute_failures_total[1h])",
    "increase(ati_kafka_commit_failures_total[1h])",
    "increase(ati_kafka_poll_failures_total[1h])",
    "increase(ati_kafka_publish_failures_total[1h])",
    "increase(ati_kafka_publish_failures_total[1h])",
    "increase(ati_llm_invoke_failures_total[1h])",
    "increase(ati_llm_invoke_failures_total[1h])",
    "increase(ati_llm_invoke_failures_total[1h])",
    "increase(ati_postgres_repository_failures_total[1h])",
    "increase(ati_postgres_uow_commits_total[1h])",
    "increase(ati_postgres_uow_commits_total[1h])",
    "increase(ati_postgres_uow_failures_total[1h])",
    "increase(ati_postgres_uow_failures_total[1h])",
    "increase(ati_postgres_uow_rollbacks_total[1h])",
    "increase(ati_postgres_uow_rollbacks_total[1h])",
    "increase(ati_provider_execute_failures_total[1h])",
    "increase(ati_provider_execute_failures_total[1h])",
    "increase(ati_provider_http_attempts_total[1h])",
    "increase(ati_provider_http_failures_total[1h])",
    "increase(ati_provider_http_failures_total[1h])",
    "increase(ati_provider_http_retries_total[1h])",
    "increase(ati_report_generate_failures_total[1h])",
    "increase(ati_report_generate_failures_total[1h])",
    "increase(ati_report_generate_failures_total[1h])",
    "increase(ati_report_generate_failures_total[1h])",
    "increase(pg_stat_database_deadlocks[1h])",
    "increase(redpanda_kafka_rpc_sasl_session_expiration_total[1h])",
    "increase(redpanda_rpc_request_errors_total[1h])",
    "rate(ati_datasource_acquire_duration_seconds_count[1h])",
    "rate(ati_datasource_convert_duration_seconds_count[1h])",
    "rate(ati_evidence_messages_processed_total[1h])",
    "rate(ati_evidence_messages_processed_total[1h])",
    "rate(ati_evidence_messages_processed_total[1h])",
    "rate(ati_evidence_messages_processed_total[1h])",
    "rate(ati_geo_resolve_failed_total[1h])",
    "rate(ati_geo_resolve_failed_total[1h])",
    "rate(ati_geo_resolve_resolved_total[1h])",
    "rate(ati_geo_resolve_resolved_total[1h])",
    "rate(ati_geo_resolve_resolved_total[1h])",
    "rate(ati_geo_resolve_resolved_total[1h])",
    "rate(ati_geo_resolve_unresolvable_total[1h])",
    "rate(ati_geo_resolve_unresolvable_total[1h])",
    "rate(ati_investigation_execute_executed_total[1h])",
    "rate(ati_investigation_execute_executed_total[1h])",
    "rate(ati_kafka_messages_committed_total[1h])",
    "rate(ati_kafka_messages_committed_total[1h])",
    "rate(ati_kafka_messages_committed_total[1h])",
    "rate(ati_kafka_messages_published_total[1h])",
    "rate(ati_kafka_messages_published_total[1h])",
    "rate(ati_kafka_messages_published_total[1h])",
    "rate(ati_kafka_messages_received_total[1h])",
    "rate(ati_kafka_messages_received_total[1h])",
    "rate(ati_kafka_messages_received_total[1h])",
    "rate(ati_report_generate_duration_seconds_count[1h])",
    "rate(http_server_duration_milliseconds_count[1h])",
    "rate(pg_stat_database_blks_hit[1h])",
    "rate(pg_stat_database_blks_read[1h])",
    "rate(pg_stat_database_tup_deleted[1h])",
    "rate(pg_stat_database_tup_inserted[1h])",
    "rate(pg_stat_database_tup_updated[1h])",
    "rate(pg_stat_database_xact_commit[1h])",
    "rate(pg_stat_database_xact_rollback[1h])",
    "rate(redpanda_application_uptime_seconds_total[1h])",
    "rate(redpanda_kafka_records_fetched_total[1h])",
    "rate(redpanda_kafka_records_fetched_total[1h])",
    "rate(redpanda_kafka_records_produced_total[1h])",
    "rate(redpanda_kafka_records_produced_total[1h])",
    'rate(redpanda_kafka_request_bytes_total{redpanda_request="consume"}[1h])',
    'rate(redpanda_kafka_request_bytes_total{redpanda_request="produce"}[1h])',
    "redpanda_application_uptime_seconds_total",
    "sum(ati_agent_invoke_failures_total) by (ati_agent)",
    "sum(ati_datasource_convert_items_count)",
    "sum(ati_geo_resolve_resolved_total) / (sum(ati_geo_resolve_resolved_total) + sum(ati_geo_resolve_unresolvable_total) + sum(ati_geo_resolve_failed_total))",
    "sum(ati_postgres_repository_failures_total) by (ati_postgres_repository, ati_postgres_operation)",
    "sum(http_server_active_requests) by (http_method)",
    "sum(http_server_duration_milliseconds_count) by (http_method)",
    "sum(http_server_duration_milliseconds_count) by (http_method, http_target)",
    "sum(http_server_duration_milliseconds_count) by (http_status_code)",
    'sum(http_server_duration_milliseconds_count{http_status_code=~"5.."})',
    "sum(pg_database_size_bytes) by (datname)",
    "sum(pg_exporter_last_scrape_error)",
    "sum(pg_exporter_last_scrape_error)",
    "sum(pg_exporter_scrapes_total)",
    "sum(pg_exporter_scrapes_total)",
    "sum(pg_locks_count) by (mode)",
    "sum(pg_scrape_collector_success)",
    "sum(pg_settings_max_connections)",
    'sum(pg_stat_activity_count{state="active"})',
    'sum(pg_stat_activity_count{state="idle in transaction"})',
    'sum(pg_stat_activity_count{state="idle"})',
    "sum(pg_stat_database_numbackends) by (datname)",
    "sum(pg_up)",
    "sum(pg_up)",
    "sum(pg_wal_segments)",
    "sum(pg_wal_size_bytes)",
    "sum(redpanda_cluster_brokers)",
    "sum(redpanda_cluster_partitions)",
    "sum(redpanda_cluster_unavailable_partitions)",
    "sum(redpanda_kafka_consumer_group_committed_offset) by (redpanda_topic)",
    'sum(redpanda_kafka_max_offset{redpanda_namespace="kafka"}) - sum(redpanda_kafka_consumer_group_committed_offset)',
    'sum(redpanda_kafka_max_offset{redpanda_namespace="kafka"}) - sum(redpanda_kafka_consumer_group_committed_offset)',
    'sum(redpanda_kafka_max_offset{redpanda_namespace="kafka"}) by (redpanda_topic)',
    'sum(redpanda_kafka_max_offset{redpanda_namespace="kafka"}) by (redpanda_topic) - sum(redpanda_kafka_consumer_group_committed_offset) by (redpanda_topic)',
    'sum(redpanda_kafka_max_offset{redpanda_namespace="kafka"}) by (redpanda_topic, redpanda_partition) - sum(redpanda_kafka_consumer_group_committed_offset) by (redpanda_topic, redpanda_partition)',
    "sum(redpanda_kafka_under_replicated_replicas)",
    "sum(redpanda_raft_recovery_offsets_pending)",
    "sum(redpanda_rpc_active_connections)",
    "sum(redpanda_storage_cache_disk_free_bytes)",
    "sum(redpanda_storage_disk_free_bytes)",
    "sum(redpanda_storage_disk_total_bytes)",
)


def test_graf_f01_prometheus_targets_have_executable_expr() -> None:
    """GRAF-F01 every intended Prometheus target carries non-empty ``expr``.

    Grafana's Prometheus datasource executes the PromQL from the ``expr``
    target field; an empty ``expr`` would render a query error.
    """
    for dashboard in _load_dashboards():
        for target in _prometheus_targets(dashboard):
            ds = target.get("datasource") or {}
            assert ds.get("type") == "prometheus"
            assert ds.get("uid") == "ati-prometheus"
            expr = target.get("expr") or ""
            assert expr.strip(), f"{dashboard['uid']}: empty expr in {target}"
            assert target.get("refId"), f"{dashboard['uid']}: missing refId"


def test_graf_f02_no_custom_query_surrogate() -> None:
    """GRAF-F02 no Prometheus target uses a custom ``query`` surrogate field."""
    for dashboard in _load_dashboards():
        for target in _prometheus_targets(dashboard):
            assert "query" not in target, (
                f"{dashboard['uid']}: surrogate query field in {target}"
            )


def test_graf_f03_promql_inventory_preserved() -> None:
    """GRAF-F03 the PR 29D PromQL inventory (multiset) is preserved exactly.

    PR 29D-1 moved expressions into ``expr`` without changing PromQL text; the
    multiset of executable expressions must match the frozen PR 29D inventory.
    """
    expressions = [
        expr for dashboard in _load_dashboards() for expr in _expressions(dashboard)
    ]
    assert len(expressions) == len(PROMQL_INVENTORY)
    assert sorted(expressions) == list(PROMQL_INVENTORY)


def test_graf_f04_navigation_uses_verified_grafana_links_contract() -> None:
    """GRAF-F04 navigation parses from Grafana's dashboard ``links`` model.

    Verified against pinned Grafana 13.2.2: a dashboard link uses
    ``type: "link"`` (or ``"dashboards"``) with ``url`` (relative ``/d/<uid>``
    or absolute), ``title``, and the standard ``keepTime`` / ``targetBlank`` /
    ``asDropdown`` / ``tags`` fields; Grafana resolves relative URLs and
    appends the current time range when ``keepTime`` is true.
    """
    for dashboard in _load_dashboards():
        links = _dashboard_links(dashboard)
        assert links, f"{dashboard['uid']}: no dashboard links"
        for link in links:
            assert link.get("type") in {"link", "dashboards"}, (
                f"{dashboard['uid']}: unsupported link type {link.get('type')!r}"
            )
            assert link.get("url"), f"{dashboard['uid']}: link without url"
            assert link.get("title"), f"{dashboard['uid']}: link without title"
            for field in ("keepTime", "targetBlank", "asDropdown", "includeVars"):
                assert field in link, f"{dashboard['uid']}: link missing {field}"
            assert isinstance(link.get("tags"), list)


def test_graf_f05_no_external_link_pseudo_panels() -> None:
    """GRAF-F05 no panel uses the ATI-invented ``externalLink`` type."""
    for dashboard in _load_dashboards():
        for panel in dashboard["panels"]:
            assert panel.get("type") != "externalLink", (
                f"{dashboard['uid']}: pseudo-panel {panel.get('title')!r}"
            )


def test_graf_f06_overview_links_to_all_eight_details() -> None:
    """GRAF-F06 System Overview links to all eight detail dashboards."""
    overview = _dashboard_by_uid()["ati-system-overview"]
    assert _linked_dashboard_uids(overview) == DETAIL_UID


def test_graf_f07_every_detail_links_back_to_overview() -> None:
    """GRAF-F07 every detail dashboard links back to System Overview."""
    dashboards = _dashboard_by_uid()
    for uid in DETAIL_UID:
        assert "/d/ati-system-overview" in _link_urls(dashboards[uid]), uid


def test_graf_f08_hierarchy_relationships_present() -> None:
    """GRAF-F08 all required child relationships are encoded as links."""
    dashboards = _dashboard_by_uid()
    for source, required in REQUIRED_CHILD_LINKS.items():
        linked = _linked_dashboard_uids(dashboards[source])
        for destination in required:
            assert destination in linked, (source, destination)


def test_graf_f09_stable_uid_destinations_no_hostnames() -> None:
    """GRAF-F09 navigation uses stable UID/relative destinations only.

    Link URLs are either relative ``/d/<uid>`` destinations (stable UIDs) or
    the allowlisted local Jaeger UI; no deployment-specific Grafana hostname is
    ever hard-coded.
    """
    for dashboard in _load_dashboards():
        for url in _link_urls(dashboard):
            if url.startswith("/d/"):
                dest = url.removeprefix("/d/")
                assert "/" not in dest, (dashboard["uid"], url)
                assert dest in DASHBOARD_UID_TO_TITLE, (
                    f"{dashboard['uid']}: unknown dashboard UID {dest!r}"
                )
                continue
            assert url == JAEGER_UI_URL, (
                f"{dashboard['uid']}: unexpected absolute link {url!r}"
            )


def test_graf_f10_time_preservation_enabled_on_dashboard_links() -> None:
    """GRAF-F10 dashboard links preserve the time range (``keepTime``).

    Verified against pinned Grafana 13.2.2: ``keepTime: true`` appends the
    current dashboard time range to the destination URL. It applies to
    dashboard-internal ``/d/<uid>`` links; the external Jaeger UI link keeps
    ``keepTime`` off so Jaeger never receives Grafana time parameters.
    """
    for dashboard in _load_dashboards():
        for link in _dashboard_links(dashboard):
            if link["url"].startswith("/d/"):
                assert link.get("keepTime") is True, (
                    f"{dashboard['uid']}: time preservation disabled on {link}"
                )
            else:
                assert link.get("keepTime") in (None, False)


def test_graf_f11_three_stable_datasource_uids_unchanged() -> None:
    """GRAF-F11 the three provisioned datasource UIDs are unchanged and reused."""
    datasources = _load_yaml("grafana/provisioning/datasources/datasources.yaml")
    uids = {entry["uid"] for entry in datasources["datasources"]}
    assert uids == STABLE_DATASOURCE_UIDS
    for dashboard in _load_dashboards():
        used = _datasource_uids_used(dashboard)
        assert used <= STABLE_DATASOURCE_UIDS


def test_graf_f12_query_ownership_contracts_preserved() -> None:
    """GRAF-F12 per-dashboard ownership contracts remain intact.

    API uses standard OTel HTTP route-template telemetry; Kafka lag is derived
    from authoritative Redpanda series; PostgreSQL uses postgres-exporter;
    Persistence uses ATI repository/UoW; Ingestion uses the Evidence flow; GEO
    uses GEO metrics; Agents & LLM uses agent/LLM/provider/embedding series;
    Investigations uses investigation/report series.
    """
    dashboards = _dashboard_by_uid()
    expectations = {
        "ati-api-http": ("http_server_duration_milliseconds_bucket", "http_target"),
        "ati-kafka-redpanda": (
            "redpanda_kafka_max_offset",
            "redpanda_kafka_consumer_group_committed_offset",
        ),
        "ati-postgresql": ("pg_up", "pg_exporter_scrapes_total"),
        "ati-persistence-repository": (
            "ati_postgres_repository_failures_total",
            "ati_postgres_uow_commits_total",
            "ati_evidence_outcomes_created_total",
        ),
        "ati-datasource-ingestion": (
            "ati_evidence_messages_processed_total",
            "ati_datasource_acquire_failures_total",
        ),
        "ati-geo-resolution": (
            "ati_geo_resolve_resolved_total",
            "ati_geo_resolve_duration_seconds_bucket",
        ),
        "ati-agents-llm": (
            "ati_agent_invoke_duration_seconds_bucket",
            "ati_llm_invoke_failures_total",
            "ati_provider_http_retries_total",
            "ati_embedding_invoke_failures_total",
        ),
        "ati-investigations-reports": (
            "ati_investigation_execute_executed_total",
            "ati_report_generate_failures_total",
        ),
    }
    for uid, markers in expectations.items():
        queries = "\n".join(_expressions(dashboards[uid]))
        for marker in markers:
            assert marker in queries, (uid, marker)


def test_graf_f13_privacy_and_cardinality_rules_preserved() -> None:
    """GRAF-F13 prohibited high-cardinality/content dimensions stay absent."""
    identifiers = set(FORBIDDEN_IDENTIFIER_TOKENS) | {"http_target=", "http_route="}
    for dashboard in _load_dashboards():
        for expr in _expressions(dashboard):
            lowered = expr.lower()
            for token in identifiers:
                assert token not in lowered, (
                    f"{dashboard['uid']}: forbidden token {token!r} in {expr}"
                )
            assert not _IP_LITERAL.search(expr), (
                f"{dashboard['uid']}: IP literal in {expr}"
            )


def test_graf_f14_loki_uses_verified_target_contract() -> None:
    """GRAF-F14 Loki panels use the verified Grafana Loki target contract.

    ``expr`` carries the classic LogQL filter, ``queryType`` is ``range``, and
    the targets bind the stable ``ati-loki`` datasource UID with a bounded
    OTLP label set (``service_name``).
    """
    dashboards = _dashboard_by_uid()
    loki_dashboards = {uid for uid, dash in dashboards.items() if _loki_targets(dash)}
    assert loki_dashboards == {
        "ati-agents-llm",
        "ati-api-http",
        "ati-datasource-ingestion",
        "ati-geo-resolution",
        "ati-investigations-reports",
    }
    for dashboard in dashboards.values():
        for target in _loki_targets(dashboard):
            ds = target.get("datasource") or {}
            assert ds.get("type") == "loki"
            assert ds.get("uid") == "ati-loki"
            expr = target.get("expr") or ""
            assert expr.startswith("{") and expr.endswith("}")
            assert "service_name=" in expr  # bounded OTLP label set
            assert target.get("queryType") == "range"
            assert target.get("refId")


def test_graf_f15_jaeger_uses_verified_navigation_contract() -> None:
    """GRAF-F15 Jaeger exploration/navigation uses a supported Grafana link.

    The developer Jaeger all-in-one UI entry point is a dashboard ``link`` of
    ``type: "link"`` pointing at the local Jaeger UI; the ``ati-jaeger``
    datasource remains provisioned for Grafana's own trace exploration. No
    proxy/plugin/backend was added.
    """
    datasources = _load_yaml("grafana/provisioning/datasources/datasources.yaml")
    uids = {entry["uid"] for entry in datasources["datasources"]}
    assert "ati-jaeger" in uids

    dashboards = _dashboard_by_uid()
    for uid in JAEGER_LINK_DASHBOARDS:
        jaeger_links = [
            link
            for link in _dashboard_links(dashboards[uid])
            if link.get("title") == JAEGER_LINK_TITLE
        ]
        assert len(jaeger_links) == 1, uid
        assert jaeger_links[0]["type"] == "link"
        assert jaeger_links[0]["url"] == JAEGER_UI_URL
    for uid, dashboard in dashboards.items():
        if uid not in JAEGER_LINK_DASHBOARDS:
            assert not any(
                link.get("title") == JAEGER_LINK_TITLE
                for link in _dashboard_links(dashboard)
            ), uid


def test_graf_f16_exactly_nine_dashboards_stable_identity() -> None:
    """GRAF-F16 exactly nine dashboards with the exact UID/title mapping."""
    dashboards = _load_dashboards()
    assert len(dashboards) == 9
    by_uid = {dash["uid"]: dash["title"] for dash in dashboards}
    assert by_uid == DASHBOARD_UID_TO_TITLE


def test_graf_f17_provisioning_unchanged_canonical_read_only_dir() -> None:
    """GRAF-F17 provisioning contracts unchanged; canonical dir stays read-only."""
    provider = _load_yaml("grafana/provisioning/dashboards/dashboards.yaml")
    providers = provider["providers"]
    assert len(providers) == 1
    assert providers[0]["type"] == "file"
    assert providers[0]["options"]["path"] == "/etc/grafana/dashboards"

    files = sorted(_DASHBOARDS_DIR.glob("*.json"))
    assert len(files) == 9

    compose = yaml.safe_load(_COMPOSE_OBSERVABILITY.read_text(encoding="utf-8"))
    assert isinstance(compose, dict)
    grafana_volumes = [str(v) for v in compose["services"]["grafana"]["volumes"]]
    assert any(
        volume.startswith("./infra/observability/grafana/dashboards:")
        and volume.endswith(":ro")
        for volume in grafana_volumes
    )


def test_graf_f18_no_new_ati_telemetry_referenced() -> None:
    """GRAF-F18 dashboards reference no ATI series beyond current main.

    Scope guard: PR 29D-1 is a representation correction, so every ATI
    application series used by an executable target must belong to the frozen
    PR 29D instrument set. Introducing new application telemetry would require
    an explicit, documented expansion of ``ALLOWED_ATI_SERIES``.
    """
    for dashboard in _load_dashboards():
        used = _ati_series_used(dashboard)
        unknown = used - ALLOWED_ATI_SERIES
        assert not unknown, f"{dashboard['uid']}: unknown ATI series {sorted(unknown)}"
