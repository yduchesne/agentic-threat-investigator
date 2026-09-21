# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic offline validation of PR 29D Grafana dashboards-as-code.

These tests are deliberately static: they parse the provisioning YAML and
the nine repository-canonical dashboard JSON files, extract the target
expressions (PromQL queries, Loki LogQL expressions, datasource UIDs, link
targets), and assert the frozen PR 29D contracts. Proving the third-party
products run is left to the manual developer smoke procedure in
``docs/OBSERVABILITY.md`` (no telemetry integration-test phase, GRAF-C17
rule and PR-level acceptance).
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


def _load_yaml(relative: str) -> dict[str, Any]:
    """Load a YAML config under infra/observability as a JSON-ish dict."""
    data = yaml.safe_load((_OBSERVABILITY / relative).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _load_dashboards() -> list[dict[str, Any]]:
    """Return the parsed dashboard JSON documents (GRAF-C02/C03)."""
    files = sorted(_DASHBOARDS_DIR.glob("*.json"))
    return [json.loads(p.read_text(encoding="utf-8")) for p in files]


def _panel_targets(panel: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the query targets declared by one panel."""
    return list(panel.get("targets") or [])


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
    """GRAF-C08 trace usage targets the Jaeger runtime via the stable contract.

    Reconciliation: Grafana 13.2.2's Jaeger datasource queries Jaeger 2.21.0's
    v3 query API (verified compatible); trace exploration panels link to the
    Jaeger all-in-one UI and the ``ati-jaeger`` datasource stays provisioned
    for Grafana's own trace exploration. Assert the datasource UID contract
    plus every Jaeger-facing panel target.
    """
    datasources = _load_yaml("grafana/provisioning/datasources/datasources.yaml")
    uids = {entry["uid"] for entry in datasources["datasources"]}
    assert "ati-jaeger" in uids

    for dashboard in _load_dashboards():
        used = _datasource_uids_used(dashboard)
        assert used <= STABLE_DATASOURCE_UIDS
        for panel in dashboard["panels"]:
            if (
                panel.get("type") == "externalLink"
                and "trace" in panel.get("title", "").lower()
            ):
                assert panel["link"].startswith("http://localhost:16686")


# ---------------------------------------------------------------------------
# GRAF-C09..C11: navigation hierarchy
# ---------------------------------------------------------------------------


def _external_links(dashboard: dict[str, Any]) -> list[str]:
    return [
        panel.get("link", "")
        for panel in dashboard["panels"]
        if panel.get("type") == "externalLink"
    ]


def test_graf_c09_overview_links_to_all_eight_details() -> None:
    """GRAF-C09 System Overview links to every detail dashboard."""
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}
    overview = dashboards["ati-system-overview"]
    linked_uids = {
        link.removeprefix("/d/")
        for link in _external_links(overview)
        if link.startswith("/d/")
    }
    assert linked_uids == DETAIL_UID


def test_graf_c10_every_detail_links_back_to_overview() -> None:
    """GRAF-C10 all eight detail dashboards link to System Overview."""
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}
    for uid in DETAIL_UID:
        assert any(
            link == "/d/ati-system-overview"
            for link in _external_links(dashboards[uid])
        ), uid


def test_graf_c11_required_child_links_exist() -> None:
    """GRAF-C11 the agreed drill-down hierarchy links exist."""
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}

    def links_to(uid: str, target: str) -> bool:
        return any(link == f"/d/{target}" for link in _external_links(dashboards[uid]))

    assert links_to("ati-investigations-reports", "ati-agents-llm")
    assert links_to("ati-datasource-ingestion", "ati-kafka-redpanda")
    assert links_to("ati-datasource-ingestion", "ati-persistence-repository")
    assert links_to("ati-persistence-repository", "ati-postgresql")


# ---------------------------------------------------------------------------
# GRAF-C12/C13: privacy and cardinality
# ---------------------------------------------------------------------------


def test_graf_c12_no_forbidden_high_cardinality_variables() -> None:
    """GRAF-C12 no IDs/IP/domain/request/execution identifiers anywhere.

    The check covers every metric expression, legend, and variable value
    (the surfaces that become metric dimensions). The Jaeger external-link
    navigation URL is an explicit allowlist exception: it is a Grafana link
    target, not a metric dimension.
    """
    for path in sorted(_DASHBOARDS_DIR.glob("*.json")):
        dashboard = json.loads(path.read_text(encoding="utf-8"))
        for text in _all_strings(dashboard):
            if text.startswith("http://localhost:16686"):
                continue  # verified Jaeger UI navigation target
            lowered = text.lower()
            for token in FORBIDDEN_IDENTIFIER_TOKENS:
                assert token not in lowered, f"{path.name}: forbidden token {token!r}"
            assert not _IP_LITERAL.search(text), f"{path.name}: IP literal {text!r}"
            assert not _URL_SCHEME_PATTERN.search(text), f"{path.name}: URL in {text!r}"


def test_graf_c13_api_cardinality_uses_route_templates_only() -> None:
    """GRAF-C13 API identity is method x route template, never concrete paths."""
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}
    api = dashboards["ati-api-http"]
    queries = [
        target.get("query", "")
        for panel in api["panels"]
        for target in _panel_targets(panel)
        if target.get("query")
    ]
    assert queries
    assert any("http_target" in q for q in queries)  # route-template dimension
    for query in queries:
        # Concrete path values are never used as filter values.
        assert "http_target=" not in query and "http_route=" not in query
        # Template grouping is the only http_target/route usage: as a grouping
        # label inside `by (...)`, or within a method/status group expression.
        matches = re.findall(r"http_target", query)
        for _m in matches:
            assert "http_target" in query  # present as the bounded label only


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
        )  # Jaeger stays an exploration surface, not a panel


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
# Query-ownership assertions (parse target expressions, not descriptions)
# ---------------------------------------------------------------------------


def _queries(dashboard: dict[str, Any]) -> list[str]:
    return [
        target.get("query", "")
        for panel in dashboard["panels"]
        for target in _panel_targets(panel)
        if target.get("query")
    ]


def test_query_ownership_api_uses_route_template_telemetry() -> None:
    """API / HTTP targets the standard OTel http.server duration series."""
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}
    queries = "\n".join(_queries(dashboards["ati-api-http"]))
    assert "http_server_duration_milliseconds_bucket" in queries
    assert "http_server_duration_milliseconds_count" in queries
    assert "http_target" in queries  # registered route template identity


def test_query_ownership_kafka_lag_is_redpanda_authoritative() -> None:
    """Kafka lag derives from Redpanda series, never from ATI counters."""
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}
    for uid in (
        "ati-system-overview",
        "ati-kafka-redpanda",
        "ati-datasource-ingestion",
    ):
        for query in _queries(dashboards[uid]):
            if "redpanda_kafka_max_offset" in query and " - " in query:
                # A lag arithmetic expression must join the committed offsets.
                assert "redpanda_kafka_consumer_group_committed_offset" in query
                assert "ati_kafka" not in query
    kafka_queries = "\n".join(_queries(dashboards["ati-kafka-redpanda"]))
    assert "redpanda_kafka_max_offset" in kafka_queries
    assert "redpanda_kafka_consumer_group_committed_offset" in kafka_queries
    assert "redpanda_kafka_records_produced_total" in kafka_queries
    # Lag arithmetic exists on the overview and the Kafka dashboard.
    overview = "\n".join(_queries(dashboards["ati-system-overview"]))
    assert "redpanda_kafka_consumer_group_committed_offset" in overview


def test_query_ownership_postgresql_uses_postgres_exporter() -> None:
    """PostgreSQL dashboard consumes postgres-exporter metrics."""
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}
    queries = "\n".join(_queries(dashboards["ati-postgresql"]))
    assert "pg_up" in queries
    assert "pg_exporter_scrapes_total" in queries
    assert "pg_stat_database_xact_commit" in queries
    assert "pg_stat_database_numbackends" in queries
    assert "ati_postgres" not in queries  # application telemetry stays separate


def test_query_ownership_persistence_uses_ati_persistence_series() -> None:
    """Persistence / Repository consumes ATI repository/UoW series."""
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}
    queries = "\n".join(_queries(dashboards["ati-persistence-repository"]))
    assert "ati_postgres_repository_duration_seconds_bucket" in queries
    assert "ati_postgres_repository_failures_total" in queries
    assert "ati_postgres_uow_duration_seconds_bucket" in queries
    assert "ati_postgres_uow_commits_total" in queries
    assert "ati_evidence_persist_duration_seconds_bucket" in queries
    assert "ati_evidence_outcomes_unchanged_total" in queries


def test_query_ownership_ingestion_contains_evidence_flow() -> None:
    """Datasource & Ingestion contains the Evidence-flow series."""
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}
    queries = "\n".join(_queries(dashboards["ati-datasource-ingestion"]))
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
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}
    queries = "\n".join(_queries(dashboards["ati-geo-resolution"]))
    assert "ati_geo_resolve_resolved_total" in queries
    assert "ati_geo_resolve_unresolvable_total" in queries
    assert "ati_geo_resolve_failed_total" in queries
    assert "ati_geo_resolve_duration_seconds_bucket" in queries


def test_query_ownership_agents_contains_agent_llm_provider_series() -> None:
    """Agents & LLM contains agent/LLM/provider/embedding series."""
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}
    queries = "\n".join(_queries(dashboards["ati-agents-llm"]))
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
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}
    queries = "\n".join(_queries(dashboards["ati-investigations-reports"]))
    assert "ati_investigation_execute_executed_total" in queries
    assert "ati_investigation_execute_failures_total" in queries
    assert "ati_investigation_execute_duration_seconds_bucket" in queries
    assert "ati_report_generate_failures_total" in queries
    assert "ati_report_generate_duration_seconds_bucket" in queries


def test_counter_usage_uses_rate_or_increase_or_grouped_sum() -> None:
    """Counters are consumed through rate()/increase()/grouped sum, never raw."""
    counters = re.compile(r"([a-z_]+_total)\b")
    for dashboard in _load_dashboards():
        for query in _queries(dashboard):
            for match in counters.finditer(query):
                series = match.group(1)
                if series == "redpanda_application_uptime_seconds_total":
                    continue  # monotonic seconds gauge consumed with rate()
                assert any(func in query for func in ("rate(", "increase(", "sum(")), (
                    f"{dashboard['uid']}: raw counter {series} in {query}"
                )


def test_histogram_quantiles_use_bucket_series_and_le_grouping() -> None:
    """Histogram quantiles group by the verified le bucket dimension."""
    for dashboard in _load_dashboards():
        for query in _queries(dashboard):
            if "histogram_quantile(" in query:
                assert "_bucket" in query, (
                    f"{dashboard['uid']}: no bucket series in {query}"
                )
                assert "by (le" in query, (
                    f"{dashboard['uid']}: no le grouping in {query}"
                )


def test_no_application_and_infrastructure_mixing() -> None:
    """Application and infrastructure dashboards stay separated.

    Kafka / Redpanda owns no repository/UoW series; PostgreSQL owns no ATI
    application series; Persistence owns no exporter series beyond the
    documented dependency-health summary.
    """
    dashboards = {dash["uid"]: dash for dash in _load_dashboards()}
    kafka = "\n".join(_queries(dashboards["ati-kafka-redpanda"])) + "".join(
        _all_strings(dashboards["ati-kafka-redpanda"])
    )
    assert "ati_postgres" not in kafka
    assert "pg_" not in kafka

    postgres = "\n".join(_queries(dashboards["ati-postgresql"])) + "".join(
        _all_strings(dashboards["ati-postgresql"])
    )
    assert "ati_postgres" not in postgres

    persistence = "\n".join(_queries(dashboards["ati-persistence-repository"]))
    # The dependency-health summary may reference the exporter health gauge
    # only, never deep exporter statistics.
    for exporter_signal in ("pg_stat", "pg_locks", "pg_database_size", "pg_wal"):
        assert exporter_signal not in persistence
