# SPDX-License-Identifier: AGPL-3.0-only
"""PR 39-10: shared local host-port resolution and its runtime wiring.

There is no repository shell-test framework, so these tests execute the
repository-owned ``scripts/local-port-config.sh`` resolver under a controlled
environment and lock in the resolved host-port contract (prefix derivation,
validation, explicit-override precedence, and origin derivation). They also
assert the rendered Compose definitions and the ``start.sh`` orchestration
consume the resolved values, so the feature is tested beyond helper
arithmetic.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Mapping

import pytest
import yaml  # type: ignore[import-untyped]  # mypy: PyYAML has no bundled stubs

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER = REPO_ROOT / "scripts" / "local-port-config.sh"
START_SH = REPO_ROOT / "start.sh"
COMPOSE_FILES = (
    REPO_ROOT / "compose.yaml",
    REPO_ROOT / "compose.observability.yaml",
)

_PORT_VARS = (
    "ATI_POSTGRES_HOST_PORT",
    "ATI_REDPANDA_HOST_PORT",
    "ATI_API_HOST_PORT",
    "ATI_FRONTEND_HOST_PORT",
    "ATI_GRAFANA_HOST_PORT",
    "ATI_PROMETHEUS_HOST_PORT",
    "ATI_JAEGER_HOST_PORT",
)
_ORIGIN_VARS = ("ATI_PUBLIC_BASE_URL", "ATI_WEB_BASE_URL")
_RESOLVED_VARS = _PORT_VARS + _ORIGIN_VARS

_DEFAULTS = {
    "ATI_POSTGRES_HOST_PORT": "5432",
    "ATI_REDPANDA_HOST_PORT": "9092",
    "ATI_API_HOST_PORT": "8000",
    "ATI_FRONTEND_HOST_PORT": "8080",
    "ATI_GRAFANA_HOST_PORT": "3000",
    "ATI_PROMETHEUS_HOST_PORT": "9090",
    "ATI_JAEGER_HOST_PORT": "16686",
}

_PREFIX_5 = {
    "ATI_POSTGRES_HOST_PORT": "55432",
    "ATI_REDPANDA_HOST_PORT": "59092",
    "ATI_API_HOST_PORT": "58000",
    "ATI_FRONTEND_HOST_PORT": "58080",
    "ATI_GRAFANA_HOST_PORT": "53000",
    "ATI_PROMETHEUS_HOST_PORT": "59090",
    "ATI_JAEGER_HOST_PORT": "56686",
}

# Container-side ports that must never move (publication and inspection map).
_PUBLISHED_CONTAINER_PORTS = {
    "postgres": "5432",
    "redpanda": "9092",
    "api": "8000",
    "frontend": "80",
    "prometheus": "9090",
    "jaeger": "16686",
    "grafana": "3000",
}


def _run_resolver(
    tmp_path: Path,
    env_file_lines: Mapping[str, str] | None = None,
    process_env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run the real resolver with one isolated .env and controlled environment."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "".join(f"{key}={value}\n" for key, value in (env_file_lines or {}).items()),
        encoding="utf-8",
    )

    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("ATI_") and key != "COMPOSE_PROJECT_NAME"
    }
    env["ATI_ENV_FILE"] = str(env_file)
    env.update(process_env or {})

    printf_args = " ".join(f'"${var}"' for var in _RESOLVED_VARS)
    script = (
        "set -Eeuo pipefail\n"
        f'source "{HELPER}"\n'
        "resolve_local_ports\n"
        f"printf '%s\\n' {printf_args}\n"
    )
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        env=env,
        cwd=REPO_ROOT,
        check=False,
    )


def _resolved(
    tmp_path: Path,
    env_file_lines: Mapping[str, str] | None = None,
    process_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return the resolver's exported variables, asserting success."""
    result = _run_resolver(tmp_path, env_file_lines, process_env)
    assert result.returncode == 0, result.stderr
    values = result.stdout.splitlines()
    assert len(values) == len(_RESOLVED_VARS), result.stdout
    return dict(zip(_RESOLVED_VARS, values, strict=True))


def _assert_rejected(
    tmp_path: Path,
    env_file_lines: Mapping[str, str] | None = None,
    process_env: Mapping[str, str] | None = None,
) -> None:
    """Assert the resolver fails with a concise error and no stdout values."""
    result = _run_resolver(tmp_path, env_file_lines, process_env)
    assert result.returncode != 0
    assert result.stdout == ""
    assert "error:" in result.stderr


# ---------------------------------------------------------------------------
# P01-P18: resolver matrix
# ---------------------------------------------------------------------------


def test_p01_prefix_absent_uses_defaults(tmp_path: Path) -> None:
    """P01: no prefix and no overrides keeps every standard port."""
    resolved = _resolved(tmp_path)
    for var, value in _DEFAULTS.items():
        assert resolved[var] == value
    assert resolved["ATI_PUBLIC_BASE_URL"] == "http://localhost:8080"
    assert resolved["ATI_WEB_BASE_URL"] == "http://localhost:8000"


def test_p02_empty_prefix_uses_defaults(tmp_path: Path) -> None:
    """P02: an explicitly empty prefix is backward compatible."""
    resolved = _resolved(tmp_path, {"ATI_PORT_PREFIX": ""})
    for var, value in _DEFAULTS.items():
        assert resolved[var] == value


def test_p03_prefix_five_derives_every_port(tmp_path: Path) -> None:
    """P03: prefix 5 produces the documented host-port namespace."""
    resolved = _resolved(tmp_path, {"ATI_PORT_PREFIX": "5"})
    for var, value in _PREFIX_5.items():
        assert resolved[var] == value, var
    assert resolved["ATI_PUBLIC_BASE_URL"] == "http://localhost:58080"
    assert resolved["ATI_WEB_BASE_URL"] == "http://localhost:58000"


def test_p04_prefix_five_with_one_explicit_override(tmp_path: Path) -> None:
    """P04: one explicit override wins; the rest stay prefix-derived."""
    resolved = _resolved(
        tmp_path,
        {"ATI_PORT_PREFIX": "5"},
        {"ATI_POSTGRES_HOST_PORT": "15432"},
    )
    assert resolved["ATI_POSTGRES_HOST_PORT"] == "15432"
    assert resolved["ATI_API_HOST_PORT"] == "58000"


def test_p05_prefix_five_with_all_explicit_overrides(tmp_path: Path) -> None:
    """P05: explicit values are used unchanged and never prefixed again."""
    explicit = {var: str(20000 + index) for index, var in enumerate(_PORT_VARS)}
    resolved = _resolved(tmp_path, {"ATI_PORT_PREFIX": "5"}, explicit)
    for var, value in explicit.items():
        assert resolved[var] == value, var


@pytest.mark.parametrize(
    ("prefix", "label"),
    [
        ("0", "P06"),
        ("6", "P07"),
        ("-1", "P08"),
        ("55", "P09"),
        ("x", "P10"),
        (" 5", "P11"),
    ],
)
def test_invalid_port_prefix_is_rejected(
    tmp_path: Path, prefix: str, label: str
) -> None:
    """P06-P11: invalid prefixes fail before any Compose mutation."""
    _assert_rejected(tmp_path, {"ATI_PORT_PREFIX": prefix})


def test_p12_explicit_port_zero_is_rejected(tmp_path: Path) -> None:
    """P12: an explicit port must be a valid TCP port."""
    _assert_rejected(tmp_path, {"ATI_API_HOST_PORT": "0"})


def test_p13_explicit_port_above_range_is_rejected(tmp_path: Path) -> None:
    """P13: 65536 is out of range."""
    _assert_rejected(tmp_path, {"ATI_API_HOST_PORT": "65536"})


def test_p14_explicit_nonnumeric_port_is_rejected(tmp_path: Path) -> None:
    """P14: nonnumeric explicit ports are rejected."""
    _assert_rejected(tmp_path, {"ATI_API_HOST_PORT": "http"})


def test_p15_web_origin_follows_explicit_api_port(tmp_path: Path) -> None:
    """P15: the web origin follows the effective API host port."""
    resolved = _resolved(
        tmp_path,
        {"ATI_PORT_PREFIX": "5", "ATI_API_HOST_PORT": "61000"},
    )
    assert resolved["ATI_API_HOST_PORT"] == "61000"
    assert resolved["ATI_WEB_BASE_URL"] == "http://localhost:61000"


def test_p16_public_origin_follows_explicit_frontend_port(tmp_path: Path) -> None:
    """P16: the React origin follows the effective frontend host port."""
    resolved = _resolved(
        tmp_path,
        {"ATI_PORT_PREFIX": "5", "ATI_FRONTEND_HOST_PORT": "61888"},
    )
    assert resolved["ATI_FRONTEND_HOST_PORT"] == "61888"
    assert resolved["ATI_PUBLIC_BASE_URL"] == "http://localhost:61888"


def test_p17_explicit_browser_origins_are_preserved(tmp_path: Path) -> None:
    """P17: explicit browser origins are never rewritten by the prefix."""
    resolved = _resolved(
        tmp_path,
        {
            "ATI_PORT_PREFIX": "5",
            "ATI_PUBLIC_BASE_URL": "https://ati.example.test",
            "ATI_WEB_BASE_URL": "https://web.example.test",
        },
    )
    assert resolved["ATI_PUBLIC_BASE_URL"] == "https://ati.example.test"
    assert resolved["ATI_WEB_BASE_URL"] == "https://web.example.test"


def test_p18_five_digit_default_is_not_string_concatenated(tmp_path: Path) -> None:
    """P18: Jaeger is 56686, never 516686."""
    resolved = _resolved(tmp_path, {"ATI_PORT_PREFIX": "5"})
    assert resolved["ATI_JAEGER_HOST_PORT"] == "56686"
    assert resolved["ATI_JAEGER_HOST_PORT"] != "516686"


def test_process_environment_wins_over_env_file(tmp_path: Path) -> None:
    """Process environment retains established precedence over .env."""
    resolved = _resolved(
        tmp_path,
        {"ATI_POSTGRES_HOST_PORT": "15000"},
        {"ATI_POSTGRES_HOST_PORT": "16000"},
    )
    assert resolved["ATI_POSTGRES_HOST_PORT"] == "16000"


def test_empty_process_value_falls_through_to_env_file(tmp_path: Path) -> None:
    """An empty service-specific value counts as unspecified."""
    resolved = _resolved(
        tmp_path,
        {"ATI_POSTGRES_HOST_PORT": "15000"},
        {"ATI_POSTGRES_HOST_PORT": ""},
    )
    assert resolved["ATI_POSTGRES_HOST_PORT"] == "15000"


def test_helper_is_side_effect_free_when_sourced() -> None:
    """Sourcing the helper emits no output and mutates no port variables."""
    result = subprocess.run(
        ["bash", "-c", f'source "{HELPER}"; printf done'],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "done"


# ---------------------------------------------------------------------------
# Rendered Compose assertions
# ---------------------------------------------------------------------------


def _load_compose_services() -> dict[str, dict[str, Any]]:
    """Merge the core and observability Compose service definitions."""
    services: dict[str, dict[str, Any]] = {}
    for path in COMPOSE_FILES:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for name, body in (loaded.get("services") or {}).items():
            services.setdefault(name, {}).update(body or {})
    return services


_INTERPOLATION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _interpolate(value: str, mapping: Mapping[str, str]) -> str:
    """Resolve the simple ``${VAR:-default}`` Compose interpolation forms used here."""

    def replace(match: re.Match[str]) -> str:
        var, default = match.group(1), match.group(2)
        if var in mapping:
            return mapping[var]
        if default is not None:
            return default
        return ""

    return _INTERPOLATION.sub(replace, value)


def _published_host_ports(
    services: Mapping[str, Mapping[str, Any]], mapping: Mapping[str, str]
) -> dict[str, dict[str, str]]:
    """Render every service's published ``container_port -> host_port`` bindings."""
    rendered: dict[str, dict[str, str]] = {}
    for name, body in services.items():
        ports = body.get("ports") or []
        if not ports:
            continue
        bindings: dict[str, str] = {}
        for entry in ports:
            if not isinstance(entry, str):
                continue
            host, container = _interpolate(entry, mapping).rsplit(":", 1)
            bindings[container] = host
        rendered[name] = bindings
    return rendered


def test_rendered_compose_prefix_five_publishes_documented_mappings(
    tmp_path: Path,
) -> None:
    """Prefix 5 renders all seven documented host-to-container mappings."""
    resolved = _resolved(tmp_path, {"ATI_PORT_PREFIX": "5"})
    bindings = _published_host_ports(_load_compose_services(), resolved)
    for service, container_port in _PUBLISHED_CONTAINER_PORTS.items():
        assert (
            bindings[service][container_port]
            == _PREFIX_5[f"ATI_{service.upper()}_HOST_PORT"]
        ), service


def test_rendered_compose_mixed_override_keeps_prefix_for_others(
    tmp_path: Path,
) -> None:
    """A single explicit override changes only that service."""
    resolved = _resolved(
        tmp_path,
        {"ATI_PORT_PREFIX": "5"},
        {"ATI_API_HOST_PORT": "61000"},
    )
    bindings = _published_host_ports(_load_compose_services(), resolved)
    assert bindings["api"]["8000"] == "61000"
    assert bindings["postgres"]["5432"] == "55432"
    assert bindings["frontend"]["80"] == "58080"


def test_rendered_compose_no_prefix_preserves_standard_ports(tmp_path: Path) -> None:
    """An absent prefix renders the standard default mappings."""
    resolved = _resolved(tmp_path)
    bindings = _published_host_ports(_load_compose_services(), resolved)
    for service, container_port in _PUBLISHED_CONTAINER_PORTS.items():
        assert (
            bindings[service][container_port]
            == _DEFAULTS[f"ATI_{service.upper()}_HOST_PORT"]
        ), service


def test_redpanda_advertised_port_matches_publication(tmp_path: Path) -> None:
    """Redpanda's OUTSIDE listener advertises exactly the published port."""
    resolved = _resolved(tmp_path, {"ATI_PORT_PREFIX": "5"})
    services = _load_compose_services()
    bindings = _published_host_ports(services, resolved)["redpanda"]
    published = bindings["9092"]

    command = services["redpanda"]["command"]
    advertise = next(
        arg
        for arg in command
        if isinstance(arg, str) and arg.startswith("--advertise-kafka-addr")
    )
    match = re.search(
        r"OUTSIDE://127\.0\.0\.1:([^,]+)", _interpolate(advertise, resolved)
    )
    assert match is not None
    assert match.group(1) == published == "59092"


def test_container_ports_and_internal_endpoints_are_unchanged() -> None:
    """Prefixing never changes container ports or in-network endpoints."""
    text = "\n".join(path.read_text(encoding="utf-8") for path in COMPOSE_FILES)
    assert "postgres:5432" in text  # in-network PostgreSQL endpoint
    assert "redpanda:29092" in text  # in-network Kafka listener
    assert '"--port", "8000"' in text  # FastAPI container port
    services = _load_compose_services()
    for internal in (
        "otel-collector",
        "loki",
        "postgres-exporter",
        "worker",
        "geo-resolver",
        "migrate",
        "fake-data-bootstrap",
        "scheduler",
    ):
        assert not services[internal].get("ports"), internal


# ---------------------------------------------------------------------------
# start.sh wiring
# ---------------------------------------------------------------------------


def _script() -> str:
    """Return the current start.sh contents."""
    return START_SH.read_text(encoding="utf-8")


def _shell_function(script: str, name: str) -> str:
    """Return the body of one top-level ``name() { ... }`` shell function."""
    marker = f"{name}() {{"
    start = script.index(marker)
    end = script.index("\n}\n", start)
    return script[start : end + 3]


def test_start_sources_shared_resolver_and_has_no_hardcoded_api_port() -> None:
    """start.sh consumes the shared resolver instead of its own port math."""
    script = _script()
    assert "scripts/local-port-config.sh" in script
    assert "resolve_local_ports" in script
    assert "API_PORT=8000" not in script
    assert "API_PORT=$ATI_API_HOST_PORT" in script


def test_start_resolves_ports_before_any_compose_mutation() -> None:
    """Invalid configuration fails before the first Compose command runs."""
    script = _script()
    resolve_call = script.index("\nif ! resolve_local_ports; then")
    first_compose = script.index(
        "compose_cmd up --no-start --no-recreate --remove-orphans"
    )
    assert resolve_call < first_compose
    failure = script.index("\nif ! resolve_local_ports; then")
    assert script.index("exit 1", failure) < first_compose


def test_start_probes_and_summary_use_effective_ports() -> None:
    """Health probes and the endpoint summary use the resolved variables."""
    script = _script()
    for var in (
        "POSTGRES_PORT",
        "REDPANDA_PORT",
        "API_PORT",
        "FRONTEND_PORT",
        "GRAFANA_PORT",
        "PROMETHEUS_PORT",
        "JAEGER_PORT",
    ):
        assert f"{var}=$ATI_" in script, var
    assert (
        'probe_api() { http_probe "http://127.0.0.1:${API_PORT}/health/ready"; }'
        in script
    )
    assert "http://localhost:%s/ (server-rendered web UI)" in script
    assert "$JAEGER_PORT" in _shell_function(script, "endpoint_for")


def test_start_reconciles_stale_published_ports_without_rebuild_or_teardown() -> None:
    """Port-only changes recreate containers, preserving images and data."""
    script = _script()
    body = _shell_function(script, "reconcile_published_host_ports")
    assert "port_mapping_matches" in body
    assert "remove_project_containers" in body

    inspect = _shell_function(script, "container_published_host_port")
    assert "HostConfig.PortBindings" in inspect

    remove = _shell_function(script, "remove_project_containers")
    assert "podman rm -f" in remove
    assert "compose_cmd build" not in remove
    assert "down" not in remove
    assert "delete_data" not in remove

    # The reconciliation runs before the create-phase short-circuit so a
    # stale mapping can never be treated as an idempotent start.
    assert script.index("reconcile_published_host_ports\n") < script.index(
        "if containers_exist_for_all; then"
    )
