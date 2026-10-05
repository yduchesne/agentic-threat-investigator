# SPDX-License-Identifier: AGPL-3.0-only
"""PR 34 harness topology configuration (parsed once from the harness env).

The observability harness owns the backend URLs; the ATI generator process
never sees any of these variables (``scripts/observability-integration.sh``
forwards only ``ATI_OBSERVABILITY_ENABLED`` and the standard OTLP endpoint).
This module therefore resolves exactly the verifier-side contact points plus
the run identity/credentials the harness generated.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _require(env: str) -> str:
    """Return a required environment variable or exit with a clear message."""
    value = os.environ.get(env, "")
    if not value.strip():
        raise SystemExit(f"{env} is required for the observability harness")
    return value.strip()


@dataclass(frozen=True)
class ObsTopology:
    """The verifier-visible topology of one harness run.

    URLs are the harness-randomized host ports; ``run_id`` is the unique
    diagnostic run identity the generator emitted; Grafana credentials are
    the synthetic per-run values (never committed, never logged).
    """

    run_id: str
    collector_health_url: str
    prometheus_url: str
    jaeger_url: str
    loki_url: str
    grafana_url: str
    grafana_admin_user: str
    grafana_admin_password: str

    @classmethod
    def from_environment(cls) -> "ObsTopology":
        """Build the topology from the harness environment variables."""
        return cls(
            run_id=_require("ATI_OBS_RUN_ID"),
            collector_health_url=_require("ATI_OBS_COLLECTOR_HEALTH_URL"),
            prometheus_url=_require("ATI_OBS_PROMETHEUS_URL"),
            jaeger_url=_require("ATI_OBS_JAEGER_URL"),
            loki_url=_require("ATI_OBS_LOKI_URL"),
            grafana_url=_require("ATI_OBS_GRAFANA_URL"),
            grafana_admin_user=_require("ATI_OBS_GRAFANA_ADMIN_USER"),
            grafana_admin_password=_require("ATI_OBS_GRAFANA_ADMIN_PASSWORD"),
        )


__all__ = ["ObsTopology"]
