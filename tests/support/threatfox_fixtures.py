# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI-authored synthetic ThreatFox response fixtures.

Every payload in this module is synthetic documentation-safe test data
authored for ATI (RFC 5737 addresses, RFC 2606 ``.test`` domains, and
synthetic identifiers). No payload is a copied ThreatFox record and no
helper contacts the real ThreatFox service. The canonical AsyncRAT
scenario supports later PR 16--22 investigation scenarios:

```text
malicious-domain.test
 -> DNS -> 203.0.113.42
 -> ThreatFox -> AsyncRAT (win.asyncrat)
```

The provider/HTTP scaffolding intentionally mirrors
``tests/support/abuseipdb_fixtures.py`` so provider test modules stay
symmetrical; the duplication is test-only and deliberately accepted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx

from agentic_threat_investigator.app.providers import ProviderResult
from agentic_threat_investigator.domain.entities import Entity
from agentic_threat_investigator.infrastructure.providers.http import ProviderHttpClient
from agentic_threat_investigator.infrastructure.providers.threatfox import (
    ThreatFoxProvider,
)
from tests.support.provider_http import no_op_sleep, static_client, zero_jitter

# pylint: disable=duplicate-code


CANONICAL_ASYNCRAT_MALWARE = "win.asyncrat"
"""Official ThreatFox machine malware label for AsyncRAT (Malpedia family)."""

CANONICAL_ASYNCRAT_PRINTABLE = "AsyncRAT"
"""Official ThreatFox printable malware name for AsyncRAT."""

CANONICAL_ASYNCRAT_DOMAIN = "malicious-domain.test"
"""Synthetic documentation-safe C2 domain of the canonical scenario."""

CANONICAL_ASYNCRAT_IP = "203.0.113.42"
"""Synthetic RFC 5737 documentation address of the canonical scenario."""

CANONICAL_ASYNCRAT_IP_PORT = "203.0.113.42:443"
"""Synthetic ip:port IOC of the canonical scenario."""


def asyncrat_domain_record(**overrides: Any) -> dict[str, Any]:
    """Build the canonical synthetic AsyncRAT domain-IOC record."""
    record: dict[str, Any] = {
        "id": "864201",
        "ioc": CANONICAL_ASYNCRAT_DOMAIN,
        "threat_type": "botnet_cc",
        "threat_type_desc": (
            "Indicator that identifies a botnet command&control server (C&C)"
        ),
        "ioc_type": "domain",
        "ioc_type_desc": ("Domain that is used for botnet Command&control (C&C)"),
        "malware": CANONICAL_ASYNCRAT_MALWARE,
        "malware_printable": CANONICAL_ASYNCRAT_PRINTABLE,
        "malware_alias": None,
        "malware_malpedia": None,
        "confidence_level": 100,
        "first_seen": "2026-08-20 12:00:00 UTC",
        "last_seen": "2026-08-21 12:00:00 UTC",
        "reference": None,
        "reporter": "synthetic_reporter",
        "tags": ["AsyncRAT"],
        "malware_samples": [],
    }
    for key, value in overrides.items():
        if value is REMOVED:
            record.pop(key, None)
        else:
            record[key] = value
    return record


def asyncrat_ip_port_record(**overrides: Any) -> dict[str, Any]:
    """Build the canonical synthetic AsyncRAT ip:port IOC record."""
    record: dict[str, Any] = {
        "id": "864202",
        "ioc": CANONICAL_ASYNCRAT_IP_PORT,
        "threat_type": "botnet_cc",
        "threat_type_desc": (
            "Indicator that identifies a botnet command&control server (C&C)"
        ),
        "ioc_type": "ip:port",
        "ioc_type_desc": (
            "ip:port combination that is used for botnet Command&control (C&C)"
        ),
        "malware": CANONICAL_ASYNCRAT_MALWARE,
        "malware_printable": CANONICAL_ASYNCRAT_PRINTABLE,
        "malware_alias": None,
        "malware_malpedia": None,
        "confidence_level": 100,
        "first_seen": "2026-08-20 12:00:00 UTC",
        "last_seen": None,
        "reference": None,
        "reporter": "synthetic_reporter",
        "tags": ["AsyncRAT"],
        "malware_samples": [],
    }
    for key, value in overrides.items():
        if value is REMOVED:
            record.pop(key, None)
        else:
            record[key] = value
    return record


MATCH_FACT_KEYS = {
    "threatfox_id",
    "ioc",
    "ioc_type",
    "threat_type",
    "threat_type_description",
    "malware",
    "malware_printable",
    "confidence_level",
    "first_seen",
    "last_seen",
    "reference",
    "tags",
}
"""The exact approved normalized match fact keys."""


def threatfox_search_response(*records: dict[str, Any]) -> dict[str, Any]:
    """Build a synthetic successful ThreatFox ``search_ioc`` response."""
    return {"query_status": "ok", "data": list(records)}


def threatfox_no_result_response() -> dict[str, Any]:
    """Build the synthetic valid no-result response."""
    return {"query_status": "no_result"}


FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")
FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
FIXED_KEY = "test-threatfox-auth-key"


class _Removed:  # pylint: disable=too-few-public-methods
    """Sentinel marking a member as absent from the synthetic response."""


REMOVED = _Removed()


def threatfox_provider(
    client: httpx.AsyncClient,
    *,
    clock: Any = None,
    http_kwargs: dict[str, Any] | None = None,
    auth_key: str = FIXED_KEY,
) -> ThreatFoxProvider:
    """Build the provider under test with the deterministic test key.

    ``http_kwargs`` apply to the shared HTTP client (sleep, jitter, policy);
    ``clock`` is the provider's UTC retrieval clock.
    """
    client_kwargs: dict[str, Any] = {
        "sleep": no_op_sleep,
        "jitter_fn": zero_jitter,
    }
    if http_kwargs:
        client_kwargs.update(http_kwargs)
    provider_kwargs: dict[str, Any] = {"clock": clock} if clock is not None else {}
    return ThreatFoxProvider(
        ProviderHttpClient(client=client, **client_kwargs),
        auth_key=auth_key,
        **provider_kwargs,
    )


async def investigate(
    response: httpx.Response,
    *,
    entity: Entity,
    clock: Any = None,
    http_kwargs: dict[str, Any] | None = None,
    auth_key: str = FIXED_KEY,
) -> ProviderResult:
    """Investigate one entity against one static synthetic response.

    ``ThreatFoxProvider.investigate`` returns a ``ProviderResult``; the
    return type is kept loose so tests never need a production import for
    assertions on plain attributes.
    """
    async with static_client(response) as client:
        threatfox = threatfox_provider(
            client, clock=clock, http_kwargs=http_kwargs, auth_key=auth_key
        )
        return await threatfox.investigate(FIXED_UUID, entity)
