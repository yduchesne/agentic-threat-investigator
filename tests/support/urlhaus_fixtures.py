# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI-authored synthetic URLhaus response fixtures.

Every payload in this module is synthetic documentation-safe test data
authored for ATI (RFC 5737 addresses, RFC 2606 ``.test`` domains, and
synthetic identifiers). No payload is a copied URLhaus record, no helper
contacts the real URLhaus service, and no fixture ever references a real
malicious URL or a real payload hash. The canonical scenario supports the
later PR 18 deterministic extraction:

```text
malicious-domain.test
 -> URL -> http://malicious-domain.test/download/payload.bin
 -> URLhaus -> url_status/threat/tags + synthetic payload metadata
```

The provider/HTTP scaffolding intentionally mirrors
``tests/support/threatfox_fixtures.py`` so provider test modules stay
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
from agentic_threat_investigator.infrastructure.providers.urlhaus import UrlhausProvider
from tests.support.provider_http import no_op_sleep, static_client, zero_jitter

# pylint: disable=duplicate-code


CANONICAL_URLHAUS_DOMAIN = "malicious-domain.test"
"""Synthetic documentation-safe host of the canonical URLhaus scenario."""

CANONICAL_URLHAUS_URL = "http://malicious-domain.test/download/payload.bin"
"""Synthetic documentation-safe malware-distribution URL of the scenario."""

CANONICAL_URLHAUS_IPV4 = "203.0.113.42"
"""Synthetic RFC 5737 documentation address of the canonical scenario."""

SYNTHETIC_SHA256 = "a" * 64
"""Synthetic 64-hex SHA256-shaped value; not any real payload digest."""

SYNTHETIC_MD5 = "b" * 32
"""Synthetic 32-hex MD5-shaped value; not any real payload digest."""


def urlhaus_payload(**overrides: Any) -> dict[str, Any]:
    """Build one synthetic URLhaus payload metadata entry."""
    payload: dict[str, Any] = {
        "firstseen": "2026-08-20",
        "filename": "payload.bin",
        "file_type": "elf",
        "response_size": "12345",
        "response_md5": SYNTHETIC_MD5,
        "response_sha256": SYNTHETIC_SHA256,
        "urlhaus_download": "https://urlhaus-api.abuse.ch/v1/download/synthetic/",
        "signature": None,
        "virustotal": None,
        "imphash": "c" * 32,
        "ssdeep": "synthetic-ssdeep",
        "tlsh": "synthetic-tlsh",
        "magika": "elf",
    }
    for key, value in overrides.items():
        if value is REMOVED:
            payload.pop(key, None)
        else:
            payload[key] = value
    return payload


def urlhaus_url_record(**overrides: Any) -> dict[str, Any]:
    """Build the canonical synthetic URLhaus URL-lookup record."""
    record: dict[str, Any] = {
        "query_status": "ok",
        "id": "556677",
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/556677/",
        "url": CANONICAL_URLHAUS_URL,
        "url_status": "online",
        "host": CANONICAL_URLHAUS_DOMAIN,
        "date_added": "2026-08-20 12:00:00 UTC",
        "last_online": None,
        "threat": "malware_download",
        "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"},
        "reporter": "synthetic_reporter",
        "larted": "false",
        "takedown_time_seconds": None,
        "tags": ["elf"],
        "payloads": [urlhaus_payload()],
    }
    for key, value in overrides.items():
        if value is REMOVED:
            record.pop(key, None)
        else:
            record[key] = value
    return record


def urlhaus_host_url_record(**overrides: Any) -> dict[str, Any]:
    """Build one synthetic URL record inside a host-lookup response.

    Host-lookup URL entries carry no ``host`` or ``payloads`` members.
    """
    record: dict[str, Any] = {
        "id": "556677",
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/556677/",
        "url": CANONICAL_URLHAUS_URL,
        "url_status": "online",
        "date_added": "2026-08-20 12:00:00 UTC",
        "threat": "malware_download",
        "reporter": "synthetic_reporter",
        "larted": "false",
        "takedown_time_seconds": None,
        "tags": ["elf"],
    }
    for key, value in overrides.items():
        if value is REMOVED:
            record.pop(key, None)
        else:
            record[key] = value
    return record


def urlhaus_url_response(**overrides: Any) -> dict[str, Any]:
    """Build a synthetic successful URLhaus exact-URL lookup response."""
    return urlhaus_url_record(**overrides)


def urlhaus_host_response(
    *records: dict[str, Any],
    url_count: str = "1",
    host: str = CANONICAL_URLHAUS_DOMAIN,
    firstseen: str = "2026-08-19 08:00:00 UTC",
) -> dict[str, Any]:
    """Build a synthetic successful URLhaus host-lookup response."""
    return {
        "query_status": "ok",
        "urlhaus_reference": "https://urlhaus.abuse.ch/host/malicious-domain.test/",
        "host": host,
        "firstseen": firstseen,
        "url_count": url_count,
        "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"},
        "urls": list(records),
    }


def urlhaus_no_results_response() -> dict[str, Any]:
    """Build the synthetic valid no-result response (plural documented form)."""
    return {"query_status": "no_results"}


MATCH_FACT_KEYS = {
    "urlhaus_id",
    "url",
    "url_status",
    "date_added",
    "last_online",
    "threat",
    "host",
    "tags",
    "payloads",
}
"""The exact approved normalized match fact keys."""

PAYLOAD_FACT_KEYS = {
    "first_seen",
    "filename",
    "file_type",
    "response_size",
    "response_md5",
    "response_sha256",
    "signature",
}
"""The exact approved normalized payload fact keys (fact-only data)."""


FIXED_UUID = UUID("11111111-2222-3333-4444-555555555555")
FIXED_TS = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
FIXED_KEY = "test-urlhaus-auth-key"


class _Removed:  # pylint: disable=too-few-public-methods
    """Sentinel marking a member as absent from the synthetic response."""


REMOVED = _Removed()


def urlhaus_provider(
    client: httpx.AsyncClient,
    *,
    clock: Any = None,
    http_kwargs: dict[str, Any] | None = None,
    auth_key: str = FIXED_KEY,
) -> UrlhausProvider:
    """Build the provider under test with the deterministic test key.

    ``http_kwargs`` apply to the shared HTTP client (sleep, jitter,
    policy); ``clock`` is the provider's UTC retrieval clock.
    """
    client_kwargs: dict[str, Any] = {
        "sleep": no_op_sleep,
        "jitter_fn": zero_jitter,
    }
    if http_kwargs:
        client_kwargs.update(http_kwargs)
    provider_kwargs: dict[str, Any] = {"clock": clock} if clock is not None else {}
    return UrlhausProvider(
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

    ``UrlhausProvider.investigate`` returns a ``ProviderResult``; the
    return type is kept loose so tests never need a production import for
    assertions on plain attributes.
    """
    async with static_client(response) as client:
        urlhaus = urlhaus_provider(
            client, clock=clock, http_kwargs=http_kwargs, auth_key=auth_key
        )
        return await urlhaus.investigate(FIXED_UUID, entity)
