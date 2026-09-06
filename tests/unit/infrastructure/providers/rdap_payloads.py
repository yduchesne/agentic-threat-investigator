# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Shared synthetic RDAP/IANA payload builders for provider contract tests."""

from __future__ import annotations

from typing import Any

import httpx


def _bootstrap_registry(services: list[Any]) -> dict[str, Any]:
    return {
        "version": "1.0",
        "publication": "2026-01-01T00:00:00Z",
        "description": "Test Registry",
        "services": services,
    }


def _rdap_domain(name: str, handle: str = "DOM-1") -> dict[str, Any]:
    return {
        "objectClassName": "domain",
        "handle": handle,
        "ldhName": name,
        "status": ["active"],
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-01-10T15:30:00Z"},
        ],
        "entities": [
            {
                "handle": "REG-1",
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Admin"]]],
            }
        ],
        "nameservers": [{"ldhName": "ns1.example.com."}],
    }


def _rdap_network(start: str, end: str, handle: str = "NET-1") -> dict[str, Any]:
    is_v4 = "." in start
    prefix_key = "v4prefix" if is_v4 else "v6prefix"
    return {
        "objectClassName": "ip network",
        "handle": handle,
        "startAddress": start,
        "endAddress": end,
        "ipVersion": "v4" if is_v4 else "v6",
        "name": "TEST-NET",
        "cidr0_cidrs": [{prefix_key: start, "length": 24 if is_v4 else 48}],
    }


def _rdap_autnum(start: int, end: int, handle: str = "AS100") -> dict[str, Any]:
    return {
        "objectClassName": "autnum",
        "handle": handle,
        "startAutnum": start,
        "endAutnum": end,
        "name": "TEST-ASN",
    }


def iana_registry_response(services: list[Any]) -> httpx.Response:
    """Build a synthetic 200 JSON bootstrap registry HTTP response."""
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        json=_bootstrap_registry(services),
    )
