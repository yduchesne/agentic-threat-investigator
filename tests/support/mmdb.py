# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic ATI-authored synthetic DB-IP City Lite MMDB fixture.

The generated database is entirely synthetic: no real DB-IP data, no DB-IP
download, and no internet access are involved. Addresses come exclusively
from documentation ranges (RFC 5737/3849), names and coordinates are clearly
synthetic, and country codes are harmless valid ISO 3166-1 alpha-2 codes.
The binary is generated at test time by the MIT-licensed ``mmdb-writer`` dev
dependency; the production DB-IP dataset is never bundled.
"""

from __future__ import annotations

import os
import tempfile
import types

import mmdb_writer
from netaddr import IPNetwork, IPSet  # type: ignore[import-untyped]

# Synthetic fixture addresses (documentation ranges only).
CITY_IPV4_NETWORK = "192.0.2.0/24"
REGION_IPV4_NETWORK = "198.51.100.0/24"
COUNTRY_IPV4_NETWORK = "203.0.113.0/24"
CITY_IPV6_NETWORK = "2001:db8::/32"

CITY_IPV4 = "192.0.2.10"
REGION_IPV4 = "198.51.100.20"
COUNTRY_IPV4 = "203.0.113.30"
CITY_IPV6 = "2001:db8::1"
MISS_IPV4 = "192.0.3.1"
MISS_IPV6 = "2001:db9::1"


def build_synthetic_city_lite_mmdb() -> bytes:
    """Build a tiny deterministic dual-stack synthetic City Lite MMDB.

    Coverage: an IPv4 city hit, a region-precision hit, a country-precision
    hit, an IPv6 city hit, and unlisted addresses that deterministically
    miss. The metadata build epoch is frozen so the artifact bytes are
    reproducible; record content is fully deterministic either way.
    """
    writer = _new_writer("DBIP-City-Lite", "ATI synthetic DB-IP City Lite fixture")
    writer.insert_network(
        IPSet([IPNetwork(CITY_IPV4_NETWORK)]),
        {
            "country": {"iso_code": "US"},
            "city": {"names": {"en": "Example City"}},
            "location": {"latitude": -33.5, "longitude": 150.25},
        },
    )
    writer.insert_network(
        IPSet([IPNetwork(REGION_IPV4_NETWORK)]),
        {
            "country": {"iso_code": "AU"},
            "subdivisions": [{"iso_code": "NSW", "names": {"en": "New South Wales"}}],
        },
    )
    writer.insert_network(
        IPSet([IPNetwork(COUNTRY_IPV4_NETWORK)]),
        {"country": {"iso_code": "AU"}},
    )
    writer.insert_network(
        IPSet([IPNetwork(CITY_IPV6_NETWORK)]),
        {
            "country": {"iso_code": "US"},
            "city": {"names": {"en": "Example V6 City"}},
            "location": {"latitude": 10.0, "longitude": -20.0},
        },
    )
    return _write_bytes(writer)


def build_scalar_record_city_lite_mmdb() -> bytes:
    """Build a synthetic MMDB whose single matched record is a bare string."""
    writer = _new_writer("DBIP-City-Lite", "ATI synthetic scalar-record fixture")
    writer.insert_network(IPSet([IPNetwork(CITY_IPV4_NETWORK)]), "scalar record")
    return _write_bytes(writer)


def build_wrong_product_city_lite_mmdb() -> bytes:
    """Build a valid synthetic MMDB declaring a different product type."""
    writer = _new_writer("GeoLite2-City", "ATI synthetic wrong-product fixture")
    writer.insert_network(
        IPSet([IPNetwork(CITY_IPV4_NETWORK)]),
        {"city": {"names": {"en": "Wrong Product City"}}},
    )
    return _write_bytes(writer)


def _new_writer(database_type: str, description: str) -> mmdb_writer.MMDBWriter:
    """Create one synthetic dual-stack MMDB writer with fixed metadata."""
    return mmdb_writer.MMDBWriter(
        ip_version=6,
        database_type=database_type,
        languages=["en"],
        description={"en": description},
        ipv4_compatible=True,
    )


def _write_bytes(writer: mmdb_writer.MMDBWriter) -> bytes:
    """Serialize one MMDB writer output to bytes through a temp file.

    The metadata build epoch is frozen around serialization so the fixture
    bytes are reproducible across runs.
    """
    # getattr/setattr stay dynamic on purpose: mmdb_writer does not statically
    # export ``time``, and the fixture monkeypatches the writer's frozen
    # epoch. Direct attribute access would fail strict mypy.
    original_time = getattr(mmdb_writer, "time")  # noqa: B009
    setattr(mmdb_writer, "time", types.SimpleNamespace(time=lambda: 0.0))  # noqa: B010
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".mmdb", delete=False) as handle:
            temporary = handle.name
        writer.to_db_file(temporary)
        with open(temporary, "rb") as handle:
            return handle.read()
    finally:
        setattr(mmdb_writer, "time", original_time)  # noqa: B010
        if temporary is not None:
            os.unlink(temporary)
