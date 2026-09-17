# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Stable ATI identifier vocabulary.

Identifier URNs published by this module are durable contract values. They are
persisted in the database, exchanged through the API, and shared with batch
sources; member names are implementation conveniences only.
"""

from enum import Enum


class SourceId(str, Enum):
    """Stable ATI source identifier URNs for the v0.1 source set.

    These values identify the external intelligence source/provider. They are
    durable and must never be reinterpreted or renamed.
    """

    IPINFO_LITE = "urn:ati:source:ipinfo_lite"
    RDAP = "urn:ati:source:rdap"
    GOOGLE_PUBLIC_DNS = "urn:ati:source:google_public_dns"
    DBIP_CITY_LITE = "urn:ati:source:dbip_city_lite"
    ABUSEIPDB = "urn:ati:source:abuseipdb"
    THREATFOX = "urn:ati:source:threatfox"
    URLHAUS = "urn:ati:source:urlhaus"
    MITRE_ATTACK = "urn:ati:source:mitre_attack"
    CISA_KEV = "urn:ati:source:cisa_kev"


class SemanticFormatId(str, Enum):
    """Stable ATI semantic-format identifier URNs.

    A semantic format identifies the meaning/schema of source objects after
    transport and serialization decoding. Converter selection is based on
    this value, never on provider, protocol, serialization, or datasource
    instance. Provider-specific/proprietary semantic models receive their
    own durable ATI URNs; STIX 2.1 is one shared open semantic model.
    """

    STIX_21 = "urn:ati:datasource:semanticformat:stix21"
    THREATFOX = "urn:ati:datasource:semanticformat:threatfox"
