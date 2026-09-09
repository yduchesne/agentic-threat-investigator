# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Canonical investigation extraction scenario tests.

The canonical scenario is the reusable PR 18B fixture for PR 18C persistence
and PR 19+ investigation scenarios:

```text
malicious-domain.test
  RESOLVES_TO
203.0.113.42

203.0.113.42
  ASSOCIATED_WITH
win.asyncrat (AsyncRAT)
```
"""

from agentic_threat_investigator.app.extraction import extract
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.relationships import RelationshipType
from tests.support.extraction_fixtures import (
    CANONICAL_ASYNCRAT_DOMAIN,
    CANONICAL_ASYNCRAT_IP,
    CANONICAL_ASYNCRAT_MALWARE,
    CANONICAL_ASYNCRAT_PRINTABLE,
    CANONICAL_DNS_EVIDENCE_ID,
    CANONICAL_THREATFOX_EVIDENCE_ID,
    canonical_dns_evidence,
    canonical_threatfox_evidence,
)


def test_canonical_dns_evidence_resolves_the_scenario_domain() -> None:
    """DNS extraction of the canonical evidence yields the RESOLVES_TO edge."""
    result = extract(canonical_dns_evidence())

    assert len(result.entities) == 1
    assert result.entities[0].type is EntityType.IP_ADDRESS
    assert result.entities[0].value == CANONICAL_ASYNCRAT_IP
    assert len(result.relationships) == 1
    edge = result.relationships[0]
    assert edge.source.type is EntityType.DOMAIN
    assert edge.source.value == CANONICAL_ASYNCRAT_DOMAIN
    assert edge.type is RelationshipType.RESOLVES_TO
    assert edge.target.value == CANONICAL_ASYNCRAT_IP
    assert edge.evidence_id == CANONICAL_DNS_EVIDENCE_ID


def test_canonical_threatfox_evidence_associates_the_scenario_ip_with_asyncrat() -> (
    None
):
    """ThreatFox extraction of the canonical evidence yields win.asyncrat."""
    result = extract(canonical_threatfox_evidence())

    assert len(result.entities) == 1
    malware = result.entities[0]
    assert malware.type is EntityType.MALWARE
    assert malware.value == CANONICAL_ASYNCRAT_MALWARE
    assert malware.display_name == CANONICAL_ASYNCRAT_PRINTABLE
    assert len(result.relationships) == 1
    edge = result.relationships[0]
    assert edge.source.type is EntityType.IP_ADDRESS
    assert edge.source.value == CANONICAL_ASYNCRAT_IP
    assert edge.type is RelationshipType.ASSOCIATED_WITH
    assert edge.target.type is EntityType.MALWARE
    assert edge.target.value == CANONICAL_ASYNCRAT_MALWARE
    assert edge.evidence_id == CANONICAL_THREATFOX_EVIDENCE_ID
