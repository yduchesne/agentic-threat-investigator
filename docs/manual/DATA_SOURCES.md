# Data Sources

This page lists the currently supported data sources.

## Live Data Sources

Live sources are invoqued per `Entity`, in the course of pivoting when conducting investigations. Within ATI, such sources are integrated through the `EvidenceProvider` interface, which abtracts the systems being used. Currently, all of them are integrated by way of an API each provides.

The following table lists the currently supported sources:

| Source | ATI evidence type(s) | What ATI obtains / description | Relevant links |
|---|---|---|---|
| **Google Public DNS** | `DNS` | Live DNS resolution. ATI queries DNS records for domains/IPs and converts responses into Evidence. Deterministic extraction can discover entities and relationships such as `DOMAIN → RESOLVES_TO → IP_ADDRESS`, CNAME, MX and NS relationships. | [Google Public DNS](https://developers.google.com/speed/public-dns?utm_source=chatgpt.com) · [DNS-over-HTTPS API](https://developers.google.com/speed/public-dns/docs/doh/json?utm_source=chatgpt.com) |
| **RDAP** | `REGISTRATION`, `NETWORK` | Registration and allocation information for domains, IP addresses and ASNs. Used for ownership/registration/network context rather than threat reputation. ATI's RDAP provider supports domain, IP and ASN entities. | [ICANN RDAP overview](https://www.icann.org/rdap?utm_source=chatgpt.com) · [RDAP.org bootstrap service](https://rdap.org/?utm_source=chatgpt.com) |
| **ThreatFox** | `THREAT_INTELLIGENCE` | IOC intelligence from abuse.ch. ATI can query indicators such as domains and IP addresses and normalize ThreatFox's source-specific semantic records into ATI Evidence. It can also discover threat-related entities such as malware families and evidence-backed associations. | [ThreatFox](https://threatfox.abuse.ch/?utm_source=chatgpt.com) · [ThreatFox API](https://threatfox.abuse.ch/api/?utm_source=chatgpt.com) |
| **URLhaus** | `THREAT_INTELLIGENCE` | Malware-URL intelligence from abuse.ch. Provides information about URLs associated with malware distribution and their associated infrastructure. ATI supports URL, domain and IP investigation paths through this provider. | [URLhaus](https://urlhaus.abuse.ch/?utm_source=chatgpt.com) · [URLhaus API](https://urlhaus.abuse.ch/api/?utm_source=chatgpt.com) |
| **AbuseIPDB** | `REPUTATION` | IP reputation/abuse information. ATI uses it to obtain source-backed reputation evidence about an IP rather than treating infrastructure characteristics themselves as evidence of maliciousness. | [AbuseIPDB](https://www.abuseipdb.com/?utm_source=chatgpt.com) · [AbuseIPDB API documentation](https://docs.abuseipdb.com/?utm_source=chatgpt.com) |
| **IPinfo** | `NETWORK` | Network/infrastructure enrichment for IP addresses, particularly ASN/network context. ATI deliberately treats this as contextual network evidence rather than asserting that an ASN "owns" or is maliciously associated with an IP. | [IPinfo](https://ipinfo.io/?utm_source=chatgpt.com) · [IPinfo developer documentation](https://ipinfo.io/developers?utm_source=chatgpt.com) |
| **DB-IP** | `GEOLOCATION` | IP geolocation enrichment. ATI obtains geographic context for IP infrastructure and feeds it into its deterministic GEOINT resolution path. This is contextual evidence; location alone is explicitly not evidence of maliciousness. Unlike the sources above, ATI's DB-IP integration is **local dataset/file backed rather than a live remote API call** during investigation. | [DB-IP](https://db-ip.com/?utm_source=chatgpt.com) · [DB-IP databases](https://db-ip.com/db/?utm_source=chatgpt.com) |

### Batch Data Sources

At the name implies, batch data sources perform bulk import and are integrated out-of-band with regards to investigation.

| Batch source | ATI data produced / type | Description | Relevant links |
|---|---|---|---|
| **MITRE ATT&CK** | **Research documents / RAG corpus** — not canonical `Evidence` | ATI ingests the ATT&CK STIX 2.1 corpus through `MitreAttackBatchSource`. The records are normalized and converted by `MitreAttackDocumentBuilder` into ATI research `Document`s, chunked/embedded and stored for pgvector retrieval. During an investigation, the Threat Research Agent can retrieve relevant ATT&CK material through `ResearchRetriever`. | [MITRE ATT&CK](https://attack.mitre.org/?utm_source=chatgpt.com) · [ATT&CK data and tools](https://attack.mitre.org/resources/attack-data-and-tools/?utm_source=chatgpt.com) · [MITRE CTI STIX repository](https://github.com/mitre-attack/attack-stix-data?utm_source=chatgpt.com) |
| **DB-IP** | `GEOLOCATION` evidence / geospatial reference data | ATI uses the downloaded DB-IP dataset locally rather than making a remote lookup for every investigation. IP records provide geographic information that feeds ATI's geolocation/GEOINT processing. Unlike ATT&CK, DB-IP ultimately participates in the evidence/geolocation path rather than the RAG research corpus. | [DB-IP](https://db-ip.com/?utm_source=chatgpt.com) · [DB-IP databases](https://db-ip.com/db/?utm_source=chatgpt.com) · [DB-IP Lite databases](https://db-ip.com/db/lite.php?utm_source=chatgpt.com) |