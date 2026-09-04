# Agentic Threat Investigator — Data Sources

## Table of contents

- [Source policy](#source-policy)
- [Live/local evidence sources](#livelocal-evidence-sources)
  - [IPinfo Lite](#ipinfo-lite)
  - [RDAP](#rdap)
  - [Google Public DNS](#google-public-dns)
  - [DB-IP City Lite](#db-ip-city-lite)
  - [AbuseIPDB](#abuseipdb)
  - [ThreatFox](#threatfox)
  - [URLhaus](#urlhaus)
- [Structured batch sources](#structured-batch-sources)
  - [MITRE ATT&CK](#mitre-attck)
  - [CISA Known Exploited Vulnerabilities](#cisa-known-exploited-vulnerabilities)
- [Narrative RAG corpus](#narrative-rag-corpus)
- [Deferred sources](#deferred-sources)
- [Batch ingestion model](#batch-ingestion-model)
- [Live evidence model](#live-evidence-model)
- [Artifact storage](#artifact-storage)
- [Data bundling](#data-bundling)

## Source policy

v0.1 uses only free, relevant data sources suitable for the open-source product's intended use. Access terms, attribution, and redistribution rights must be verified independently before release.

Preferred acquisition order:

1. Dataset download.
2. API/feed.
3. Targeted scraping only where needed.

"Free to access" does not imply permission to bundle or redistribute data.

## Live/local evidence sources

### IPinfo Lite

Purpose:

- ASN/basic network context.
- Country/continent context.

ATI treats provider-specific fields as source facts rather than generic confidence.

Source identifier:

`urn:ati:source:ipinfo_lite`

### RDAP

Purpose:

- IP registration.
- Network ranges.
- ASN registration.
- Domain registration where supported.
- Registrar/registry entities and dates.

ATI uses IANA bootstrap data and authoritative RDAP services rather than hard-coding a single RIR.

Source identifier:

`urn:ati:source:rdap`

### Google Public DNS

Purpose:

- Current DNS resolution.
- Infrastructure discovery.
- A/AAAA/CNAME/MX/NS/TXT/SOA/PTR as applicable.

DNS is a principal source of domain-to-IP pivots.

It is not a threat-intelligence or passive-DNS source.

Source identifier:

`urn:ati:source:google_public_dns`

### DB-IP City Lite

Purpose:

- Approximate city/region/country.
- Approximate latitude/longitude.

ATI uses the downloadable local MMDB database rather than relying on a low-quota free API.

The UI must label these results as approximate IP geolocation and must not imply physical attacker/device location.

Source identifier:

`urn:ati:source:dbip_city_lite`

### AbuseIPDB

Purpose:

- IP reputation.
- Abuse reports and provider-specific scoring.

No result or low score is not automatically evidence that an IP is benign.

Source identifier:

`urn:ati:source:abuseipdb`

### ThreatFox

Purpose:

- IOC-to-malware associations.
- Recent threat-intelligence context.

ATI persists observations locally because provider retention may be bounded.

Source identifier:

`urn:ati:source:threatfox`

### URLhaus

Purpose:

- Malicious URL intelligence.
- Payload/malware information.
- Related infrastructure.

Source identifier:

`urn:ati:source:urlhaus`

## Structured batch sources

### MITRE ATT&CK

Purpose:

- Techniques.
- Software/malware.
- Groups where present in source data, without v0.1 actor-attribution functionality.
- Relationships.
- Structured RAG material.

Prefer STIX 2.1 current bundles.

Source identifier:

`urn:ati:source:mitre_attack`

The v0.1 source consumes an already-acquired STIX 2.1 bundle. It emits these
`SourceRecord.record_type` values:

- `attack_technique` for STIX `attack-pattern` objects;
- `attack_software` for STIX `malware` and `tool` objects;
- `attack_group` for STIX `intrusion-set` objects;
- `attack_relationship` for STIX `relationship` objects.

The durable source-record identity is the STIX object ID. Timestamps and the
original STIX object are retained as provenance; ATT&CK tactics and platforms
are normalized into technique/software payload attributes. Revoked and
deprecated records are retained rather than deleted.

STIX relationships are normalized to `urn:ati:relationship:attack:uses_technique`
when a `uses` relationship targets an `attack-pattern`. Other relationship
forms use `urn:ati:relationship:threat:associated_with`, while preserving the
original STIX relationship type and endpoint IDs in the canonical payload.
Missing endpoint objects do not invalidate a relationship record.

Bundle metadata objects such as `identity`, `marking-definition`,
`x-mitre-tactic`, `x-mitre-matrix`, and `course-of-action` are skipped. Unknown
STIX types are also ignored. Source progress uses the opaque `index:<n>`
checkpoint format and is committed atomically with each bounded batch.

### CISA Known Exploited Vulnerabilities

Purpose:

- Structured exploited-vulnerability knowledge.

Use full periodic download/upsert.

Source identifier:

`urn:ati:source:cisa_kev`

## Narrative RAG corpus

Initial corpus:

- ATT&CK-derived documents.
- Selected CISA advisories/threat reports.
- Selected freely usable public threat-research documents added deliberately.

ATI does not use arbitrary live web search as its v0.1 RAG corpus.

## Deferred sources

MalwareBazaar is deferred beyond the initial v0.1 source set.

Paid CTI feeds, paid passive DNS, paid geolocation, paid VPN/proxy detection, AWS telemetry, SIEM, and EDR integrations are out of v0.1.

## Batch ingestion model

Structured batch sources normalize to `SourceRecord`.

```python
class SourceRecord(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: UUID | None = None
    source_id: str
    source_record_id: str
    record_type: str
    normalization_version: int
    observed_at: datetime | None = None
    published_at: datetime | None = None
    retrieved_at: datetime
    canonical_payload: dict[str, Any]
    raw_payload: dict[str, Any] | None = None
    content_hash: str
    metadata: dict[str, Any] = Field(default_factory=dict)
```

External identity is `(source_id, source_record_id)`.

Use a durable provider identifier where available. Otherwise derive a deterministic identifier from stable normalized fields. Retrieval time must not participate in source-record identity.

`content_hash` is based on deterministic semantic canonical payload, excluding retrieval and local transport metadata. It is derived and verified at construction (supplied values are normalized to lowercase). Nested payload and metadata values are recursively frozen so the digest cannot become stale. Non-JSON payload values and naive timestamp strings are rejected.

Results classify records as:

- INSERTED
- UPDATED
- UNCHANGED

Only changed records require downstream regeneration/re-embedding.

## Live evidence model

Live provider calls produce normalized `Evidence` directly. Live providers and batch normalizers share lower-level canonicalization utilities but the live path is not artificially forced through `SourceRecord`.

## Artifact storage

`BatchSource` consumes an already-present artifact through an application-layer `ObjectStore`; it never downloads the artifact. Artifact locations are canonical, credential-free URIs. URI-scheme resolution occurs during composition, outside the source. v0.1 implements `FileSystemObjectStore` and places local datasets beneath:

`${ATI_DATA_DIR}/datasets/<source>/`

Checkpoints are opaque source-owned values persisted by `(source_id, artifact_uri, normalization_version)`. Each record batch and its post-batch checkpoint commit atomically. A completed artifact is a deterministic no-op on repeat invocation unless explicitly restarted. Restart clears only that artifact/version checkpoint.

Ingestion results retain authoritative IDs, versions, input ordinals, and INSERTED/UPDATED/UNCHANGED outcomes. Only INSERTED and UPDATED records are exposed as changed work for downstream processing. The normalized PostgreSQL data remains authoritative application state.

## Data bundling

Third-party datasets are generally not committed or bundled in the ATI source repository. Setup/ingestion tooling retrieves them from authoritative sources.

Synthetic test fixtures should be ATI-authored rather than wholesale copies of provider responses where redistribution terms are uncertain.
