# Agentic Threat Investigator — Data Sources

## Table of contents

- [Source policy](#source-policy)
- [Live/local evidence sources](#livelocal-evidence-sources)
  - [Live-source input and URL validation](#live-source-input-and-url-validation)
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

### Live-source input and URL validation

All live sources follow the cross-provider
[URL, path, and redirect safety contract](AGENT_DESIGN.md#provider-url-path-and-redirect-safety).
Production requests require validated HTTPS authorities without credentials,
queries, or fragments. Provider resource paths are built only from strictly
validated canonical entity values; entity values cannot replace the selected
authority. Redirects and response-provided links are never followed.

Invalid entity values produce a non-retryable `UNSUPPORTED_INDICATOR` before
clock evaluation or HTTP. DNS-name validation operates on the original value
before lossy canonicalization: case, surrounding whitespace, one terminal root
dot, and valid IDNA forms are canonicalized, while repeated terminal dots,
empty labels, embedded whitespace, underscores, and invalid or overlong labels
are rejected.

Errors and logs never expose credentials, full URLs containing query values,
headers, redirect targets, or response bodies. Evidence provenance stores only
validated credential-free URLs. Source-specific selection, request, and
provenance rules are documented below.

### IPinfo Lite

Purpose:

- ASN/basic network context.
- Country/continent context.

ATI treats provider-specific fields as source facts rather than generic confidence.

Source identifier:

`urn:ati:source:ipinfo_lite`

### RDAP

- **SourceId URN:** `urn:ati:source:rdap`
- **Protocol:** RDAP (RFC 9082/9083) via IANA bootstrap discovery
- **Entity types:** DOMAIN, IP_ADDRESS, ASN

#### Bootstrap

IANA registration bootstrap files are parsed, selected, and cached by the
narrowly named `rdap_bootstrap.py` module permitted by the implementation
plan. Registries are cached in-process with configurable positive integer TTL
(`rdap_bootstrap_cache_seconds`, default 3600; the cache validates a strictly
positive value at construction), keyed by registry URL with
per-registry locking. Cache failures are not cached (next lookup retries the
fetch).

An empty `services` list is a valid registry that simply matches no entity
value; it produces `NOT_FOUND`, not a schema error.

Selection logic:
- DNS: case-insensitive final-label match; DNS bootstrap keys must be exactly
  one canonical final label.
- IPv4/IPv6: unique longest-prefix match; equal-length overlapping prefixes are rejected.
  Bootstrap keys are parsed strictly: a key with host bits set (for example
  ``198.51.100.42/24``) invalidates the registry as `INVALID_RESPONSE`
  instead of being masked to its network address.
- ASN: narrowest inclusive range match; equal-span ambiguous ranges are rejected.
- The first valid HTTPS URL is chosen in registry source order across all
  services matching the entity value and across each matching service's URL
  list, and is normalized to exactly one trailing slash; URL validity of
  non-matching services is not evaluated. For DNS this means a matching TLD
  is `INVALID_RESPONSE` only when none of its matching services contains a
  valid HTTPS base URL, even when an earlier matching service has none.
  Ambiguity is decided on the normalized selected URL, not raw fallback URL
  tuples.

#### Fact shape (common)

RDAP responses are validated with strict per-object-class models
(`RdapDomainResponse`, `RdapNetworkResponse`, `RdapAutnumResponse`). Every
documented present field is type-checked and length-bounded; wrong types in
nested containers (links, notices, remarks, entities, vCard containers,
nameservers, secureDNS, CIDR0) are schema errors (`INVALID_RESPONSE`).
Canonicalization (IDNA names, IP boundary addresses, CIDR0 networks) happens
during model validation, so fact builders consume only canonical values.

Invalid optional-entry policy:
- event dates are RFC 3339 date-time values: non-RFC spellings (including
  a space date/time separator, offsets without a colon, and naive
  timestamps) are omitted; events with a blank action or a missing, blank,
  unparseable, or non-RFC 3339 date are omitted from facts; an event is
  never emitted without its UTC date; wrong event field types are rejected;
- event actors are trimmed of surrounding whitespace and omitted when blank
  or over the bounded event-text length; wrong actor field types are
  rejected. An actor is recorded verbatim as provider-attributed context
  only; no organization, relationship, or ownership meaning is inferred
  from it and it never triggers entity lookup;
- malformed individual vCard properties (wrong fn value type, blank or
  overlong display names) are omitted; wrong vCard container shapes
  (non-list, wrong arity, missing or non-list property list) are rejected;
- related-entity references without a nonblank (after trimming) handle are
  omitted individually; they never fail the otherwise valid lookup and no
  relationships are inferred from them. Source order is preserved for the
  remaining usable references.

- `object_class_name`: always present; the canonical lowercase form of the
  response `objectClassName` after it is validated against the expected
  object class
- `handle`: the response handle trimmed of surrounding whitespace, when the
  trimmed value is nonblank; a whitespace-only handle is omitted
- `status`: list of RDAP status strings when present, normalized to the
  stable canonical form: entries are trimmed and lowercased, blank entries
  are omitted, and duplicates are removed while preserving first-seen source
  order; entries are length-bounded and wrong entry types are rejected
  (`INVALID_RESPONSE`)
- `events`: list of ``{action, date, actor}`` dicts; every emitted event has
  both a nonblank bounded action and a valid RFC 3339 timezone-aware
  timestamp normalized to UTC (entries missing a valid date are omitted as
  described above; ``actor`` present only for a valid, nonblank,
  length-bounded ``eventActor``)
- `entities`: compact entity references with a nonblank trimmed ``handle``,
  ``roles``, and optional ``display_name`` (extracted from vcard ``fn``);
  references with an absent or blank handle are omitted as described above

#### Fact shape (domain)

- `ldh_name`: the canonical punycode (ASCII) form of the response `ldhName`
  (when present)
- `unicode_name`: the response `unicodeName` trimmed of surrounding
  whitespace, preserving the provider Unicode form (when present); it is not
  further canonicalized. A supplied `unicodeName` must be a syntactically
  valid IDNA DNS name (malformed Unicode syntax is `INVALID_RESPONSE`)
- `secure_dns`: DNSSEC metadata (when present)
- `nameservers`: list of canonical DNS names in upstream source order. Each
  nameserver entry uses its canonical `ldhName` when present, otherwise the
  canonical IDNA form derived from `unicodeName`. Both RDAP names are
  optional: an entry supplying neither name contributes no fact entry and
  never fails the lookup. When both names are supplied they must
  canonicalize to the same DNS identity; contradictory forms are
  `INVALID_RESPONSE`, as are wrong member types and syntactically invalid
  supplied names.

Domain identity: every supplied identity member (`ldhName` and
`unicodeName`) must canonicalize to the queried canonical domain. A
`unicodeName`-only response is accepted only when its canonical IDNA form
matches the query; when both names are supplied they must canonicalize to
the same DNS identity. A malformed or contradictory identity member is
`INVALID_RESPONSE` and no evidence is emitted.

#### Fact shape (ip network)

- `start_address`, `end_address`, `ip_version`: always present
- `name`, `type`, `country`: when present
- `parent_handle`: when present
- `cidr0_cidrs`: list of normalized ``{"prefix": str, "length": int}`` when present.
  Every CIDR0 entry must declare exactly one family discriminator with a legal
  prefix length, match the response address family, and be fully contained
  within the response's start/end address range; unrelated or inconsistent
  CIDR0 entries are `INVALID_RESPONSE`. Prefixes are parsed strictly: a
  prefix with host bits set asserts a different network than it renders and
  is `INVALID_RESPONSE`, never silently masked to the network address.

#### Fact shape (autnum)

- `start_autnum`, `end_autnum`: always present. Authoritative range endpoints
  are validated against the same legal 32-bit ASN domain (`1..4294967295`)
  as ATI canonical ASN values and IANA bootstrap ASN ranges; zero endpoints,
  endpoints above the maximum, or a range that does not contain the queried
  ASN are `INVALID_RESPONSE`
- `name`, `type`, `country`: when present

#### Provenance

- `source_url`: the authoritative RDAP URL queried
- `source_record_id`: the response handle when nonblank after trimming,
  falling back to the normalized identity
  (`start-end` for IP, `AS<start>-<end>` for ASN, or canonical domain)
- `observed_at`: the newest valid RFC 3339 ``last changed`` event timestamp
  (UTC), or None; malformed optional event entries are omitted (see the
  invalid optional-entry policy above)
- `raw_payload=None` (conservative data-minimization for RDAP)

### Google Public DNS

Purpose:

- Current DNS resolution.
- Infrastructure discovery.
- A/AAAA/CNAME/MX/NS/TXT/SOA/PTR as applicable.

DNS is a principal source of domain-to-IP pivots.

It is not a threat-intelligence or passive-DNS source.

Source identifier:

`urn:ati:source:google_public_dns`

Supported entity types:

- ``DOMAIN``: queries A, AAAA, CNAME, MX, NS, TXT, SOA in order. NXDOMAIN
  on the first query short-circuits remaining types. An NXDOMAIN response
  that carries an Answer section is contradictory upstream data and is
  rejected as ``INVALID_RESPONSE``. NOERROR with no answers
  for a record type is a valid empty sub-result. Queried names and all
  provider-supplied DNS names are strictly validated (no embedded
  whitespace, underscores, empty labels, or overlong labels; at most one
  terminal DNS root dot is removed, so names such as ``example.com..``
  are rejected; Unicode input is canonicalized to IDNA punycode). Invalid
  names are `UNSUPPORTED_INDICATOR` on input and `INVALID_RESPONSE` in
  responses.
- ``IP_ADDRESS``: queries PTR via the reverse-pointer name (``in-addr.arpa``
  or ``ip6.arpa``).

Normalized evidence type:

- ``urn:ati:evidence:dns``

Normalized facts shape:

```text
query_name: canonical domain or reverse-pointer name
query_type: uppercase RR type name
status: integer DNS status (0 = NOERROR, 3 = NXDOMAIN)
flags: {tc, rd, ra, ad, cd} using present boolean values
answers: ordered list of normalized records
```

Every normalized answer contains ``name``, ``record_type``, and ``ttl``.
Type-specific fields:

- A/AAAA: ``value`` as canonical compressed IP.
- CNAME/NS/PTR: ``value`` as canonical lowercase IDNA domain without trailing dot.
- MX: integer ``preference`` and canonical domain ``exchange``.
- TXT: exact decoded provider string as ``value``.
- SOA: structured ``mname``, ``rname``, ``serial``, ``refresh``, ``retry``,
  ``expire``, and ``minimum``.

Providers retrieve and normalize. They do not infer relationships or
instantiate discovered entities. Relationship extraction and entity
discovery belong to PR 14.

DNS provenance is `source_url=https://dns.google/resolve`, `observed_at=None`,
and a timezone-aware UTC `retrieved_at`. DNS evidence uses `raw_payload=None`
under the conservative data-minimization decision for this PR.

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
