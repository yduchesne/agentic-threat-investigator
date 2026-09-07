# Agentic Threat Investigator — Data Sources

## Table of contents

- [Source policy](#source-policy)
- [Live/local evidence sources](#livelocal-evidence-sources)
  - [Live-source input and URL validation](#live-source-input-and-url-validation)
  - [IPinfo Lite](#ipinfo-lite)
  - [RDAP](#rdap)
  - [Google Public DNS](#google-public-dns)
    - [Authoritative DNS semantics](#authoritative-dns-semantics)
    - [Entity names and protocol names](#entity-names-and-protocol-names)
    - [DNS record validation matrix](#dns-record-validation-matrix)
    - [DNS RR-set consistency](#dns-rr-set-consistency)
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

The stable ATI member `SourceId.IPINFO_LITE` publishes this identifier.

#### Applicability

Supported entity types:

- `IP_ADDRESS`

Unsupported entity types (each is a non-retryable
`UNSUPPORTED_INDICATOR` produced before clock evaluation or any HTTP I/O):

- `DOMAIN`
- `URL`
- `NETWORK_PREFIX`
- `ASN`
- `ORGANIZATION`
- `MALWARE`
- `ATTACK_TECHNIQUE`
- `VULNERABILITY`

#### Endpoint

A single IP lookup uses the fixed HTTPS authority and the canonical IP as
the only variable path segment:

`https://api.ipinfo.io/lite/<canonical-ip>`

The `/me` self-lookup form is not used. The legacy
`https://ipinfo.io/<ip>/json` endpoint is not used. The canonical IP is
percent-encoded into the resource path; the URL never contains a query,
fragment, credentials, or the access token.

#### Authentication

Requests authenticate with the access token in the Authorization header:

```http
Authorization: Bearer <token>
```

IPinfo accepts the same token as a Bearer header, HTTP Basic username, or
`?token=` query parameter. ATI uses only the Bearer header form. The token
must never appear in query parameters, URLs, logs, errors, evidence, or
fixtures. The token is resolved during composition/bootstrap from the
secret reference documented in `CONFIGURATION.md`; the provider receives
the resolved token value and never reads configuration or the environment.

#### Successful response fields

The Lite lookup response is a top-level JSON object:

```json
{
  "ip": "8.8.8.8",
  "asn": "AS15169",
  "as_name": "Google LLC",
  "as_domain": "google.com",
  "country_code": "US",
  "country": "United States",
  "continent_code": "NA",
  "continent": "North America"
}
```

Only `ip` is strictly required. All other fields are optional; a Lite
response may omit any operator or geographic member for addresses without
such data, and omission is a source fact, not an error. Optional fields
that are present must be strictly valid strings under the rules below;
presence with malformed content invalidates the response.

#### ATI normalized fact shape

Facts are the canonical forms of the response members, keyed identically:

```json
{
  "ip": "8.8.8.8",
  "asn": "AS15169",
  "as_name": "Google LLC",
  "as_domain": "google.com",
  "country_code": "US",
  "country": "United States",
  "continent_code": "NA",
  "continent": "North America"
}
```

The provider does not add derived fields. City, region, latitude,
longitude, VPN/proxy classification, risk, reputation, confidence,
provider score, and network-prefix members are not part of the Lite
response and are never synthesized.

#### Response validation matrix

One successful lookup yields exactly one immutable `Evidence`
(`EvidenceType.NETWORK`). One malformed response yields one typed
`ProviderError` and no evidence; the provider never emits a partly
normalized observation.

| Case | Behavior |
|---|---|
| IPv4 query | Supported; canonical compressed form used in path and subject |
| IPv6 query | Supported; canonical compressed lowercase form used in path and subject |
| unsupported entity type | `UNSUPPORTED_INDICATOR` before I/O; zero HTTP calls |
| invalid entity value | `UNSUPPORTED_INDICATOR` before I/O; zero HTTP calls |
| top-level JSON object required | Non-object top level (list, string, number, boolean, null) is `INVALID_RESPONSE` |
| missing `ip` | `INVALID_RESPONSE`; cross-field identity cannot be proven |
| malformed `ip` | `INVALID_RESPONSE`; outer whitespace is stripped before address parsing (shared canonicalization convention) |
| returned IP mismatch | Returned `ip` must canonicalize exactly to the requested canonical IP; otherwise `INVALID_RESPONSE` (covers textual variants, family mismatch, and wrong address) |
| malformed `asn` | Present `asn` must be `AS` + decimal digits within the legal 32-bit ASN domain (`1..4294967295`), canonical uppercase `AS<number>`; otherwise `INVALID_RESPONSE` |
| malformed `as_domain` | Present `as_domain` must be a valid strict DNS name (IDNA, label characters, length bounds); otherwise `INVALID_RESPONSE` |
| malformed `country_code` | Present value must be a bounded ISO 3166-1 alpha-2 uppercase code; otherwise `INVALID_RESPONSE` |
| malformed `continent_code` | Present value must be a bounded uppercase two-letter continent code; otherwise `INVALID_RESPONSE` |
| wrong scalar types | Strict scalars only: booleans, integers, lists, objects, and null where a string is expected are `INVALID_RESPONSE` |
| missing optional fields | Omitted optional members are omitted from facts; not an error |
| null optional fields | Null is not a string sentinel and is `INVALID_RESPONSE` |
| unknown fields | Unknown top-level members are ignored (extra="ignore") and never copied into facts |
| descriptive text | `as_name`, `country`, and `continent` are preserved verbatim as provider presentation text, bounded in length; only whitespace-only values are rejected |
| overlong strings | Strings over their bounded length are `INVALID_RESPONSE` |
| blank optional strings | Present-but-blank strings are `INVALID_RESPONSE` |
| 401 | `AUTHENTICATION_FAILED`, non-retryable |
| 403 | `FORBIDDEN`, non-retryable |
| 404 | `NOT_FOUND`, non-retryable (shared provider convention) |
| 429 | `RATE_LIMITED`, retryable; Retry-After honored by shared HTTP behavior |
| timeout | `TIMEOUT`, retryable |
| 5xx | `PROVIDER_UNAVAILABLE`, retryable |
| malformed JSON | `INVALID_RESPONSE`, non-retryable |
| invalid content type | `INVALID_RESPONSE`, non-retryable |
| response too large | `INVALID_RESPONSE`, non-retryable (shared bounded-body rule) |
| cancellation | `asyncio.CancelledError` propagates unchanged |

Error messages are generic and never include the response body, URLs,
headers, or the token.

#### Evidence semantics

A successful lookup emits:

- `EvidenceType.NETWORK` (`urn:ati:evidence:network`);
- subject: the queried IP entity reference;
- source: `urn:ati:source:ipinfo_lite`;
- `observed_at=None` (the Lite API carries no source observation time);
- timezone-aware UTC `retrieved_at`;
- credential-free `source_url=https://api.ipinfo.io/lite/<canonical-ip>`;
- `raw_payload=None` (conservative data minimization).

Country and continent members are contextual network facts about the
address's registration geography. They are not maliciousness evidence by
themselves, and a missing country is not evidence of concealment or of
benignity. The provider does not create an ATI verdict, does not assess
maliciousness, does not create relationships, does not instantiate
discovered entities from `as_domain`, and does not persist anything.

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

#### Authoritative DNS semantics

Google's JSON API documentation defines the HTTP request/response encoding,
but it is not the complete semantic specification for DNS record data. DNS
normalization and validation must also follow the applicable DNS standards,
including:

- RFC 1035 for DNS names and common resource-record presentation;
- RFC 7505 for null MX;
- RFC 8499 for current DNS terminology.

When the JSON transport contract and an applicable DNS protocol contract both
constrain a value, ATI validates both. A schema-valid JSON string is not
necessarily a semantically valid resource record. Conversely, a protocol-valid
special value must not be rejected merely because it is not a valid ATI entity
value.

#### Entity names and protocol names

ATI entity canonicalization and DNS protocol-field normalization are related
but distinct contracts:

- An investigated `DOMAIN` must identify a non-root reusable domain entity.
  Empty values, empty labels, and the DNS root (`.`) are not ATI domain
  entities.
- Non-root DNS owner names and ordinary domain-valued RDATA use strict
  lowercase IDNA normalization without a terminal dot.
- The DNS root is a valid protocol name but not an ATI `DOMAIN` entity. Where
  a supported domain-valued DNS field contains the root, ATI preserves it as
  the exact normalized string `.` and marks it ineligible for entity
  discovery. A field-specific semantic rule may impose additional limits.
- A protocol-defined sentinel may be valid in one specific RDATA field even
  when it is not eligible to become an ATI entity. Such exceptions must be
  explicit per record type; they must not weaken the general domain entity or
  DNS-name validator.
- The MX root exchange (`.`) has the specific null-MX meaning only when paired
  with preference `0`. It must never be emitted as a discovered domain,
  relationship endpoint, or pivot target.

Provider implementations must use field-specific normalizers where protocol
semantics differ from entity canonicalization. Do not make a global
canonicalizer accept a protocol sentinel to accommodate one record type.

#### DNS record validation matrix

For each query, ATI validates every answer before emitting evidence. One
malformed answer invalidates that query observation; ATI never emits a partly
normalized answer set. CNAME records included in another query type are
preserved in source order only where the provider contract permits a CNAME
chain.

| RR type | Required semantic validation | Stable normalized fields | Special values |
|---|---|---|---|
| A | RDATA is an IPv4 address | canonical compressed `value` | none |
| AAAA | RDATA is an IPv6 address | canonical compressed lowercase `value` | none |
| CNAME | RDATA is one DNS domain name | canonical `value` | root normalizes to `.` and is not discoverable |
| NS | RDATA is one DNS domain name | canonical `value` | root normalizes to `.` and is not discoverable |
| PTR | RDATA is one DNS domain name | canonical `value` | root normalizes to `.` and is not discoverable |
| MX | preference is an integer in `0..65535`; exchange follows the MX rules below | integer `preference`, canonical `exchange` | `0 .` is null MX |
| TXT | JSON `data` is a string and remains untrusted text; ATI does not execute, concatenate, or reinterpret provider presentation quoting | exact post-JSON-decoding provider string as `value` | a zero-length `data` member is schema-invalid |
| SOA | RDATA tokenizes into exactly two DNS domain names and five unsigned 32-bit integers | `mname`, `rname`, `serial`, `refresh`, `retry`, `expire`, `minimum` | RFC 1035 decimal and escaped-character name syntax is decoded before canonicalization; malformed/incomplete escapes are invalid |

Domain-valued RDATA parsing must understand DNS presentation escapes rather
than splitting or validating the escaped source text as though it were already
a canonical hostname. A backslash followed by exactly three ASCII decimal
digits decodes one octet; Unicode numeral characters are not decimal-escape
digits. A backslash followed by another character quotes that
character. A trailing or incomplete escape is invalid. Decoded names must be
representable as valid DNS names under ATI's supported IDNA/text contract;
unsupported arbitrary-octet labels are `INVALID_RESPONSE`, not replacement-
decoded or silently altered. SOA tokenization must honor escaped whitespace so
it cannot change field boundaries.

Record-type tests must include a positive ordinary form, malformed syntax, a
wrong-family/type form where applicable, canonicalization boundaries, root-name
handling for domain-valued fields, escaped presentation syntax where
applicable, and each standards-defined special form ATI claims to support. If
a standards-valid form has no approved normalized representation, stop and
update this document before coding rather than classifying it as malformed by
accident.

#### DNS RR-set consistency

Validation includes relationships among answers, not only validation of each
record in isolation. At minimum:

- NXDOMAIN with an Answer section is contradictory and is
  `INVALID_RESPONSE`.
- A null MX is valid only as preference `0` with exchange `.`.
- A valid null-MX set contains exactly one MX record. A null MX mixed with an
  ordinary MX, a duplicate null MX, or a root exchange with nonzero preference
  is `INVALID_RESPONSE`; no partial MX evidence is emitted.
- Preference `0` with a non-root exchange is an ordinary MX record, not null
  MX.
- A CNAME included as part of an otherwise supported answer chain does not
  itself count as an MX record when evaluating null-MX cardinality.
- When `Question` is present, every entry must match the canonical requested
  name and numeric requested type.
- Every non-CNAME answer must be attributable to the requested name or to the
  terminal target of a validated CNAME chain. CNAME chains must be contiguous
  by canonical owner/target name, must not loop, and must not contain two
  different targets for the same owner. Unrelated-owner answers are
  `INVALID_RESPONSE` and are never attached to the investigated subject.
- For a direct query without a CNAME chain, each answer owner must equal the
  canonical query name. Owner-name validation alone is insufficient.
- Answer-type exceptions must be explicit. A query may contain its requested
  type and a validated CNAME chain; an unrelated known or unknown RR type is
  `INVALID_RESPONSE`.

RR-set consistency rules must be enforced after individual answer
normalization and before immutable Evidence construction. They do not infer
relationships or maliciousness.

Supported entity types:

- ``DOMAIN``: queries A, AAAA, CNAME, MX, NS, TXT, SOA in order. NXDOMAIN
  on the first query short-circuits remaining types. An NXDOMAIN response
  that carries an Answer section is contradictory upstream data and is
  rejected as ``INVALID_RESPONSE``. NOERROR with no answers
  for a record type is a valid empty sub-result. Queried names and ordinary
  provider-supplied DNS names are strictly validated (no embedded whitespace,
  underscores, empty labels, or overlong labels; at most one terminal DNS
  root dot is removed, so names such as ``example.com..`` are rejected;
  Unicode input is canonicalized to IDNA punycode). Invalid input names are
  `UNSUPPORTED_INDICATOR`; invalid response names are `INVALID_RESPONSE`.
  Protocol sentinels are accepted only where the field-specific matrix above
  explicitly defines them and never broaden valid entity inputs.
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
- CNAME/NS/PTR: ``value`` as a canonical lowercase IDNA domain without a
  trailing dot, or `.` for the protocol root. The root value is retained as a
  source fact but is not eligible for entity discovery.
- MX: integer ``preference`` and ``exchange``. An ordinary exchange is a
  canonical lowercase IDNA domain without a trailing dot. The exact pair
  ``preference=0`` and ``exchange="."`` represents null MX and states that the
  source advertises no mail exchanger. The root sentinel is retained only as
  a provider fact; it is not a domain entity or relationship target.
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
