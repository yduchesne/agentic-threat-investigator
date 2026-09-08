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
`?token=` query parameter. ATI uses only the Bearer header form. Real or
resolved tokens must never be committed, logged, persisted, placed in URLs,
or copied into test fixtures; clearly synthetic placeholder credentials are
permitted only in isolated deterministic tests. The token is resolved
during composition/bootstrap from the
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
| malformed `asn` | Present `asn` must be `AS` + decimal digits within the legal 32-bit ASN domain (`1..4294967295`), canonical uppercase `AS<number>`; otherwise `INVALID_RESPONSE`. Outer whitespace is stripped before validation (shared canonicalization convention) |
| malformed `as_domain` | Present `as_domain` must be a valid strict DNS name (IDNA, label characters, length bounds); otherwise `INVALID_RESPONSE`. Outer whitespace is stripped and the value lowercased/IDNA-canonicalized (shared canonicalization convention) |
| malformed `country_code` | Present value must be an officially assigned ISO 3166-1 alpha-2 uppercase code (exceptionally reserved elements such as `UK` and unassigned elements such as `ZZ` are rejected); otherwise `INVALID_RESPONSE` |
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

#### Source contract

DB-IP City Lite is a **local, file-backed** geolocation evidence source. It is
not an HTTP provider: the provider performs no DB-IP API call, no download,
and holds no HTTP client. PR 14 never downloads the database; operators obtain
it once (see `docs/DEPLOYMENT.md`) and place it under the configured dataset
location before provider use. The artifact URI is credential-free (a
`file://` URI below `${ATI_DATA_DIR}/datasets/` in v0.1); no API key exists.

The artifact is the downloadable **DB-IP IP to City Lite MMDB**
(MaxMind DB format). The provider resolves the configured artifact URI through
the existing ObjectStore boundary (`FileSystemObjectStore` in v0.1), reads the
artifact bytes, and opens a long-lived read-only MMDB reader at composition
time. The MMDB file is untrusted input: every consumed record is strictly
validated before normalization, and the MMDB metadata `database_type` is
verified against the official DB-IP City Lite product identity
(`DBIP-City-Lite`); a valid MMDB of any other product edition is rejected
with a typed composition failure.

Supported entity type: `IP_ADDRESS` only (IPv4 and IPv6, canonicalized by the
domain IP canonicalizer before lookup).

Consumed City Lite members (all other members are ignored):

```text
country.iso_code
subdivisions[0].names["en"]
city.names["en"]
location.latitude
location.longitude
```

Paid or out-of-scope fields (postal code, timezone, ASN, ISP, organization,
connection type) are never consumed. Only English (`en`) names are used in
v0.1. If the English name is absent, the field is `None`; no arbitrary
language fallback is performed.

#### Record validation

- `country.iso_code`: strict string, exactly two ASCII letters, normalized to
  uppercase. Lowercase is accepted and uppercased; digits, punctuation, wrong
  lengths, booleans, numbers, lists, objects, null, blank, and whitespace-only
  values are malformed.
- `city.names["en"]`, `subdivisions[0].names["en"]`: strict non-blank bounded
  strings (at most 200 characters after stripping outer whitespace). Booleans,
  numbers, lists, objects, null, blank, whitespace-only, and overlong values
  are malformed.
- `subdivisions[0]`: the first entry is selected deterministically when
  present; `subdivisions` must be a list and the first entry a mapping with a
  mapping `names` member. A non-list `subdivisions`, a non-mapping first
  entry, or a non-mapping `names` is a malformed record. An absent `names`
  member or an absent `en` name yields `None`; no arbitrary language fallback
  is performed.
- `location.latitude`/`location.longitude`: finite real numeric values only.
  Booleans, strings, NaN, infinities, and out-of-range values are malformed.
  Valid ranges are latitude [-90, 90] and longitude [-180, 180].
- Coordinate pair rule: both coordinates must be present or both absent. A
  partial pair (exactly one of the two) is `INVALID_RESPONSE`.
- Unknown or out-of-scope members at any level are ignored.
- Malformed nested structures (non-dict `country`, `city`, `location`; or a
  non-list `subdivisions`) make the record malformed.

#### Precision

Exactly one of:

- `CITY` — usable city and country present.
- `REGION` — no usable city; usable region and country present.
- `COUNTRY` — no usable city/region; usable country present.
- `UNKNOWN` — a record exists but no approved granularity can be established;
  coordinates alone do not upgrade precision and are still normalized when
  valid.

A record carrying no usable approved data at all (no country, region, city,
and no valid coordinate pair) is treated as a documented lookup miss and
yields no evidence and no error.

#### Misses, private/reserved addresses, and failures

- Lookup miss (no record for the canonical IP, including private, reserved,
  and non-global ranges, which City Lite never contains): a valid miss is
  `ProviderResult(provider=..., evidence=(), errors=())` — no evidence and no
  error. A miss is not a benign assessment.
- Missing, unreadable, or corrupt artifact at lookup time:
  `PROVIDER_UNAVAILABLE` (retryable).
- Malformed matched record (including a partial coordinate pair):
  `INVALID_RESPONSE` (non-retryable).

#### Evidence shape

A successful usable lookup emits exactly one immutable evidence observation:

```text
type         = GEOLOCATION (urn:ati:evidence:geolocation)
subject      = queried IP (canonicalized value)
source       = urn:ati:source:dbip_city_lite
source_url   = None (local artifact; no host paths are leaked)
observed_at  = None
retrieved_at = lookup time (timezone-aware UTC)
raw_payload  = None
facts        = normalized geolocation: country_code, region, city,
               latitude, longitude, provider, precision
```

The `provider` fact is `urn:ati:source:dbip_city_lite`. Geolocation facts are
approximate context only; they never imply attacker or device physical
location and are never maliciousness evidence.

#### Validation matrix

Automated tests must cover: IPv4 and IPv6 hits; lookup miss; unsupported and
invalid entity input without any lookup; missing, unreadable, and corrupt
artifact; malformed top-level and nested record shapes; missing English
names; country-code validity; coordinate types, ranges, NaN, infinities,
booleans, strings, and partial pairs; extra/unknown fields; city, region, and
country precision derivation; no-usable-location records; private/reserved
addresses; and the absence of persistence, relationships, network I/O, or
recursive side effects.

### AbuseIPDB

Purpose:

- IP reputation.
- Abuse reports and provider-specific scoring.

No result or low score is not automatically evidence that an IP is benign.

Source identifier:

`urn:ati:source:abuseipdb`

The stable ATI member `SourceId.ABUSEIPDB` publishes this identifier.

ATI treats provider-specific fields as source facts rather than generic
confidence. `abuseConfidenceScore` and all report facts are retained as
normalized source facts only; they never weight ATI assessment confidence
and never constitute maliciousness evidence by themselves.

#### Applicability

Supported entity types:

- `IP_ADDRESS`

Unsupported entity types (each is a non-retryable
`UNSUPPORTED_INDICATOR` produced before clock evaluation or any HTTP
I/O):

- `DOMAIN`
- `URL`
- `NETWORK_PREFIX`
- `ASN`
- `ORGANIZATION`
- `MALWARE`
- `ATTACK_TECHNIQUE`
- `VULNERABILITY`

#### Endpoint

A single IP check uses the fixed AbuseIPDB API v2 endpoint with the
canonical IP as a query parameter:

`https://api.abuseipdb.com/api/v2/check`

The `/api/v2/check-block`, `/api/v2/blacklist`, and `/api/v2/report`
endpoints are not used. The request query string carries exactly
`ipAddress` (the canonical IP; IPv6 colons are percent-encoded by the
shared client), `maxAgeInDays` (settings-bounded to `1..365`), and
`verbose` (always sent, so report facts are returned). The URL stored as
evidence `source_url` is the credential-free, query-free endpoint above.
The legacy `?key=` query authentication form is never used because it
leaks credentials into server logs.

#### Authentication

Requests authenticate with the API key in the custom header:

```http
Key: <api key>
```

Real or resolved keys must never be committed, logged, persisted, placed
in URLs, or copied into test fixtures; clearly synthetic placeholder
keys are permitted only in isolated deterministic tests. The key is
resolved during composition/bootstrap from the secret reference
documented in `CONFIGURATION.md`; the provider receives the resolved
key value and never reads configuration or the environment.

#### Request parameters

- `ipAddress`: the canonical queried IP (required).
- `maxAgeInDays`: the report look-back window in days; configured by
  the `abuseipdb_max_age_in_days` setting (default `30`, bounded
  `1..365`), identical for every lookup.
- `verbose`: always present, so the response includes the `reports`
  array and report facts.

#### Quota and operational limits

- Request quotas and rate limits depend on the operator's current
  AbuseIPDB plan and are external terms subject to change; ATI does not
  encode a fixed daily quota policy.
- When the quota is exhausted the source responds with HTTP 429; the
  shared provider HTTP policy treats it as retryable and honors
  `Retry-After`.
- Only the `/api/v2/check` endpoint is used. ATI performs lookups only
  and never submits abuse reports.
- Automated tests use ATI-authored synthetic responses only and never
  contact the real AbuseIPDB service.

#### Successful response fields

The success response is a top-level JSON object with a `data` object.
The example below is illustrative synthetic data authored for ATI
documentation and tests (an RFC 5737 documentation address and synthetic
operator values); it is not a copied AbuseIPDB record. Consumed `data`
members:

```json
{
  "ipAddress": "192.0.2.39",
  "isPublic": false,
  "ipVersion": 4,
  "isWhitelisted": false,
  "abuseConfidenceScore": 75,
  "isTor": false,
  "totalReports": 1,
  "numDistinctUsers": 1,
  "lastReportedAt": "2026-01-15T12:00:00+00:00",
  "reports": [
    {
      "reportedAt": "2026-01-15T12:00:00+00:00",
      "categories": [18, 22]
    }
  ]
}
```

Consumed members are exactly: `ipAddress`, `isPublic`, `ipVersion`,
`isWhitelisted`, `abuseConfidenceScore`, `isTor`, `totalReports`,
`numDistinctUsers`, `lastReportedAt`, report `reportedAt`, and report
`categories`.

Presence rules:

- `isWhitelisted` is required in the response but may be `true`,
  `false`, or `null`; its value is always retained as the
  `is_whitelisted` fact. Whitelist state is a source fact only and is
  never translated into benign/suspicious/malicious semantics
  (AbuseIPDB itself cautions against using this field as the primary
  basis for action).
- `lastReportedAt` is required but may be a timezone-aware timestamp or
  `null`; its value is always retained as the `last_reported_at` fact.
- Because ATI always requests `verbose`, `reports` is a required array;
  an empty array is valid and is retained as `reports: []`. A missing
  or null `reports` member is malformed.
- Report `reportedAt` and `categories` are required in every report
  entry.
- `categories` values are strict positive integers; `0`, negative
  integers, booleans, floats, strings, and null are invalid. ATI
  retains the integer identifiers exactly as reported and does not
  synthesize, map, or attach category names.
- All other members are required non-nullable: an explicit null or
  absent member is malformed (`INVALID_RESPONSE`).

Deliberately unconsumed members (ignored, never copied into facts,
never validated, never synthesized): `countryCode`, `countryName`,
`usageType`, `isp`, `domain`, `hostnames`, report `comment` (untrusted
third-party free text), report `reporterId`, report
`reporterCountryCode`, report `reporterCountryName`, and all unknown
members. AbuseIPDB documents the geography and network fields as
sourced from IPinfo; ATI has a dedicated IPinfo Lite provider and does
not normalize this data from AbuseIPDB. Ignored members cannot become
entities, relationships, evidence facts, or pivot targets.

Only exact external camel-case member names affect parsing: ATI-side
snake-case names are never accepted as source members (the response
models do not populate by field name), and unknown members are ignored.

#### ATI normalized fact shape

```json
{
  "ip_address": "192.0.2.39",
  "is_public": false,
  "ip_version": 4,
  "is_whitelisted": false,
  "abuse_confidence_score": 75,
  "is_tor": false,
  "total_reports": 1,
  "num_distinct_users": 1,
  "last_reported_at": "2026-01-15T12:00:00+00:00",
  "max_age_in_days": 30,
  "reports": [
    {
      "reported_at": "2026-01-15T12:00:00+00:00",
      "categories": [18, 22]
    }
  ]
}
```

Every fact key above is always present in a successful lookup, including
zero-report responses and non-default look-back windows:
`max_age_in_days` is always included so report and count semantics can
be interpreted against the queried window. `last_reported_at` is `null`
when the source value is null. `last_reported_at` and report
`reported_at` values are strict timezone-aware ISO 8601 timestamps
normalized to UTC; outer whitespace in a timestamp is invalid and is
never normalized away. Report entries and category identifiers preserve
source array order: ATI does not sort, deduplicate, or attach category
names. Each normalized report contains exactly `reported_at` and
`categories`. The provider does not add derived fields; risk bands,
severity, verdicts, and confidence values are never synthesized.

#### Response validation matrix

One successful lookup yields exactly one immutable `Evidence`
(`EvidenceType.REPUTATION`). One malformed response yields one typed
`ProviderError` and no evidence; the provider never emits a partly
normalized observation.

| Case | Behavior |
|---|---|
| IPv4 query | Supported; canonical compressed form in the query and subject |
| IPv6 query | Supported; canonical compressed lowercase form in the query and subject |
| unsupported entity type | `UNSUPPORTED_INDICATOR` before I/O; zero HTTP calls |
| invalid entity value | `UNSUPPORTED_INDICATOR` before I/O; zero HTTP calls |
| top-level JSON object required | Non-object top level is `INVALID_RESPONSE` |
| missing/non-object `data` | `INVALID_RESPONSE` |
| returned IP mismatch | `data.ipAddress` must canonicalize exactly to the requested canonical IP; otherwise `INVALID_RESPONSE` (covers textual variants, family mismatch, and a wrong address) |
| `ipVersion` mismatch | Must be `4` for IPv4 and `6` for IPv6 queries; otherwise `INVALID_RESPONSE` |
| `isWhitelisted` | Required member; `true`, `false`, and `null` are valid and retained; booleans-string, integer, list, and object values are `INVALID_RESPONSE` |
| `lastReportedAt` | Required member; a timezone-aware ISO 8601 timestamp or `null` is valid; naive timestamps, whitespace-padded strings, non-strings, and unparseable values are `INVALID_RESPONSE` |
| `abuseConfidenceScore` bounds | Strict integer `0..100`; floats, booleans, strings, null, out-of-range are `INVALID_RESPONSE` |
| `totalReports`/`numDistinctUsers` | Strict integers `>= 0`; otherwise `INVALID_RESPONSE` |
| `isPublic`/`isTor` | Strict booleans; otherwise `INVALID_RESPONSE` |
| timestamps | Strict timezone-aware ISO 8601; naive timestamps, whitespace-padded strings, non-strings, and unparseable values are `INVALID_RESPONSE` |
| `reports` | Required array under the verbose contract; a missing or null member and non-array values are `INVALID_RESPONSE`; an explicit empty array is valid |
| report `reportedAt` | Required; strict timezone-aware ISO 8601 |
| report `categories` | Required list of strict positive integers (explicit empty list allowed); `0`, negative integers, booleans, floats, numeric strings, null entries, and a missing member are `INVALID_RESPONSE` |
| null required member | `INVALID_RESPONSE`, except `isWhitelisted` and `lastReportedAt` whose documented null values are valid |
| unknown members | Unknown members at any level are ignored and never copied into facts |
| 401 | `AUTHENTICATION_FAILED`, non-retryable |
| 402 | `FORBIDDEN`, non-retryable (expired subscription is an access denial, not a malformed response) |
| 403 | `FORBIDDEN`, non-retryable |
| 404 | `NOT_FOUND`, non-retryable (shared provider convention) |
| 422 | `INVALID_RESPONSE`, non-retryable |
| 429 | `RATE_LIMITED`, retryable; `Retry-After` honored by shared HTTP behavior |
| timeout | `TIMEOUT`, retryable |
| 5xx | `PROVIDER_UNAVAILABLE`, retryable |
| malformed JSON | `INVALID_RESPONSE`, non-retryable |
| invalid content type | `INVALID_RESPONSE`, non-retryable |
| response too large | `INVALID_RESPONSE`, non-retryable (shared bounded-body rule) |
| cancellation | `asyncio.CancelledError` propagates unchanged |

Error messages are generic and never include the response body, URLs,
headers, or the API key.

#### Misses and benignity

There is no lookup-miss concept: the source returns score data for any
checkable IP. A response with `abuseConfidenceScore` 0 and zero reports
is a successful lookup whose facts are retained as evidence; it is
**not** a benign assessment and never implies benignity.

#### Evidence semantics

A successful lookup emits:

- `EvidenceType.REPUTATION` (`urn:ati:evidence:reputation`);
- subject: the queried IP entity reference;
- source: `urn:ati:source:abuseipdb`;
- `observed_at`: the normalized `lastReportedAt` value (UTC) when
  non-null; `None` only when `lastReportedAt` is null;
- timezone-aware UTC `retrieved_at`;
- credential-free `source_url=https://api.abuseipdb.com/api/v2/check`;
- `raw_payload=None` (conservative data minimization).

The provider does not create an ATI verdict, does not assess
maliciousness, does not weight assessment confidence, does not create
relationships, does not instantiate discovered entities from report
data, and does not persist anything.

### ThreatFox

Purpose:

- IOC-to-malware associations from the abuse.ch ThreatFox Community API.
- Source malware identifiers and printable names for later deterministic
  MALWARE entity discovery.

ATI persists observations locally because provider retention may be bounded
(ThreatFox expires IOCs from API/export visibility after six months).

Source identifier:

`urn:ati:source:threatfox`

The stable ATI member `SourceId.THREATFOX` publishes this identifier.

ThreatFox is a malware-focused community IOC platform: a record associates
one IOC (domain, `ip:port`, URL, or hash) with a malware family, a source
`confidence_level`, first/last-seen timestamps, and optional reference and
tag metadata. All of these values are normalized source facts. The source
`confidence_level` is not an ATI Assessment confidence and never weights
one; a ThreatFox match is not by itself an ATI malicious verdict, and a
ThreatFox no-result is never a benign assessment.

#### Applicability

Supported entity types:

- `DOMAIN`
- `IP_ADDRESS`

Unsupported entity types (each is a non-retryable `UNSUPPORTED_INDICATOR`
produced before clock evaluation or any HTTP I/O):

- `URL` — ATI has no approved URL canonicalization or exact URL identity
  contract yet, so an unambiguous exact-match identity rule cannot be
  guaranteed; ThreatFox URL support is deferred until such a contract
  exists.
- `NETWORK_PREFIX`, `ASN`, `ORGANIZATION`, `MALWARE`, `ATTACK_TECHNIQUE`,
  `VULNERABILITY`

#### Endpoint

A single IOC search uses the fixed ThreatFox Community API v1 endpoint:

`https://threatfox-api.abuse.ch/api/v1/`

The request is an HTTP `POST` whose JSON body carries exactly:

```json
{
  "query": "search_ioc",
  "search_term": "<canonical entity value>",
  "exact_match": true
}
```

`search_term` is the canonicalized queried entity value. `exact_match` is
always `true`: ATI never performs wildcard searches. The other Community
API queries (`get_iocs`, `ioc`, `search_hash`, `taginfo`, `malwareinfo`,
`submit_ioc`, `get_label`, `malware_list`, `types`, `tag_list`) are not
used. ATI performs lookups only and never submits IOCs. The URL stored as
evidence `source_url` is the credential-free endpoint above.

#### Authentication

Requests authenticate with the abuse.ch Auth-Key in the custom header:

```http
Auth-Key: <auth key>
```

The Auth-Key travels only in the `Auth-Key` header. It never appears in
the URL, the request body, logs, errors, evidence facts, or fixtures.
Real or resolved keys must never be committed or logged; clearly synthetic
placeholder keys are permitted only in isolated deterministic tests. The
key is resolved during composition/bootstrap from the secret reference
documented in `CONFIGURATION.md`; the provider receives the resolved key
value and never reads configuration or the environment.

#### IOC identity matching

ATI independently validates every returned record even though the request
requests an exact match. A record's `ioc_type` must agree with its actual
IOC syntax and with the queried entity type, and the record's IOC value
must canonicalize exactly to the queried canonical identity. Unrelated
records are rejected (`INVALID_RESPONSE`) even when the upstream claims an
exact match.

- **DOMAIN**: the returned domain is validated with ATI's strict provider
  DNS-name validator before canonical comparison, then must equal the
  queried canonical domain. Empty labels, underscores, invalid IDNA
  input, multiple terminal dots, invalid label characters or lengths,
  and overlong names are rejected (`INVALID_RESPONSE`). Case differences
  and exactly one terminal root dot are accepted through
  canonicalization. The record `ioc_type` must be `domain`.
- **IP_ADDRESS, bare IP**: a returned IOC that parses as a whole IPv4 or
  IPv6 address matches when its canonical form equals the queried
  canonical IP. The record `ioc_type` must be `ip:port` (the only source
  type ThreatFox uses for address indicators); the port part is optional
  in source data.
- **IP_ADDRESS, `ip:port`**: a returned `address:port` pair matches when
  the parsed host canonicalizes exactly to the queried canonical IP and
  the port is an integer in `1..65535`. The port is retained as part of
  the source IOC string only; it never becomes an entity, a fact field,
  or a pivot target.
- **IPv6 safety**: a bracketed RFC 3986 `[address]:port` pair is parsed
  as host plus port. An unbracketed colon-containing value is never split
  on colons to infer a port: a multi-colon value is accepted only when it
  parses as a whole bare IPv6 address, so ambiguous unbracketed
  IPv6-plus-port spellings are rejected rather than guessed.
- **URL records**: `url`-typed records never match a DOMAIN or
  IP_ADDRESS query and are rejected.

The record `ioc_type` must be one of the source types ATI can interpret
(`domain`, `ip:port`, `url`); any other value (for example `filename` or a
hash type) cannot match a supported query and is rejected.

#### Duplicate source records

Duplicate handling runs only after each entry passes strict model
validation and queried-IOC identity validation:

- the first occurrence of a ThreatFox `id` establishes that source
  record's consumed normalized content and its output position;
- a later occurrence of the same `id` with identical consumed normalized
  content is an exact duplicate and is omitted from `facts.matches`;
- a later occurrence of the same `id` with different consumed normalized
  content makes the whole response `INVALID_RESPONSE` with no evidence;
- records with different IDs remain in upstream order even when their
  IOC and malware are equal.

Comparison uses the consumed validated record model, not raw
dictionaries: differences only in deliberately ignored fields are
neither duplicated into facts nor treated as conflicts. Records are
never sorted, and records are never deduplicated merely because they
share a malware identifier; semantic malware entity and association
deduplication belongs to PR 18.

#### Six-month expiration

Since 2025-05-01 ThreatFox expires IOCs older than six months from API
and export visibility (they remain visible in the ThreatFox web UI). A
ThreatFox no-result therefore means only that the indicator is not
currently exposed by the API; it never proves that the indicator was
never historically observed.

#### Successful response fields

The success response is a top-level JSON object with `query_status` and a
`data` array. The example below is illustrative synthetic data authored
for ATI documentation and tests (an RFC 5737 address, an RFC 2606 `.test`
domain, and synthetic identifiers); it is not a copied ThreatFox record.
Consumed `data` members:

```json
{
  "query_status": "ok",
  "data": [
    {
      "id": "864201",
      "ioc": "malicious-domain.test",
      "threat_type": "botnet_cc",
      "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
      "ioc_type": "domain",
      "ioc_type_desc": "Domain that is used for botnet Command&control (C&C)",
      "malware": "win.asyncrat",
      "malware_printable": "AsyncRAT",
      "malware_alias": null,
      "malware_malpedia": null,
      "confidence_level": 100,
      "first_seen": "2026-08-20 12:00:00 UTC",
      "last_seen": "2026-08-21 12:00:00 UTC",
      "reference": null,
      "tags": ["AsyncRAT"]
    }
  ]
}
```

Presence rules:

- `id` must be the official bounded decimal identifier string.
- `ioc` must be a nonblank, unpadded, bounded source IOC string whose
  syntax agrees with `ioc_type` (validated by the identity rules above).
- `threat_type`, `threat_type_desc`, and `ioc_type_desc` are required
  nonblank bounded strings.
- `malware` is the ThreatFox (Malpedia-style) machine identifier: a
  strict nonblank lowercase bounded identifier. It is the canonical
  identity input for later MALWARE entity discovery.
- `malware_printable` may be `null`; a non-null value must be a nonblank
  bounded unpadded string. The printable name is display metadata only
  and never determines malware identity.
- `confidence_level` is a strict integer `0..100` exactly as reported.
- `first_seen` is required and `last_seen` may be `null`; both use the
  official `YYYY-MM-DD HH:MM:SS UTC` form and are normalized to
  timezone-aware UTC. A `last_seen` earlier than `first_seen` is
  malformed.
- `reference` may be `null`; a non-null value must be a bounded
  `http`/`https` URL. It is retained as source metadata and never
  fetched.
- `tags` may be `null` or an array of bounded nonblank strings; an
  explicitly empty array is valid. Empty, whitespace-only, and
  outer-whitespace-padded tag values are invalid. Valid source order and
  duplicate valid tags are preserved unchanged.

Consumed and validated but not retained members: `ioc_type_desc`,
`malware_alias`, and `malware_malpedia` are strictly validated on every
record and never copied into normalized facts.

- `ioc_type_desc` is required: omission and explicit null are malformed,
  and a non-null value must be a nonblank bounded unpadded string.
- `malware_alias` may be `null`; a non-null value must be a nonblank
  bounded unpadded string.
- `malware_malpedia` may be `null`; a non-null value must be a bounded
  `http`/`https` URL. It is never fetched.

Ignored and unvalidated members (never copied into facts, never
validated, never synthesized): `reporter`, `comment` (untrusted
third-party free text), `credits`, `malware_samples` (which would
require a MalwareBazaar contract ATI does not implement), and all
unknown members. Ignored members cannot become entities, relationships,
evidence facts, or pivot targets. Only exact external member names
affect parsing; ATI-side snake-case names are never accepted as source
members.

#### Query status matrix

| `query_status` | Behavior |
|---|---|
| `ok` | Success; the `data` array is validated record by record. A missing or non-array `data` is `INVALID_RESPONSE`; an explicitly empty array is a valid no-result. Duplicate source records follow the duplicate rule above. |
| `no_result` | Valid no-result: empty `ProviderResult`, no evidence and no error. Never a benign assessment. |
| `ratelimited` | Body-encoded rate limiting (HTTP 200): typed `RATE_LIMITED` error, retryable. |
| any other value (including statuses such as `error` or `unauthorized`) | Unknown status: non-retryable `INVALID_RESPONSE`. An unknown status is never success. |

#### ATI normalized fact shape

A successful search emits exactly one grouped evidence observation whose
`facts.matches` array contains one entry per validated, non-duplicate
matching record, in upstream order:

```json
{
  "matches": [
    {
      "threatfox_id": "864201",
      "ioc": "malicious-domain.test",
      "ioc_type": "domain",
      "threat_type": "botnet_cc",
      "threat_type_description": "Indicator that identifies a botnet command&control server (C&C)",
      "malware": "win.asyncrat",
      "malware_printable": "AsyncRAT",
      "confidence_level": 100,
      "first_seen": "2026-08-20T12:00:00Z",
      "last_seen": "2026-08-21T12:00:00Z",
      "reference": null,
      "tags": ["AsyncRAT"]
    }
  ]
}
```

Each match contains exactly the keys above. `malware` is the validated
ThreatFox machine identifier retained verbatim: it is the canonical
identity input from which a deterministic extractor later derives the
canonical `MALWARE` entity (`display_name` = `malware_printable` when
present, otherwise the identifier). `malware_printable` is display
metadata only and never determines identity. `first_seen` and non-null
`last_seen` values are normalized to the canonical UTC ISO 8601 form
ending in `Z` (`last_seen` is `null` when the source reported none).
Source array order is preserved: ATI does not sort or reorder matches.

#### Provider boundary: entity discovery and relationships

`ThreatFoxProvider` retrieves, validates, and normalizes. It does not
instantiate discovered entities and does not create relationship
candidates or relationships. `facts.matches` is the complete PR 16
handoff contract for later deterministic extraction: PR 18 owns malware
entity discovery, IOC `ASSOCIATED_WITH` malware relationship
construction, `RelationshipObservation` construction, semantic
deduplication of malware identities and associations, and persistence.
Distinct matching source records remain represented even when they map
to the same malware, preserving source provenance for that extractor.
The provider performs no persistence of any kind.

#### Response validation matrix

One successful search with at least one validated matching record yields
exactly one immutable `Evidence` (`EvidenceType.THREAT_INTELLIGENCE`).
One malformed response — including one malformed or unrelated record —
yields one typed `ProviderError` and no evidence; the provider never
emits a partly normalized observation.

| Case | Behavior |
|---|---|
| unsupported entity type | `UNSUPPORTED_INDICATOR` before I/O; zero HTTP calls |
| invalid entity value | `UNSUPPORTED_INDICATOR` before I/O; zero HTTP calls |
| top-level JSON object required | Non-object top level is `INVALID_RESPONSE` |
| missing/empty/non-string `query_status` | `INVALID_RESPONSE` |
| unknown `query_status` | `INVALID_RESPONSE` (never success) |
| body-encoded `ratelimited` | `RATE_LIMITED`, retryable |
| `ok` without a `data` array | `INVALID_RESPONSE` |
| `ok` with an explicitly empty `data` array | Valid no-result: empty result, no error |
| malformed record (any consumed member) | `INVALID_RESPONSE`; one malformed record invalidates the whole response |
| unrelated record (identity mismatch) | `INVALID_RESPONSE`, even though `exact_match` was requested |
| `ioc_type` disagreement with IOC syntax or query | `INVALID_RESPONSE` |
| malformed returned domain | Empty labels, underscores, invalid IDNA, multiple terminal dots, invalid label characters/lengths, and overlong names are `INVALID_RESPONSE`; case differences and one terminal root dot are accepted |
| missing/null/malformed `ioc_type_desc` | `INVALID_RESPONSE` (required, validated, not retained) |
| exact duplicate `id` (identical consumed content) | Omitted from `facts.matches`; the first occurrence stays authoritative |
| conflicting duplicate `id` (differing consumed content) | `INVALID_RESPONSE`, no evidence; changes only in ignored fields are not conflicts |
| different IDs, equal IOC/malware | Both retained in upstream order |
| `id` | Official bounded decimal string; other shapes are `INVALID_RESPONSE` |
| `malware` | Strict bounded lowercase machine identifier; other values are `INVALID_RESPONSE` |
| `malware_printable`/`malware_alias` | `null` or nonblank bounded unpadded string |
| `malware_malpedia`/`reference` | `null` or bounded `http`/`https` URL; validated, never fetched |
| `confidence_level` | Strict integer `0..100`; otherwise `INVALID_RESPONSE` |
| `first_seen`/`last_seen` | Official `YYYY-MM-DD HH:MM:SS UTC` form (or `null` for `last_seen`); naive, ISO, padded, and unparseable values are `INVALID_RESPONSE`; `last_seen` before `first_seen` is `INVALID_RESPONSE`; normalized fact output uses the exact `Z` UTC form |
| `tags` | `null` or bounded-string list; empty, whitespace-only, and outer-padded values are `INVALID_RESPONSE`; valid order and duplicates are preserved |
| unknown members | Unknown members at any level are ignored and never copied into facts |
| 401 | `AUTHENTICATION_FAILED`, non-retryable |
| 403 | `FORBIDDEN`, non-retryable |
| 404 | `NOT_FOUND`, non-retryable (shared provider convention) |
| 422 | `INVALID_RESPONSE`, non-retryable |
| 429 | `RATE_LIMITED`, retryable; `Retry-After` honored by shared HTTP behavior |
| timeout | `TIMEOUT`, retryable |
| 5xx | `PROVIDER_UNAVAILABLE`, retryable |
| malformed JSON | `INVALID_RESPONSE`, non-retryable |
| invalid content type | `INVALID_RESPONSE`, non-retryable |
| response too large | `INVALID_RESPONSE`, non-retryable (shared bounded-body rule) |
| cancellation | `asyncio.CancelledError` propagates unchanged |

Error messages are generic and never include the response body, URLs,
headers, or the Auth-Key.

#### Misses and benignity

A `no_result` response (or an explicitly empty `data` array under `ok`)
is a valid no-result: an empty `ProviderResult` with no evidence and no
error. It is **not** a benign assessment and never implies benignity.
Because ThreatFox expires IOCs older than six months from API
visibility, a no-result also never proves historical absence.

#### Evidence semantics

A successful search emits:

- `EvidenceType.THREAT_INTELLIGENCE`
  (`urn:ati:evidence:threat_intelligence`);
- subject: the queried entity reference (canonical value);
- source: `urn:ati:source:threatfox`;
- `observed_at`: the latest retained source observation across all
  validated matches (each match's `last_seen` when present, otherwise
  its `first_seen`);
- timezone-aware UTC `retrieved_at`;
- credential-free
  `source_url=https://threatfox-api.abuse.ch/api/v1/`;
- `raw_payload=None` (conservative data minimization).

The provider does not create an ATI verdict, does not assess
maliciousness, does not weight assessment confidence, does not create
relationships, does not instantiate discovered entities from record
data, and does not persist anything.

#### Source terms and test policy

- The Community API is governed by the abuse.ch fair-use principles and
  terms of use; commercial or for-profit needs may require the enhanced
  abuse.ch commercial API. Operators must review the current terms at
  <https://threatfox.abuse.ch/api/>, <https://threatfox.abuse.ch/faq/>,
  and <https://abuse.ch/terms-of-use/>.
- ATI performs lookups only; it never submits IOCs, retrieves malware
  samples, or consumes MalwareBazaar payloads.
- ATI bundles no ThreatFox dataset and never redistributes source data
  as a bundled artifact.
- All automated ThreatFox tests use ATI-authored synthetic responses
  with the real ATI provider/HTTP stack against an in-process upstream
  and never contact the real ThreatFox service, never use a real
  Auth-Key, and never require internet access. There is no live or
  opt-in live ThreatFox test.

### URLhaus

Purpose:

- Malicious-URL (malware-distribution) intelligence for URL and host
  indicators.
- Payload metadata as fact-only evidence context.

Source identifier:

`urn:ati:source:urlhaus`

#### Verified API contract

The provider uses the official URLhaus Community API v1 lookup queries
only. Authoritative reference: <https://urlhaus-api.abuse.ch/> (the
dedicated bulk-query API documented by URLhaus; also
<https://urlhaus.abuse.ch/api/>). The contract below reflects the
official documentation and must be re-verified before every release:

- URL lookup: `POST https://urlhaus-api.abuse.ch/v1/url/` with an
  `application/x-www-form-urlencoded` body carrying exactly one field,
  `url=<value>`, and the `Auth-Key` HTTP header.
- Host lookup: `POST https://urlhaus-api.abuse.ch/v1/host/` with an
  `application/x-www-form-urlencoded` body carrying exactly one field,
  `host=<value>`, and the `Auth-Key` HTTP header. The official
  documentation defines the host query for IPv4 addresses, hostnames,
  and domain names (case insensitive); IPv6 hosts are therefore not
  supported by ATI in v0.1.
- Responses are JSON with a top-level `query_status`. Documented URL
  lookup statuses: `ok`, `http_post_expected`, `no_results`,
  `invalid_url`. Documented host lookup statuses: `ok`,
  `http_post_expected`, `no_results`, `invalid_host`.
- `ok` URL responses carry a single record with the documented required
  members `id`, `urlhaus_reference`, `url`, `url_status`
  (`online`/`offline`/`unknown`), `host`, `date_added`
  (`YYYY-MM-DD HH:MM:SS UTC`), `last_online` (same form or null),
  `threat` (only `malware_download` is documented and accepted),
  `blacklists`, `reporter`, `larted`, `takedown_time_seconds`, `tags`,
  and `payloads` (0–100 entries). Every documented member must be
  present; a missing key is always invalid, while nullable members may
  carry null only where the contract documents null (`last_online`).
- `ok` host responses carry `urlhaus_reference`, a required `host`
  member, a required `firstseen` timestamp (`YYYY-MM-DD HH:MM:SS UTC`),
  `url_count` (decimal string), `blacklists`, and `urls` (1–100 raw
  entries) whose records carry only `id`, `urlhaus_reference`, `url`,
  `url_status`, `date_added`, `threat`, `reporter`, `larted`,
  `takedown_time_seconds`, and `tags`. Host nested records deliberately
  do not consume or emit `host`, `last_online`, or `payloads` members;
  the normalized facts emit those keys as explicit nulls. An `ok` host
  response with an empty `urls[]` collection is invalid: a true miss
  uses the documented `query_status="no_results"` response.
- Payload entries carry `firstseen` (`YYYY-MM-DD` date), `filename`,
  `file_type`, `response_size` (decimal string), `response_md5`,
  `response_sha256`, `urlhaus_download`, `signature`, `virustotal`,
  `imphash`, `ssdeep`, `tlsh`, and `magika`.

#### Supported and unsupported entity types

- Supported: `URL` (exact lookup), `DOMAIN` and `IP_ADDRESS` with an
  IPv4 canonical value (host lookup). IPv6 addresses are rejected with
  `UNSUPPORTED_INDICATOR` before any I/O because the verified host-query
  contract does not document them.
- Unsupported (rejected with `UNSUPPORTED_INDICATOR` before clock
  evaluation or HTTP): `NETWORK_PREFIX`, `ASN`, `ORGANIZATION`,
  `MALWARE`, `ATTACK_TECHNIQUE`, `VULNERABILITY`.

#### Canonical identity rules

- Direct URL identity is revalidated independently: the returned `url`
  must pass the complete shared ATI `canonicalize_url()` contract and
  canonicalize to exactly the queried canonical URL, and the record's
  `host` member must validate (DOMAIN or IP) and equal the canonical
  host parsed from the returned canonical URL itself. A missing,
  malformed, wrong, or cross-field-inconsistent host is
  `INVALID_RESPONSE`.
- Host envelopes are revalidated independently: the top-level `host`
  member must validate (strict DNS form for DOMAIN queries; canonical
  IPv4 for IP queries) and equal the queried canonical identity, even
  when every nested URL happens to match. A missing, malformed,
  wrong-family, or mismatched top-level host is `INVALID_RESPONSE`.
- Every host-response `urls[]` URL is validated through the complete
  shared `canonicalize_url()` contract before the record is accepted: a
  matching hostname alone is insufficient. One URL with an unsupported
  scheme, userinfo, fragment (including an empty `#` delimiter),
  malformed percent escape, invalid port, embedded whitespace, control
  character, or malformed host invalidates the complete response with
  no partial evidence.
- URL queries send the ATI canonical URL identity
  (`canonicalize_url`: strict HTTP/HTTPS-only contract documented in
  `DOMAIN_MODEL.md`).
- Domain queries send the strict canonical DNS form (`validate_dns_name`).
- IPv4 queries send the canonical dotted-quad form.
- The Auth-Key never appears in the URL or the form body.

#### Query status semantics and error mapping

- `no_results` is a valid no-result: an empty `ProviderResult`, never a
  benign assessment.
- `ok` is success only after strict record validation.
- `http_post_expected`, `invalid_url`, and `invalid_host` are
  body-encoded request rejections that can only result from an ATI
  request defect; they map to non-retryable `INVALID_RESPONSE`.
- Unknown statuses are never success and map to non-retryable
  `INVALID_RESPONSE`.
- Shared HTTP mapping applies: 401 -> `AUTHENTICATION_FAILED`,
  403 -> `FORBIDDEN`, 404 -> `NOT_FOUND`, 429 -> `RATE_LIMITED` with
  `Retry-After` handling, timeout -> `TIMEOUT`, 5xx ->
  `PROVIDER_UNAVAILABLE` (retried), malformed JSON / wrong content type
  / oversized body -> `INVALID_RESPONSE`.

#### Normalized fact shape and PR 18 extraction eligibility

A successful lookup emits exactly one immutable
`THREAT_INTELLIGENCE` evidence observation whose `facts` contain
`matches` (source order preserved) plus, for host lookups, the
host-envelope provenance facts `queried_host` (the canonical validated
top-level host), `first_seen` (the canonical UTC ISO-8601 form of the
host-level `firstseen` source timestamp), and `url_count` (the parsed
non-negative total observed by URLhaus; the returned `urls[]` list is
capped at 100 and need not equal `url_count`):

```json
{
  "queried_host": "malicious-domain.test",
  "first_seen": "2026-08-19T08:00:00Z",
  "url_count": 1,
  "matches": [
    {
      "urlhaus_id": "556677",
      "url": "http://malicious-domain.test/download/payload.bin",
      "url_status": "online",
      "date_added": "2026-08-20T12:00:00Z",
      "last_online": null,
      "threat": "malware_download",
      "host": "malicious-domain.test",
      "tags": ["elf"],
      "payloads": [
        {
          "first_seen": "2026-08-20",
          "filename": "payload.bin",
          "file_type": "elf",
          "response_size": 12345,
          "response_md5": null,
          "response_sha256": null,
          "signature": null
        }
      ]
    }
  ]
}
```

Extraction eligibility (PR 18 owns all extraction; PR 17 performs
none):

- `matches[].url` — entity-eligible: the source URL is emitted in
  canonical ATI form (`canonicalize_url()` output, never the original
  source spelling) and is the canonical URL identity input.
- `matches[].host` (URL lookups) — entity-eligible: emitted as a
  canonical DOMAIN/IP identity value (strict DNS form or canonical IP
  representation), never the original source spelling; only if strictly
  derivable/validated by the PR 18 extractor as a DOMAIN or IPv4
  entity. Host-response nested records emit `host=null` because that
  endpoint does not supply the member.
- The queried entity itself — the evidence subject, already canonical.
- `payloads[].response_md5` / `response_sha256` — fact-only. ATI v0.1
  has no file/hash entity type.
- `payloads[].file_type`, `filename`, `response_size` — fact-only.
- `payloads[].signature` — fact-only; no malware entity is inferred
  from signatures or tags (ThreatFox remains ATI's IOC→MALWARE source).
- `tags`, `url_status`, `threat`, timestamps — fact-only source
  observations. `url_status: offline` is never a benign verdict.
- `queried_host` and `first_seen` are host-envelope provenance facts:
  `queried_host` is the strictly validated canonical top-level host the
  source itself reports for the query, and `first_seen` is the
  host-level source observation time. They are retained for provenance
  completeness; extraction eligibility remains with the record-level
  `url` and `host` members.
- Evidence `observed_at` is the latest relevant source timestamp across
  the host `firstseen` and all retained record `date_added`
  (and, for URL lookups, `last_online`) observations; an earlier host
  `firstseen` never replaces a newer record observation.

PR 17 performs no entity extraction, no relationship construction, and
no persistence. No existing `RelationshipType` semantic is repurposed
for the URL–host composition relation; PR 18 must introduce any such
semantic through separate approved documentation.

#### Duplicate and collection invariants

- For each `urlhaus_id`: the first occurrence establishes normalized
  content and output position; an exact duplicate is omitted; the same
  ID with conflicting consumed normalized content invalidates the whole
  response (`INVALID_RESPONSE`, no evidence). Duplicate comparison
  happens after strict validation and before evidence construction, on
  the consumed normalized content (canonical URL, url_status,
  normalized date_added, threat, and tags in source order); ignored
  upstream members such as `reporter`, `larted`,
  `takedown_time_seconds`, and `urlhaus_reference` are not part of the
  comparison. Canonical-equivalent raw URL spellings for the same
  source ID are identical consumed content because `matches[].url` is
  canonicalized before comparison, while security-significant canonical
  URL differences (different paths, query text/order, non-default
  ports, or byte-for-byte percent-escape spelling) remain conflicts.
- Records with distinct IDs but the same canonical URL are retained as
  independently distinct source observations; deduplication by
  canonical identity is PR 18's concern.
- For host lookups, every returned URL must parse and canonicalize to
  the queried canonical host; one unrelated record invalidates the
  whole response (the endpoint promises exact host results), and the
  top-level `host` envelope member must independently match the queried
  identity. For URL lookups, the returned `url` must canonicalize to
  exactly the queried canonical URL and the record `host` member must
  agree with the returned URL's own host.
- Duplicate collapsing happens after the documented 100-entry collection
  limits are enforced on the raw response; a raw over-limit collection
  is `INVALID_RESPONSE` regardless of duplicates.
- One malformed record invalidates the whole response: no partial
  evidence is ever emitted. Every malformed response returns a typed
  result and never escapes an exception.

#### Payload metadata policy

Payload metadata is useful context but ATI v0.1 has no file/hash entity
type: hashes, sizes, file types, signatures, and first-seen dates are
evidence facts only. ATI never downloads payloads, never fetches
`urlhaus_download` links (which are not retained at all), never opens
returned URLs, and never infers malware identity from signatures or
tags. URLhaus publicly warns that collected payloads are not necessarily
malicious once a URL changes or is cleaned.

#### Security constraints and terms

- The Auth-Key is resolved through `SecretsResolver` during composition
  (secret reference `ATI_URLHAUS_AUTH_KEY`) and is used only in the
  `Auth-Key` header; it never appears in URLs, bodies, facts, errors,
  logs, or fixtures.
- Raw provider payloads are not retained (`raw_payload=None`).
- The Community API is free of charge under abuse.ch fair-use for
  non-commercial use; commercial use may require a paid subscription
  (<https://abuse.ch/terms-of-use/>). ATI performs lookups only and
  never submits URLs or downloads datasets.
- Automated tests are fully synthetic over an in-process ASGI virtual
  upstream (`urlhaus-api.abuse.ch`); no test contacts the real URLhaus
  service, requires a real Auth-Key, or has internet access.

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
