# Core Concepts

This page describes concepts that are fundamental to understanding the rest of the system. Most concepts correspond to the different types of data (i.e.: records in database tables) that the system stores.

## References

- [Data Sources](DATA_SOURCES.md): Presents core concepts such as `Entity`, `Evidence`, etc.

## Entity

An `Entity` is a canonical object that can be "interesting" in the context of CTI:

- IP address: `203.0.113.42`.
- Domain: `malicious-example.com`.
- ASN: `AS64500`.
- URL: `https://malicious-example.com/payload.exe`
- Hash: `44d88612fea8a8f36de82e1278abb02f`

For example, an IP address entity would have, in the system:

- `id`
- `type` = `IP_ADDRESS`
- `value` = `203.0.113.42`

An entity on its own isn't malicious, neither does it have data associated with it corroborating that it is located in Seattle (for example).

## Data Sources

ATI integrates various types of data sources. Ultimately, all data sources are meant to be used to produce  `Evidence` (see next section regarding the concept of evidence).

### Live vs Batch Data Sources

A live data source (more precisely named `EvidenceProvider` within ATI) corresponds to an external API that is queried in the course of an investigation, or a RAG call made internally against ATI's vector database: it is called "on the fly", for a given `Entity`.

On the other hand, a batch data source is called out-of-band, outside of the execution of an investigation. An example is the MITRE ATT&CK data source, which is used to populate ATI's RAG database. 

> Note that, in theory, a batch data source could eventually have a live evidence provider peer: the batch data source could produce `Evidence` that is later queried by an `EvidenceProvider`. Such a case doesn't exist in the system, as of this writing. 

### Infrastructure vs Threat Intelligence

Infrastructure corresponds to internet resources such as IP addresses, domain names, and so on. Infrastructure data helps ATI answer questions of the sort: "What does this domain resolve to?", "What network contains this IP?", etc.

Threat intelligence data concerns maliciousness: "Has this IP adress been used to propagate malware?".

Infrastructure data on its own does not assess maliciousness.

## IOC

IOC stands for "Indicator of Compromise". It is an observable artifact that may indicate malicious activity or that a system has been compromised. Common IOC types include:

| IOC type | Example | What it might indicate |
|---|---|---|
| IP address | `203.0.113.42` | Known command-and-control or scanning infrastructure |
| Domain | `update-example.xyz` | Phishing, malware delivery, or C2 infrastructure |
| URL | `https://example.xyz/payload.exe` | Malware download location |
| File hash | SHA-256 hash | Known malicious executable |
| Email address | `attacker@example.com` | Phishing or threat-actor infrastructure |

For ATI, the distinction between an `IOC` and an `Entity` is important.

An ATI `Entity` such as:

```python
Entity(
    type=IP_ADDRESS,
    value="203.0.113.42"
)
```

does not mean the IP is an IOC. It merely means ATI knows about that IP address.

A data source like `ThreatFox` (see next section for a primer on data sources) might then provide evidence saying that the IP has been observed as malicious infrastructure:

```
Entity: 203.0.113.42
        │
        ▼
ThreatFox Evidence
        │
        └── reported as malware/C2 infrastructure
```

That evidence can support treating the entity as an IOC in the analytical sense. The next section delves deeper into the notion of evidence.

## Evidence

As mentioned earlier, data gathered from data sources is internally used to produce (and persist) `Evidence`. 

In ATI, evidence represents an intelligence record about an entity,
__at one point in time__. It is source-backed information about an entity such as a domain name or an IP address.

```
Evidence
├── id = <evidence UUID>
├── source = IPinfo Lite
├── type = NETWORK
└── source_record_id = ...


EvidenceObservation
├── id = <observation UUID>
├── evidence_id = <evidence UUID>
├── facts = { ... }
└── ...
```

The difference between `Evidence` and `EvidenceObservation` is as follows:

- `Evidence`: Represents the stable identity of a source intelligence record. `type`, `source`
   and `source_record_id` values are meant to be unique (both in ATI and at the source) and immutable.
- `EvidenceObservation`: the material state of that record observed at a particular point in time/version.

Furthermore, `Evidence` captures evidence type and identity; `EvidenceObservation` captures the state of an `Evidence` record at a given moment (hence the `evidence_id` on `EvidenceObservation`).

On the other hand, the connection between `Evidence`/`EvidenceObservation` and `Entity` is done through `EvidenceObservationEntity`, as shown below:

```
Entity
├── id = <IP entity UUID>
├── type = IP_ADDRESS
└── value = 203.0.113.42

EvidenceObservationEntity
├── evidence_observation_id = <observation UUID>
└── entity_id = <IP entity UUID>
```

For example, suppose this IP address and associated ASN obtained from `IPinfo`, respectively: `203.0.113.42` and `AS64500`. Using those, ATI produces two `Evidence` record with:

```
Entity                                      Entity
id    = IP-123                              id    = ASN-456
type  = IP_ADDRESS                          type  = ASN
value = 203.0.113.42                        value = AS64500
       ▲                                           ▲
       │ entity_id                                 │ entity_id
       │                                           │
EvidenceObservationEntity              EvidenceObservationEntity
       │                                           │
       │ evidence_observation_id                   │ evidence_observation_id
       │                                           │
       └──────────────────┐   ┌────────────────────┘
                          │   │
                          ▼   ▼
                  EvidenceObservation
                  id          = OBS-456
                  evidence_id = EVID-789
                  facts       = {
                                    "ip_address": "203.0.113.42",
                                    "asn": "AS64500"
                                }
                          │
                          │ evidence_id
                          ▼
                       Evidence
                  id               = EVID-789
                  source           = IPinfo Lite
                  type             = NETWORK
                  source_record_id = ...source_record_id = ...
```

## Relationship

On top of creating `Evidence` from facts provided by data sources, ATI also creates relationships, where those make sense in a CTI context. For example, given the `203.0.113.42` IP address, the Google DNS data source provides `evil.com` as the domain. ATI, in this case, creates a `Relationship` and `RelationshipObservation`, accordingly, on top of the `Evidence`/`EvidenceObservation` records that the data source provides.

Similarly to `Evidence`/`EvidenceObservation`, `Relationship` and `RelationshipObservation` reflect a current vs historical state:

```
Relationship
├── id               = REL-101
├── source_entity_id = DOMAIN-123
├── type             = RESOLVES_TO
└── target_entity_id = IP-456


RelationshipObservation
├── id                      = REL-OBS-201
├── relationship_id         = REL-101
├── evidence_observation_id = OBS-456
├── observed_at             = 2026-08-21T...
└── retrieved_at            = 2026-09-21T...
```

Note how `RelationshipObservation` as a `relationship_id` field. Furthermore, the `RelationshipObservation` points to an `EvidenceObservation` (through the `evidence_observation_id` field): that is because the `RelationshipObservation` stems from that `EvidenceObservation`: that evidence supports the assertion that `evil.example --RESOLVES_TO--> 203.0.113.42` (in other words, the evidence explains why the relationship exists).

Also, `observed_at` and `retrieved_at` are not the same thing:

- `observed_at`: When the relationship was observed, according to the data source.
- `retrieved_at`: When ATI retrieved that data.

Suppose ATI obtains successive Google DNS evidence data, on Monday, Tuesday and Friday: `evil.example 203.0.113.42`. This results in the following:

```
                         Relationship
                            REL-101
                               │
             evil.example RESOLVES_TO 203.0.113.42
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       RelationshipObs    RelationshipObs   RelationshipObs
          Monday             Tuesday            Friday
             │                  │                 │
             ▼                  ▼                 ▼
        DNS Evidence       DNS Evidence      DNS Evidence
        Observation        Observation       Observation
```


The relationship is supported by multiple observations (i.e.: `RelationshipObservation`), each backed by evidence (i.e.: `EvidenceObservation`).

As whole, here is a diagram illustrating how `Evidence` and `Relationship` relate:

```
Entity                                              Entity
id    = DOMAIN-123                                  id    = IP-456
type  = DOMAIN                                      type  = IP_ADDRESS
value = evil.example                                value = 203.0.113.42
       ▲                                                   ▲
       │ entity_id                                         │ entity_id
       │                                                   │
EvidenceObservationEntity                      EvidenceObservationEntity
       │                                                   │
  evidence_observation_id                        evidence_observation_id
       │                                                   │
       └──────────────────────┐   ┌────────────────────────┘
                              │   │
                              ▼   ▼
                      EvidenceObservation
                      id          = OBS-456
                      evidence_id = EVID-789
                      facts       = {
                                      "record_type": "A",
                                      "name": "evil.example",
                                      "address": "203.0.113.42"
                                    }
                              │
                              │ evidence_id
                              ▼
                           Evidence
                      id               = EVID-789
                      source           = Google Public DNS
                      type             = DNS
                      source_record_id = ...


Entity                                              Entity
DOMAIN-123                                          IP-456
evil.example                                        203.0.113.42
       │                                                   ▲
       │ source_entity_id                                  │ target_entity_id
       ▼                                                   │
┌─────────────────────────────────────────────────────────────┐
│ Relationship                                                │
│ id               = REL-101                                  │
│ source_entity_id = DOMAIN-123                               │
│ type             = RESOLVES_TO                              │
│ target_entity_id = IP-456                                   │
└──────────────────────────┬──────────────────────────────────┘
                           ▲
                           │ relationship_id
                           │
                 RelationshipObservation
                 id                      = REL-OBS-201
                 relationship_id         = REL-101
                 evidence_observation_id = OBS-456
                           │
                           │ evidence_observation_id
                           ▼
                  EvidenceObservation
                  id          = OBS-456
                  evidence_id = EVID-789
                           │
                           ▼
                       Evidence
                  id     = EVID-789
                  source = Google Public DNS
                  type   = DNS

```

The following diagram provides a higher-level view:

```
                       Evidence
                          │
                          │ 1:N
                          ▼
                 EvidenceObservation
                    OBS-456
                   /       \
                  /         \
     represents entities    supports relationship
                /             \
               ▼               ▼
 EvidenceObservationEntity   RelationshipObservation
        /          \                    │
       ▼            ▼                   ▼
    DOMAIN          IP              Relationship
 evil.example  203.0.113.42              │
       ▲            ▲                     │
       │            └─────────────────────┤ target
       │                                  │
       └──────────────────────────────────┘ source

              evil.example
                    │
                    │ RESOLVES_TO
                    ▼
              203.0.113.42
```

## Evidence and Relationship Extraction

Evidence and relationship data is "extracted" per-data source (either for batch or live ones). Evidence and relationship creation is entirely deterministic (it doesn't involve any agent): source-specific logic firt produces `Evidence`, associates to it the relevant `Entity` data, then proceeds to create `RelationshipAssertions`: The `Entity` and `RelationshipAssertion` data is passed downstream in an `ExtractionResult`, which is then used to create the `Relationship`/`RelationshipObservation` records:

```
Evidence Provider  / Batch Data Source
   │
   │ produces normalized evidence
   ▼
Evidence
+
EvidenceObservationCandidate
   │
   │ combined with the Entity
   │ against which provider was invoked
   ▼
EvidenceExtractionView
├── evidence
├── observation
└── invocation_entity
   │
   ▼
source-specific deterministic extractor
e.g. extract_dns()
   │
   ▼
ExtractionResult
├── entities[]
│     └── ExtractedEntity
│
└── relationships[]
      └── RelationshipAssertion
```

Note that `Evidence Provider` and `Batch Data Source`, in the above, are meant to represent what in ATI interacts sources of data (or "data sources"), in the generic sense. Logically, the system has the following layers:

- Evidence provider + Batch Data Source/converter: Creates Evidence.
- Extractor:
    - Discovers Entities.
    - Asserts Relationships.
- Persistence
    - Persists the Evidence observation.
    - Resolves/upserts Entities.
    - Resolves/upserts Relationships.
    - Creates RelationshipObservations.

The following presents a more schematized view of the above:
```
                 External intelligence
                         │
             ┌───────────┴────────────┐
             ▼                        ▼
     EvidenceProvider            Batch Datasource
  investigation-time             ingestion-time
             │                        │
             ▼                        ▼
       source records             source records
             │                        │
             └───────────┬────────────┘
                         ▼
               normalization /
                  conversion
                         │
                         ▼
              deterministic semantics
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
           Evidence    Entities   Relationships
```

## GEOINT

ATI leverages PostGIS for providing geospatial data. Relationships between "cyber entities" and geospatial entities are not hard-coded: rather, at analysis time, PostGIS's geospatial operators are used to resolve IP addresses to cities (for example).

### `Location` -- Canonical geography

A `Location` object represents a canonical, administrative geospatial entity. ATI keeps such entities separate from cyber entities (in short, there is no `Entity(type=LOCATION)`).

The following illustrate `Locations` that represent different administrative levels:

```
Location
├── Seattle
│   ├── kind = CITY
│   └── geometry = <PostGIS geometry>
│
├── Washington
│   ├── kind = REGION
│   └── geometry = <PostGIS geometry>
│
└── United States
    ├── kind = COUNTRY
    └── geometry = <PostGIS geometry>
```

Between `Location` records, Geographical containment is not hard-coded
(i.e.: it is not modeled as a self-referential foreign keys). Rather, it is resolved dynamically through PostGIS geospatial functions:

```
Seattle geometry
      │
      │ ST_Within(...)
      ▼
Washington geometry
      │
      │ ST_Within(...)
      ▼
United States geometry
```

There will NOT be such a `Relationship`: `Seattle --IS-WITHIN-->Washington`.

### `EntityLocation`

The geospatial relationship between `Entity` (say, IP address `203.0.113.2`) and `Location` (say, `Seattle`) is resolved asynchronously by a background task and kept in `EntityLocation`, which would yield, conceptually:

```
EntityLocation
├── entity_id   = IP-123
└── location_id = LOC-SEATTLE
```

The chosen `Location` is the most specific (from a geospatial-administrative standpoint) that could be resolved (int this case `Seattle` was picked even though `Washington` is also true).

Having `EntityLocation` makes it possible to find "all IPs in Bucarest that were linked to the Bayrob trojan" or to discover any geographical clusters associated to a certain attack campaign.

### `EntityLocationObservation`

In a manner similar to `Relationship` vs `RelationshipObservation`, `EntityLocationObservation` provides us with provenance or temporality.

GEOINT starts from evidence, as well (so, an `EntityLocationObservation` record should link to an `Evidence` one).

Suppose the `DB-IP` data source tells us: `203.0.113.42 → Seattle`, that constitutes evidence, from which we can infer a geospatial association. In summary:

```
DB-IP
  │
  ▼
Evidence
+
EvidenceObservation
  facts:
    city = Seattle
    region = Washington
    country = US
    latitude = ...
    longitude = ...
```

As mentioned earler, geospatial resolution is done asynchronously. The `EvidenceObservation` table has a `resolution_status` field, whose value is originally `pending`. The table below indicates the values that the field may take, besides `pending`, depending on the processing stage:

| Value          | Meaning                                                                              |
| -------------- | ------------------------------------------------------------------------------------ |
| `pending`      | Geographic enrichment is waiting to be processed.                                    |
| `processing`   | A worker has claimed and is processing it.                                           |
| `resolved`     | The claim was successfully resolved to a canonical `Location`.                       |
| `unresolvable` | ATI determined that the geographic claim cannot be resolved to a canonical location. |
| `failed`       | Resolution processing failed operationally.                                          |

To be more precise, `GeoResolution` corresponds to a queue table that is used to track the geo resolution state, for `EvidenceObservation` records.

### Parallel Organization

In summary, geography constitutes an organization that is parallel to the `Entity`/`Relationship` one.

What joins them are geospatial relationships, which are discovered through PostGIS' geospatial funtions:

```
                     ENTITY
                       │
          ┌────────────┴────────────┐
          │                         │
          │                         │
     threat graph              geography
          │                         │
          ▼                         ▼
   Relationship              EntityLocation
          │                         │
          ▼                         ▼
RelationshipObservation   EntityLocationObservation
          │                         │
          │ provenance              │ provenance
          ▼                         ▼
   EvidenceObservation ◄────────────┘
          │
          ▼
       Evidence


And:

EntityLocation
      │
      ▼
   Location
      │
      │ PostGIS spatial operations
      ▼
containing Locations
(city → region → country)
```

## Pivoting

Pivoting is done in the context of investigations. An investigation is initiated for a given `Entity`, such as a domain (e.g.: `evil.com`). Investigating that domain involves, among others, determining the IP address it resolves to (ultimately, this is done using ATI's knowledge graph: `evil.com --RESOLVES-TO --> 203.0.113.42`). Then, that IP address may in turn be investigated: it is "pivoted on", and becomes the current `Entity` under investigation.

As can be understood from the above, pivoting is, in essence, graph traversal, starting from a given root `Entity`.
