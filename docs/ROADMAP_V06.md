# ATI — v0.6 Roadmap

> **Planning status — PROPOSED TARGET / PR 32–33 SERIES**
>
> This document is authoritative for the planned ATI v0.6 MISP, STIX 2.1,
> and TAXII 2.1 datasource-integration series. The v0.5 graph-exploration
> series is preserved in `ROADMAP_V05.md`.

## Purpose

ATI v0.6 expands the datasource architecture delivered by PR 27/28 with two
widely used CTI integration paths:

1. native MISP REST/API ingestion using MISP's own semantic model; and
2. reusable STIX 2.1 Evidence semantics followed by TAXII 2.1 acquisition.

The series preserves ATI's existing separation of provider, datasource
instance, protocol, serialization format, and semantic format. Acquisition
retrieves and decodes source material; semantic adapters validate source-native
objects; `ToEvidenceConverter` implementations convert supported source
semantics into zero or more ATI `ConvertedEvidence` values; the existing
Evidence/extraction/persistence architecture remains authoritative.

The series must also follow ATI's bounded asynchronous-I/O principle:
independent I/O is executed concurrently where doing so preserves semantics,
with explicit bounds and without violating ordering, transaction, lease,
checkpoint, rate-limit, budget, or orchestration invariants.

## Ordering decision

MISP is implemented before TAXII.

This is intentional. Native MISP support can exercise ATI's existing
semantic-format-driven conversion architecture with relatively direct IOC
mappings before ATI expands its general CTI semantics. TAXII is primarily an
acquisition protocol for STIX content; useful TAXII support therefore follows
the reusable STIX 2.1 semantic/conversion work rather than embedding STIX
interpretation inside a TAXII adapter.

The target progression is:

```text
PR 32 — native MISP
        |
        | proves another native semantic format
        v
PR 33A-D — reusable STIX/CTI semantics
        |
        v
PR 33E — TAXII 2.1 acquisition
```

MISP and TAXII must not introduce parallel Evidence persistence,
relationship-persistence, investigation-orchestration, or datasource lifecycle
architectures.

## Series decomposition

| PR | Scope | Principal result |
|---|---|---|
| **32A** | MISP semantic model and parser | Validated, immutable MISP semantic records with exact source/Event context and no Evidence construction |
| **32B** | MISP-to-Evidence conversion | Native MISP semantic-format registration and deterministic IOC-focused `MispToEvidenceConverter` |
| **32C** | MISP acquisition | Bounded MISP REST acquisition, authentication, pagination/filtering, safe errors, provenance, and deterministic fake boundary |
| **32D** | MISP runtime integration and closure | Production composition, datasource lifecycle, real-stack vertical slices, documentation, and source audit |
| **33A** | STIX 2.1 semantic refactoring | Reusable single-object STIX validation independent of Bundle/TAXII envelopes; explicit ATI STIX Evidence profile |
| **33B** | STIX IOC Evidence conversion | `Stix21ToEvidenceConverter` for supported SCOs and bounded Indicator-pattern semantics |
| **33C** | Source-neutral CTI Entity expansion | Selected CTI Entity types required for useful STIX/MISP intelligence and graph exploration |
| **33D** | Source-asserted relationships and STIX sightings | Evidence-backed deterministic relationship assertions and STIX Relationship/Sighting mappings without direct converter persistence |
| **33E** | TAXII 2.1 acquisition and runtime integration | TAXII discovery/collections/envelopes/pagination/incremental retrieval feeding the reusable STIX 2.1 pipeline |

## Cross-series architectural invariants

The following rules apply to every PR in v0.6:

- acquisition and semantic conversion remain separate;
- converter selection is based only on `semantic_format`, never provider,
  protocol, endpoint, or object shape;
- one semantic source object may produce zero, one, or multiple
  `ConvertedEvidence` values;
- valid but unsupported source semantics may deterministically produce zero
  Evidence; unsupported is not equivalent to malformed;
- converters are deterministic and perform no network I/O, persistence,
  orchestration, pivot selection, verdict assignment, or unrestricted
  relationship mutation;
- exact source identity, source observation/version information, retrieval
  provenance, and applicable handling/distribution metadata are preserved;
- source restrictions such as MISP distribution/sharing metadata and STIX
  markings are not silently discarded; preservation does not imply policy
  enforcement unless ATI explicitly implements it;
- source assertions become ATI Relationships only through the existing
  Evidence-backed deterministic extraction/persistence boundary;
- `RelationshipObservation` remains immutable temporal/provenance evidence;
  source timestamps never imply unsupported relationship lifetime semantics;
- datasource lifecycle logging remains operational metadata, not Evidence,
  checkpoint state, or a distributed transaction;
- secrets use the existing `SecretsResolver` composition boundary and are
  never logged or persisted in source references;
- automated tests use ATI-authored deterministic fixtures/fakes and require no
  live MISP or TAXII service;
- real persistence/runtime behavior is proven through the repository's normal
  PostgreSQL/Redpanda integration infrastructure where applicable;
- independent I/O must be evaluated for bounded structured concurrency, while
  semantically ordered work remains sequential.

# PR 32 series — Native MISP integration

## PR 32A — MISP semantic model and parser `[DONE]`

Delivered: durable `SourceId.MISP = urn:ati:source:misp` and
`SemanticFormatId.MISP = urn:ati:datasource:semanticformat:misp`;
`infrastructure/datasources/misp_semantics.py` parses one decoded native
MISP `{"Event": {...}}` envelope into immutable `MispAttributeRecord` /
`MispObjectRecord` records (Event context, Attributes, Objects with nested
Attributes/ObjectReferences, tags, strict UTC timestamps, `deleted`,
distribution/sharing-group state preserved; UUID is upstream identity;
malformed modeled content fails closed with a bounded
`SEMANTIC_VALIDATION` error and zero records); synthetic ATI-authored
fixtures and the deterministic M32A-01..50 matrix; docs. No acquisition,
Evidence conversion (PR 32B), or runtime composition (PR 32C/32D).

Original planning description: introduce the MISP semantic-format identity
and the smallest typed, immutable semantic representation required by ATI.
Preserve MISP source data needed for exact provenance while validating the
fields ATI consumes.

The parser should flatten an acquired MISP Event response into bounded semantic
records suitable for independent conversion rather than requiring one giant
Event conversion. Candidate records include Attribute- and Object-oriented
records carrying the enclosing Event identity/context required for provenance,
tags, timestamps, and applicable distribution/sharing metadata.

Do not construct ATI Evidence in the parser. Do not attempt to model every
MISP schema field as a first-class ATI type. Unsupported valid constructs must
remain distinguishable from malformed source data.

Initial semantic coverage should prioritize common IOC-bearing Attributes,
including domain/hostname, IPv4/IPv6 source/destination forms, and compound
forms such as `domain|ip`. File/hash, URL, certificate, Galaxy, and richer
Object semantics may be added only where the detailed plan can map them to
existing approved ATI concepts without inventing ontology.

## PR 32B — MISP-to-Evidence conversion

Add `MispToEvidenceConverter`, registered exclusively under the MISP semantic
format. Convert the approved PR 32A semantic records into deterministic global
Evidence with exact MISP/Event/record provenance.

The initial vertical slice is IOC-focused:

- domain/hostname -> supported DOMAIN semantics;
- IP source/destination forms -> supported IP semantics;
- approved compound attributes -> zero-to-many Evidence in deterministic
  source order;
- valid unsupported Attribute/Object types -> zero Evidence;
- malformed required semantics -> bounded typed conversion failure.

MISP Event metadata, tags, timestamps, and preserved distribution/sharing
metadata remain source facts/provenance. The converter must not assign
maliciousness, directly persist Entities/Relationships, or infer semantics
from arbitrary MISP type names.

## PR 32C — MISP acquisition

Implement native MISP REST/API acquisition behind ATI's existing datasource
acquisition boundary. Cover endpoint/configuration composition,
`SecretsResolver`-supplied credentials, bounded request/response handling,
pagination or bounded result windows, typed safe errors, cancellation, and
credential-free source references.

Where independent page/detail requests are semantically independent, evaluate
and use bounded structured async I/O according to `ARCHITECTURE.md`; reuse an
existing authoritative HTTP/rate limiter when applicable rather than stacking
unrelated concurrency controls. Ordering required for deterministic conversion,
checkpointing, or source pagination semantics must remain explicit.

Automated tests use deterministic ATI-authored MISP response fixtures and fake
the external HTTP boundary only. No ordinary test contacts a live MISP server.

## PR 32D — MISP runtime integration and closure

Compose the MISP datasource through the existing datasource runtime and
converter registry, preserving the PR 27/28 lifecycle and Evidence
publication/persistence boundaries. Add real-stack vertical slices proving
semantic acquisition -> conversion -> Evidence pipeline behavior and exact
provenance without introducing a MISP-specific persistence path.

Reconcile configuration documentation, datasource architecture/source audit,
testing documentation, and v0.6 roadmap status. The closure PR must state
exactly which MISP constructs are supported, preserved-but-not-interpreted,
and unsupported.

# PR 33 series — STIX 2.1 and TAXII 2.1

## PR 33A — Reusable STIX 2.1 semantic refactoring

Refactor the existing STIX 2.1 semantic parser so individual STIX objects can
be validated independently of a STIX Bundle envelope. Introduce a reusable
single-object validation seam conceptually equivalent to
`parse_stix21_object()`; keep `parse_stix21_bundle()` as an envelope adapter
over that same object contract.

Preserve the existing lossless `Stix21Object` behavior: validate only the
approved common contract while retaining extension/custom fields as immutable
source data. Do not replace it with a universal Pydantic model of the entire
STIX specification.

Define and document an explicit ATI STIX 2.1 Evidence Profile distinguishing:

- valid STIX;
- ATI-supported Evidence-producing STIX;
- valid but currently unsupported STIX;
- malformed STIX.

This PR is semantic refactoring only and must preserve existing MITRE ATT&CK
corpus behavior.

## PR 33B — STIX IOC Evidence conversion

Add `Stix21ToEvidenceConverter`, registered under the STIX 2.1 semantic
format independently of TAXII.

Initial support should include approved IOC-oriented Cyber-observable Objects
that map to existing ATI Entity semantics, starting with domain names and
IPv4/IPv6 addresses. Add bounded STIX Indicator-pattern interpretation for the
approved observable/value forms.

Use a standards-compliant STIX pattern parser/AST if a maintained dependency
satisfies ATI's security/licensing requirements; do not implement STIX
patterning with regular expressions. ATI interprets only an explicit whitelist
of pattern constructs/operators. Valid unsupported patterns produce zero
Evidence or another explicitly documented unsupported disposition; they are
never guessed.

Preserve STIX object identity and version information so repeated versions of
one logical STIX object do not lose source provenance.

## PR 33C — Source-neutral CTI Entity expansion

Add the smallest source-neutral CTI Entity vocabulary justified by the
supported intelligence workflows. Candidate types include MALWARE,
THREAT_ACTOR, CAMPAIGN, INTRUSION_SET, TOOL, VULNERABILITY, ATTACK_PATTERN,
and INFRASTRUCTURE.

This is an ATI domain expansion, not a STIX-specific mirror of every SDO.
Each admitted Entity type must have explicit canonicalization, display,
query/graph, extraction, pivot/researchability, persistence, API/frontend, and
test semantics where those surfaces apply.

MISP may reuse these types in later enrichment without gaining a parallel MISP
ontology.

## PR 33D — Source-asserted relationships and STIX sightings

Introduce source-neutral deterministic handling for external intelligence that
asserts relationships, then map supported STIX Relationship and Sighting
objects through that mechanism.

A STIX converter preserves the source assertion as Evidence facts; the
existing deterministic extraction/application persistence boundary owns
canonical ATI Relationship and immutable RelationshipObservation creation.
Do not create a `StixRelationshipPersistenceService` or permit converters to
write graph state directly.

Preserve `observed_at`, source first/last-seen fields, retrieval time, and
source assertion timestamps as distinct concepts. Never infer relationship
start/end or continuous validity from isolated source observations.

The source-neutral assertion seam should be reusable by MISP Object References
when/if their richer relationship semantics are enabled.

## PR 33E — TAXII 2.1 acquisition and runtime integration

Implement TAXII 2.1 as an acquisition/protocol integration that feeds the
existing STIX 2.1 semantic pipeline.

Support the bounded subset required for production-quality collection
ingestion: server/API-root discovery as needed by ATI configuration,
collection selection, TAXII envelopes, authentication, pagination, supported
server filtering, incremental retrieval (including `added_after` where
applicable), typed safe errors, cancellation, datasource lifecycle/provenance,
and production composition.

A TAXII envelope is not rewritten into a fake STIX Bundle. The TAXII adapter
validates its own envelope and passes each contained STIX object through the
PR 33A single-object STIX semantic boundary.

Apply bounded structured async I/O only where TAXII operations are independent.
Pagination/incremental checkpoint semantics that depend on previous responses
remain ordered. Reuse subsystem-owned HTTP concurrency/rate limiting rather
than introducing competing limiters.

Add deterministic fake TAXII fixtures/server-boundary behavior plus real ATI
runtime/persistence vertical slices. Automated tests must not require a live
public TAXII service.

## Deferred beyond v0.6

The following are not implied by this roadmap and require separate approval:

- exhaustive support for every MISP Attribute/Object/Galaxy construct;
- full MISP distribution-policy enforcement;
- exhaustive STIX 2.1 SDO/SCO/SRO coverage;
- a home-grown STIX Patterning implementation;
- arbitrary custom STIX relationship semantics without an explicit ATI
  mapping;
- STIX marking-policy enforcement beyond preservation;
- TAXII server implementation (ATI is a TAXII client/consumer here);
- unbounded TAXII collection mirroring;
- replacement of PostgreSQL with a graph database;
- MISP/TAXII-specific Evidence persistence paths;
- changes to Coordinator investigative decision semantics merely to ingest a
  datasource.

## v0.6 completion criteria

v0.6 is complete when:

1. MISP is a production-composed datasource using its native semantic format
   and the standard ATI Evidence pipeline.
2. The supported MISP Evidence profile is explicit, deterministic, and proven
   without live external services.
3. STIX individual-object validation is reusable independently of Bundle and
   TAXII envelopes while existing MITRE behavior remains compatible.
4. STIX 2.1 has a registered Evidence converter with an explicit supported
   profile and deterministic unsupported-object behavior.
5. Approved CTI Entity and source-asserted relationship semantics are
   source-neutral rather than STIX/MISP persistence special cases.
6. TAXII 2.1 acquisition feeds the reusable STIX semantic/conversion pipeline
   without fabricating STIX Bundle envelopes.
7. MISP/TAXII authentication and source references preserve ATI's secrets and
   safe-error rules.
8. Independent I/O uses bounded concurrency where semantically appropriate,
   and ordered/transactional/checkpointed work remains sequential.
9. Unit tests are deterministic and ordinary CI requires no live MISP/TAXII
   endpoints or API keys.
10. Applicable real PostgreSQL/Redpanda integration gates and the repository
    canonical quality/security gates pass.
11. Architecture, configuration, testing, datasource/source-audit, and roadmap
    documentation accurately describe the delivered behavior and limitations.
