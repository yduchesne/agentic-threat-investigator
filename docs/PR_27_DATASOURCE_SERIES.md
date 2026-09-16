# PR 27 — Datasource Architecture Improvement Series

This document is the detailed roadmap-level decomposition for the datasource architecture work introduced after PR 26. It complements `DATASOURCE_ARCHITECTURE.md`; implementation-specific detailed PR plans must still be generated from fresh `main` and follow `DETAILED_PR_PLAN_AUTHORING_GUIDE.md`.

## Sequence

```text
PR 26G — GEOINT series closure [DONE]
  -> PR 27A — Datasource model and contracts
  -> PR 27B — Acquisition execution and correlated logging
  -> PR 27C — Acquisition-to-semantic boundary
  -> PR 27D — semantic_format-driven ToEvidenceConverter
  -> PR 27E — Existing-source migration and series closure
  -> PR 28 — Evaluation and release hardening (formerly PR 27)
```

## Series invariants

Across PR 27A-E:

- provider, protocol, serialization format, semantic format, and datasource instance are independent concepts;
- proprietary semantic formats receive stable ATI URNs, e.g. `urn:ati:datasource:semanticformat:threatfox`;
- semantic conversion is selected by `semantic_format`, never merely by provider/protocol/serialization;
- one acquisition execution has one UUID `execution_id` shared by its datasource log events;
- acquisition/serialization is separated from semantic interpretation and ATI Evidence construction;
- `ToEvidenceConverter` conversion cardinality is `0..N Evidence` per semantic source object;
- converters do not acquire, persist, orchestrate, assess maliciousness, or create unsupported relationships;
- existing source-specific validation, bounded I/O, safe-error, cancellation, secret, and provenance rules do not regress;
- batch and live sources may share architectural vocabulary without being forced into identical operational mechanics;
- RAG/reference corpus sources are not forced to produce Evidence;
- migration is incremental, but the end state does not retain two permanent competing Evidence-ingestion architectures;
- automated tests remain deterministic/offline and exercise production parsing/conversion paths;
- the generic evaluation/release-hardening work is PR 28, not PR 27.

## PR 27A — Datasource model and contracts

Establish the vocabulary and contracts first.

Deliver:

- explicit datasource/provider/protocol/serialization-format/semantic-format concepts reconciled with fresh `main`;
- stable semantic-format URNs;
- datasource configuration/domain contracts and fail-closed combination validation;
- explicit compatibility boundary for existing `EvidenceProvider` implementations;
- documentation and deterministic tests proving classification dimensions are independent;
- no wholesale source migration.

Examples:

```text
ThreatFox:
provider        = threatfox
protocol        = https
serialization   = json
semantic_format = urn:ati:datasource:semanticformat:threatfox

STIX 2.1 source:
semantic_format = urn:ati:datasource:semanticformat:stix21
```

The detailed plan must determine exact enum/model/config placement from fresh source. Do not introduce a universal external-data ontology.

## PR 27B — Acquisition execution and correlated logging

Make one datasource acquisition execution explicit operationally.

Deliver:

- fresh UUID `execution_id` for each datasource acquisition execution;
- same execution ID on all datasource-log events for that execution;
- explicit stage/lifecycle event vocabulary sufficient to distinguish acquisition, decoding/conversion, completion, and failure without logging source bodies;
- bounded safe counts/metadata where useful;
- deterministic success/failure/cancellation correlation tests;
- persistence/schema changes only if fresh-main analysis proves them necessary.

Do not introduce a durable execution table merely because an execution concept exists; first determine whether `execution_id` on the existing datasource log is sufficient.

## PR 27C — Acquisition-to-semantic boundary

Separate source acquisition and serialization from source semantics.

Deliver:

- semantic-format-specific source-object representation/validation;
- transport/serialization code that yields semantic source objects rather than ATI Evidence on the target path;
- explicit stage-specific error boundaries;
- preservation of source identity, observation/retrieval timing, safe source references, and artifact context required for later provenance;
- deterministic source-format fixtures using real production contracts;
- no universal mega-schema;
- no Evidence conversion registry yet unless required as a narrow seam for the next PR.

A source semantic object is still untrusted external data until its semantic contract has been validated.

## PR 27D — Semantic-format-driven `ToEvidenceConverter`

Introduce the conversion boundary.

Conceptual contract:

```python
class ToEvidenceConverter(ABC):
    def convert(self, source: SourceObject) -> Sequence[Evidence]:
        ...
```

Deliver:

- `ToEvidenceConverter` abstraction reconciled with existing ATI ABC conventions;
- converter selection/registry keyed by `semantic_format`;
- semantic-format-specific implementations, including a proprietary-format reference implementation such as ThreatFox;
- explicit zero-, one-, and multiple-Evidence conversion tests;
- exact Evidence provenance;
- deterministic conversion with no network I/O;
- no persistence ownership in converter;
- no Investigation orchestration/verdict/attribution ownership in converter.

Do not key converter selection on provider, protocol, MIME type, filename, or JSON shape.

## PR 27E — Existing-source migration and closure

Migrate the existing Evidence-producing source integrations after the architecture is stable.

For each applicable source, the target path is:

```text
configured datasource
 -> acquisition execution
 -> transport/local artifact
 -> serialization decode
 -> semantic source object(s)
 -> semantic-format-selected ToEvidenceConverter
 -> 0..N Evidence
 -> existing Evidence persistence/extraction/Investigation behavior
```

Deliver:

- migration of existing Evidence-producing providers/sources to the target architecture;
- ThreatFox as a reference proprietary semantic format proving the design is not STIX-centric;
- preservation of source-specific security/validation behavior;
- deterministic vertical slices covering execution logging through persisted Evidence and normal Investigation consumption;
- compatibility/regression tests for existing extraction and persistence behavior;
- removal of obsolete compatibility seams only after equivalent coverage exists;
- final source/test compliance audit of 27A-D;
- documentation reconciliation and series closure.

## PR 28 — Evaluation and release hardening

PR 28 is the work formerly numbered PR 27. It expands ATI to curated scenarios, deterministic invariants, agent evaluations, end-to-end trajectory evaluation, adversarial content, canonical malicious-domain/IP/malware trajectories, release gates, stability, performance/cost/latency reporting, licensing/source-term checks, and release documentation.

PR 27 should leave reusable deterministic datasource fixtures and invariants for PR 28, but must not implement PR 28's generic evaluator/release platform.

## Detailed-plan rule

Before each PR 27A-E is implemented, generate a separate coding-agent-ready detailed plan from fresh `main` following `docs/DETAILED_PR_PLAN_AUTHORING_GUIDE.md` at minimum. The detailed plan must inventory the actual current datasource/provider implementation, identify reuse and compatibility seams, name concrete files/functions after fresh inspection, define deterministic test matrices, and include STOP conditions for architecture drift.
