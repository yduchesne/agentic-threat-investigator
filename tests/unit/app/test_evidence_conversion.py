# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27D generic evidence-conversion contract tests.

Stable matrix IDs D27D-C01..C10 pin the immutable conversion context, the
0..N cardinality of the ``ToEvidenceConverter`` contract, deterministic
flattening order, structural repeatability, and deterministic local
conversion failures. Matrix IDs D27D-R01..R10 pin the semantic-format
registry: keyed selection by ``SemanticFormatId`` only, duplicate
registration failing closed, typeless lookup failures for unknown formats,
and no fallback on provider/protocol/serialization/datasource/shape.
Test-only converters are used for formats without production converters;
no database, network, or persistence is involved.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from agentic_threat_investigator.app.datasource_semantics import (
    SemanticSourceContext,
)
from agentic_threat_investigator.app.evidence_conversion import (
    ConversionError,
    DuplicateConverterError,
    EvidenceConversionContext,
    ToEvidenceConverter,
    ToEvidenceConverterRegistry,
    UnknownSemanticFormatError,
    convert_semantic_source_objects,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.evidence import (
    EntityRef,
    Evidence,
    EvidenceType,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)

pytestmark = pytest.mark.unit

_FIXED_TS = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
_INVESTIGATION_ID = UUID("11111111-2222-3333-4444-555555555555")
_SUBJECT = EntityRef(type=EntityType.DOMAIN, value="malicious-domain.test")

_THREATFOX_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("threatfox-live"),
    source_id=SourceId.THREATFOX,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.THREATFOX,
)


def _context(
    *,
    semantic_format: SemanticFormatId = SemanticFormatId.THREATFOX,
    source_id: SourceId = SourceId.THREATFOX,
    datasource_id: DatasourceId | None = None,
) -> EvidenceConversionContext:
    """Build one deterministic conversion context with adjustable identities."""
    if datasource_id is None:
        datasource_id = DatasourceId("threatfox-live")
    semantic = SemanticSourceContext(
        datasource_id=datasource_id,
        source_id=source_id,
        semantic_format=semantic_format,
        retrieved_at=_FIXED_TS,
        source_reference="https://threatfox-api.abuse.ch/api/v1/",
    )
    return EvidenceConversionContext(
        investigation_id=_INVESTIGATION_ID,
        subject=_SUBJECT,
        semantic_source=semantic,
    )


def _evidence(
    context: EvidenceConversionContext, *, seq: str | None = None
) -> Evidence:
    """Build one deterministic Evidence observation from a conversion context."""
    facts: dict[str, object] = {}
    if seq is not None:
        facts["seq"] = seq
    return Evidence(
        investigation_id=context.investigation_id,
        type=EvidenceType.THREAT_INTELLIGENCE,
        subject=context.subject,
        source=context.semantic_source.source_id.value,
        retrieved_at=context.semantic_source.retrieved_at,
        facts=facts,
    )


class _CardinalityConverter(ToEvidenceConverter[str]):
    """Test-only converter emitting a fixed number of Evidence per object.

    Proves the 0..N contract without distorting a production semantic
    format (the plan's cardinality proof uses test-only converters).
    """

    def __init__(self, semantic_format: SemanticFormatId, *, count: int) -> None:
        """Bind the converter to one semantic format and one cardinality."""
        self._semantic_format = semantic_format
        self._count = count

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Return the bound test semantic format."""
        return self._semantic_format

    def convert(
        self, source: str, context: EvidenceConversionContext
    ) -> tuple[Evidence, ...]:
        """Emit exactly ``count`` deterministic Evidence in fixed order."""
        return tuple(
            _evidence(context, seq=f"{source}-{index}") for index in range(self._count)
        )


class _FailingConverter(ToEvidenceConverter[str]):
    """Test-only converter that always fails deterministically at conversion."""

    @property
    def semantic_format(self) -> SemanticFormatId:
        """Return the claimed semantic format."""
        return SemanticFormatId.THREATFOX

    def convert(
        self, source: str, context: EvidenceConversionContext
    ) -> tuple[Evidence, ...]:
        """Raise the typed deterministic conversion failure."""
        raise ConversionError("deterministic local conversion failure")


class TestEvidenceConversionContext:
    """D27D-C01..C04: immutable context and exact identity preservation."""

    def test_c01_valid_immutable_context_accepted(self) -> None:
        """D27D-C01: a valid conversion context is accepted and immutable."""
        context = _context()
        assert context.investigation_id == _INVESTIGATION_ID
        assert context.subject == _SUBJECT
        assert context.semantic_source.semantic_format is SemanticFormatId.THREATFOX
        with pytest.raises(Exception):  # noqa: B017 - dataclasses raises FrozenInstanceError
            context.investigation_id = UUID(int=0)  # type: ignore[misc]

    def test_c02_investigation_uuid_exact_preservation(self) -> None:
        """D27D-C02: the Investigation UUID is preserved exactly by conversion."""
        context = _context()
        (evidence,) = _CardinalityConverter(
            SemanticFormatId.THREATFOX, count=1
        ).convert("source-a", context)
        assert evidence.investigation_id == _INVESTIGATION_ID

    def test_c03_subject_exact_preservation(self) -> None:
        """D27D-C03: the canonical subject binding is preserved exactly."""
        context = _context()
        (evidence,) = _CardinalityConverter(
            SemanticFormatId.THREATFOX, count=1
        ).convert("source-a", context)
        assert evidence.subject == _SUBJECT

    def test_c04_semantic_context_exact_preservation(self) -> None:
        """D27D-C04: semantic source URN and retrieval time are preserved."""
        context = _context()
        (evidence,) = _CardinalityConverter(
            SemanticFormatId.THREATFOX, count=1
        ).convert("source-a", context)
        assert evidence.source == SourceId.THREATFOX.value
        assert evidence.retrieved_at == _FIXED_TS
        assert evidence.observed_at is None


class TestCardinality:
    """D27D-C05..C09: zero/one/many and deterministic flattening."""

    def test_c05_zero_evidence_legal_success(self) -> None:
        """D27D-C05: a valid object may yield zero Evidence."""
        context = _context()
        output = _CardinalityConverter(SemanticFormatId.THREATFOX, count=0).convert(
            "source-a", context
        )
        assert output == ()

    def test_c06_one_evidence_legal_success(self) -> None:
        """D27D-C06: a valid object may yield exactly one Evidence."""
        context = _context()
        output = _CardinalityConverter(SemanticFormatId.THREATFOX, count=1).convert(
            "source-a", context
        )
        assert len(output) == 1
        assert output[0].facts == {"seq": "source-a-0"}

    def test_c07_multiple_evidence_legal_success(self) -> None:
        """D27D-C07: a valid object may yield multiple Evidence observations."""
        context = _context()
        output = _CardinalityConverter(SemanticFormatId.THREATFOX, count=2).convert(
            "source-a", context
        )
        assert len(output) == 2
        assert [item.facts for item in output] == [
            {"seq": "source-a-0"},
            {"seq": "source-a-1"},
        ]

    def test_c08_multiple_objects_deterministic_flatten_order(self) -> None:
        """D27D-C08: flattening preserves source order and converter order.

        ``convert_semantic_source_objects`` must preserve semantic
        source-object order first, then each converter's return order,
        without sorting or deduplication.
        """
        context = _context()
        registry = ToEvidenceConverterRegistry(
            (_CardinalityConverter(SemanticFormatId.THREATFOX, count=2),)
        )
        output = convert_semantic_source_objects(
            ("source-a", "source-b", "source-c"), context, registry
        )
        assert [item.facts for item in output] == [
            {"seq": "source-a-0"},
            {"seq": "source-a-1"},
            {"seq": "source-b-0"},
            {"seq": "source-b-1"},
            {"seq": "source-c-0"},
            {"seq": "source-c-1"},
        ]

    def test_c09_repeat_same_conversion_structurally_equal(self) -> None:
        """D27D-C09: repeating the same conversion yields equal output."""
        context = _context()
        converter = _CardinalityConverter(SemanticFormatId.THREATFOX, count=2)
        first = converter.convert("source-a", context)
        second = converter.convert("source-a", context)
        assert first == second
        assert all(item.id is None for item in first)

    def test_c10_conversion_failure_deterministic_local(self) -> None:
        """D27D-C10: a converter violation fails locally and typed."""
        context = _context()
        with pytest.raises(ConversionError, match="deterministic local"):
            _FailingConverter().convert("source-a", context)


class TestRegistry:
    """D27D-R01..R10: semantic-format-only selection and fail-closed lookup."""

    def test_r01_threatfox_registered_lookup_succeeds(self) -> None:
        """D27D-R01: a registered THREATFOX converter is returned."""
        registry = ToEvidenceConverterRegistry(
            (_CardinalityConverter(SemanticFormatId.THREATFOX, count=1),)
        )
        converter = registry.get(SemanticFormatId.THREATFOX)
        assert converter.semantic_format is SemanticFormatId.THREATFOX

    def test_r02_unregistered_format_typed_failure(self) -> None:
        """D27D-R02: an unregistered semantic format fails typed lookup."""
        registry = ToEvidenceConverterRegistry(
            (_CardinalityConverter(SemanticFormatId.THREATFOX, count=1),)
        )
        with pytest.raises(UnknownSemanticFormatError):
            registry.get(SemanticFormatId.STIX_21)

    def test_r03_duplicate_key_fails_construction(self) -> None:
        """D27D-R03: a duplicate semantic key fails closed at construction."""
        with pytest.raises(DuplicateConverterError):
            ToEvidenceConverterRegistry(
                (
                    _CardinalityConverter(SemanticFormatId.THREATFOX, count=1),
                    _CardinalityConverter(SemanticFormatId.THREATFOX, count=2),
                )
            )

    def test_r04_two_formats_independent_deterministic_lookup(self) -> None:
        """D27D-R04: two formats resolve to independent converters."""
        threatfox = _CardinalityConverter(SemanticFormatId.THREATFOX, count=1)
        stix = _CardinalityConverter(SemanticFormatId.STIX_21, count=2)
        registry = ToEvidenceConverterRegistry((threatfox, stix))
        assert registry.get(SemanticFormatId.THREATFOX) is threatfox
        assert registry.get(SemanticFormatId.STIX_21) is stix

    def test_r05_source_id_changes_do_not_select(self) -> None:
        """D27D-R05: SourceId never selects; only the semantic format does."""
        registry = ToEvidenceConverterRegistry(
            (_CardinalityConverter(SemanticFormatId.THREATFOX, count=1),)
        )
        for source_id in (SourceId.THREATFOX, SourceId.URLHAUS, SourceId.RDAP):
            context = _context(source_id=source_id)
            assert registry.get(
                context.semantic_source.semantic_format
            ) is registry.get(SemanticFormatId.THREATFOX)

    def test_r06_protocol_changes_do_not_select(self) -> None:
        """D27D-R06: protocol never selects a converter."""
        registry = ToEvidenceConverterRegistry(
            (_CardinalityConverter(SemanticFormatId.THREATFOX, count=1),)
        )
        for protocol in (DatasourceProtocol.HTTPS, DatasourceProtocol.FILE):
            definition = DatasourceDefinition(
                datasource_id=DatasourceId("threatfox-live"),
                source_id=SourceId.THREATFOX,
                protocol=protocol,
                serialization_format=SerializationFormat.JSON,
                semantic_format=SemanticFormatId.THREATFOX,
            )
            semantic = SemanticSourceContext.from_definition(
                definition, retrieved_at=_FIXED_TS
            )
            assert registry.get(semantic.semantic_format) is registry.get(
                SemanticFormatId.THREATFOX
            )

    def test_r07_serialization_changes_do_not_select(self) -> None:
        """D27D-R07: serialization format never selects a converter."""
        registry = ToEvidenceConverterRegistry(
            (_CardinalityConverter(SemanticFormatId.THREATFOX, count=1),)
        )
        # Serialization has one vocabulary value in v0.1; a second definition
        # with the same semantic format still resolves identically.
        definition = DatasourceDefinition(
            datasource_id=DatasourceId("threatfox-live"),
            source_id=SourceId.THREATFOX,
            protocol=DatasourceProtocol.HTTPS,
            serialization_format=SerializationFormat.JSON,
            semantic_format=SemanticFormatId.THREATFOX,
        )
        semantic = SemanticSourceContext.from_definition(
            definition, retrieved_at=_FIXED_TS
        )
        assert registry.get(semantic.semantic_format) is registry.get(
            SemanticFormatId.THREATFOX
        )

    def test_r08_datasource_id_changes_do_not_select(self) -> None:
        """D27D-R08: the datasource instance never selects a converter."""
        registry = ToEvidenceConverterRegistry(
            (_CardinalityConverter(SemanticFormatId.THREATFOX, count=1),)
        )
        for datasource_id in (
            DatasourceId("threatfox-live"),
            DatasourceId("threatfox-mirror"),
        ):
            context = _context(datasource_id=datasource_id)
            assert registry.get(
                context.semantic_source.semantic_format
            ) is registry.get(SemanticFormatId.THREATFOX)

    def test_r09_misleading_object_shape_no_fallback(self) -> None:
        """D27D-R09: a misleading object shape never triggers a fallback.

        A converter is registered for THREATFOX; a context whose semantic
        format is STIX_21 must fail the typed lookup rather than select a
        converter by shape.
        """
        registry = ToEvidenceConverterRegistry(
            (_CardinalityConverter(SemanticFormatId.THREATFOX, count=1),)
        )
        context = _context(semantic_format=SemanticFormatId.STIX_21)
        with pytest.raises(UnknownSemanticFormatError):
            convert_semantic_source_objects(("source-a",), context, registry)

    def test_r10_wrong_object_for_selected_converter_fails_closed(self) -> None:
        """D27D-R10: a wrong object type for the selected converter fails closed."""
        from agentic_threat_investigator.infrastructure.datasources import (
            threatfox_evidence,
        )

        registry = ToEvidenceConverterRegistry(
            (threatfox_evidence.ThreatFoxToEvidenceConverter(),)
        )
        assert registry.get(SemanticFormatId.THREATFOX).semantic_format is (
            SemanticFormatId.THREATFOX
        )
        # The registry lookup erases the generic; the concrete converter's
        # fail-closed runtime guard rejects the wrong object regardless.
        with pytest.raises(ConversionError):
            threatfox_evidence.ThreatFoxToEvidenceConverter().convert(
                "definitely-not-a-record",  # type: ignore[arg-type]
                _context(),
            )
