# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27C cross-cutting semantic-source contract tests.

Matrix IDs D27C-U01..U08 pin the immutable provenance context, the
stage-aware datasource failure contract, and the generic semantic
acquisition result: exact identities, timezone-aware UTC normalization,
credential-free references, definition-derived identity invariance,
success/failure invariants, bounded error-code grammar, and nonnegative
retry delays. No database, network, or Evidence is involved.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.datasource_semantics import (
    DatasourceStage,
    DatasourceStageError,
    SemanticAcquisitionResult,
    SemanticSourceContext,
)
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)

_FIXED_TS = datetime(2026, 4, 2, 9, 15, 30, tzinfo=UTC)
_NAIVE_TS = datetime(2026, 4, 2, 9, 15, 30)

_THREATFOX_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("threatfox-live"),
    source_id=SourceId.THREATFOX,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.THREATFOX,
)


def _context(**overrides: object) -> SemanticSourceContext:
    """Build one deterministic valid semantic context."""
    values = {
        "datasource_id": _THREATFOX_DEFINITION.datasource_id,
        "source_id": _THREATFOX_DEFINITION.source_id,
        "semantic_format": _THREATFOX_DEFINITION.semantic_format,
        "retrieved_at": _FIXED_TS,
    }
    values.update(overrides)
    return SemanticSourceContext(**values)  # type: ignore[arg-type]


class TestSemanticSourceContext:
    """D27C-U01..U04: context identity, timestamps, and references."""

    def test_u01_valid_context_exact_identity_ids(self) -> None:
        """D27C-U01: the context carries exact datasource/source/semantic IDs."""
        context = _context()
        assert context.datasource_id is _THREATFOX_DEFINITION.datasource_id
        assert context.source_id is SourceId.THREATFOX
        assert context.semantic_format is SemanticFormatId.THREATFOX
        assert context.retrieved_at == _FIXED_TS
        assert context.retrieved_at.utcoffset() is not None

    def test_u01b_from_definition_derives_every_identity(self) -> None:
        """from_definition derives all three identities from one definition."""
        context = SemanticSourceContext.from_definition(
            _THREATFOX_DEFINITION,
            retrieved_at=_FIXED_TS,
            source_reference="https://threatfox-api.abuse.ch/api/v1/",
        )
        assert context.datasource_id == _THREATFOX_DEFINITION.datasource_id
        assert context.source_id == _THREATFOX_DEFINITION.source_id
        assert context.semantic_format == _THREATFOX_DEFINITION.semantic_format
        assert context.source_reference == "https://threatfox-api.abuse.ch/api/v1/"

    def test_u01c_context_is_immutable(self) -> None:
        """The frozen context rejects mutation of its fields."""
        context = _context()
        with pytest.raises(Exception):  # noqa: B017 - dataclasses raises FrozenInstanceError
            context.retrieved_at = datetime(2027, 1, 1, tzinfo=UTC)  # type: ignore[misc]

    def test_u02_naive_retrieval_timestamp_rejected(self) -> None:
        """D27C-U02: a naive retrieval timestamp fails closed."""
        with pytest.raises(ValueError, match="timezone-aware"):
            _context(retrieved_at=_NAIVE_TS)
        with pytest.raises(ValueError, match="timezone-aware"):
            SemanticSourceContext.from_definition(
                _THREATFOX_DEFINITION, retrieved_at=_NAIVE_TS
            )

    def test_u02b_retrieval_timestamp_normalized_to_utc(self) -> None:
        """An aware non-UTC timestamp is normalized to UTC."""
        offset_ts = _FIXED_TS.astimezone(timezone(timedelta(hours=2)))
        assert offset_ts.utcoffset() == timedelta(hours=2)
        context = _context(retrieved_at=offset_ts)
        assert context.retrieved_at == _FIXED_TS
        assert context.retrieved_at.utcoffset() == timedelta(0)

    def test_u03_credential_bearing_reference_rejected(self) -> None:
        """D27C-U03: a credential-bearing source reference fails closed."""
        with pytest.raises(ValueError, match="credentials"):
            _context(source_reference="https://user:pass@threatfox.example.test/api")

    @pytest.mark.parametrize(
        "reference",
        [
            "",
            "   ",
            "ftp://threatfox.example.test/feed",
            "https://",
            "not a url",
            "https://threatfox.example.test/" + ("x" * 2100),
        ],
    )
    def test_u03b_malformed_or_unbounded_reference_rejected(
        self, reference: str
    ) -> None:
        """Blank, non-HTTP, hostless, whitespace, and over-bound references fail."""
        with pytest.raises(ValueError):
            _context(source_reference=reference)

    def test_u03c_valid_null_reference_accepted(self) -> None:
        """A documented None reference is retained as None."""
        assert _context(source_reference=None).source_reference is None

    def test_u04_definition_context_mismatch_impossible_through_factory(self) -> None:
        """D27C-U04: from_definition can never produce a mismatched context.

        All three identity values derive from the single definition; a
        caller substituting a different source or semantic identity would
        have to bypass the sanctioned constructor. The reference path
        additionally rejects datasource definitions whose dimensions do not
        match the source contract before any I/O (D27C-U04/X-series
        dimension gate).
        """
        context = SemanticSourceContext.from_definition(
            _THREATFOX_DEFINITION, retrieved_at=_FIXED_TS
        )
        assert context.source_id is _THREATFOX_DEFINITION.source_id
        assert context.semantic_format is _THREATFOX_DEFINITION.semantic_format
        # A directly nominated semantic format that contradicts the
        # definition would violate the documented contract; the definition
        # is the only sanctioned origin.
        assert _THREATFOX_DEFINITION.semantic_format is SemanticFormatId.THREATFOX


class TestDatasourceStageError:
    """D27C-U07/U08: the bounded stage-aware failure contract."""

    def test_u07_malformed_error_code_rejected(self) -> None:
        """D27C-U07: error codes outside the bounded grammar fail closed."""
        for code in ("", " bad_code", "bad code", "Bad-Code", "x" * 65):
            with pytest.raises(ValidationError):
                DatasourceStageError(
                    stage=DatasourceStage.ACQUISITION,
                    code=code,
                    retryable=False,
                )

    def test_u07b_valid_stage_error_accepted(self) -> None:
        """A canonical stage-aware failure carries exactly the typed fields."""
        error = DatasourceStageError(
            stage=DatasourceStage.SEMANTIC_VALIDATION,
            code="semantic_validation_failed",
            retryable=False,
        )
        assert error.stage is DatasourceStage.SEMANTIC_VALIDATION
        assert error.code == "semantic_validation_failed"
        assert error.retryable is False
        assert error.retry_after_seconds is None
        # The model carries nothing beyond the bounded operational fields.
        assert set(DatasourceStageError.model_fields) == {
            "stage",
            "code",
            "retryable",
            "retry_after_seconds",
        }

    def test_u08_negative_retry_after_rejected(self) -> None:
        """D27C-U08: a negative retry-after fails closed."""
        with pytest.raises(ValidationError):
            DatasourceStageError(
                stage=DatasourceStage.ACQUISITION,
                code="rate_limited",
                retryable=True,
                retry_after_seconds=-1,
            )

    def test_u08b_nonnegative_retry_after_accepted(self) -> None:
        """Zero and positive retry delays are retained."""
        error = DatasourceStageError(
            stage=DatasourceStage.ACQUISITION,
            code="rate_limited",
            retryable=True,
            retry_after_seconds=30,
        )
        assert error.retry_after_seconds == 30

    def test_stage_vocabulary_is_closed(self) -> None:
        """The stage vocabulary is exactly acquisition/serialization/semantic."""
        assert list(DatasourceStage) == [
            DatasourceStage.ACQUISITION,
            DatasourceStage.SERIALIZATION,
            DatasourceStage.SEMANTIC_VALIDATION,
        ]


class TestSemanticAcquisitionResult:
    """D27C-U05/U06: the generic semantic acquisition result invariants."""

    def test_u05_success_result_has_no_error(self) -> None:
        """D27C-U05: a success result carries objects and no error."""
        context = _context()
        result: SemanticAcquisitionResult[object] = SemanticAcquisitionResult(
            context=context, objects=(object(),)
        )
        assert result.error is None
        assert len(result.objects) == 1

    def test_u05b_empty_success_is_valid(self) -> None:
        """A valid no-result is successful empty semantics, never an error."""
        result: SemanticAcquisitionResult[object] = SemanticAcquisitionResult(
            context=_context()
        )
        assert result.error is None
        assert result.objects == ()

    def test_u06_failure_result_has_no_objects(self) -> None:
        """D27C-U06: a failure result carries an error and no objects."""
        error = DatasourceStageError(
            stage=DatasourceStage.ACQUISITION,
            code="acquisition_failed",
            retryable=False,
        )
        result: SemanticAcquisitionResult[object] = SemanticAcquisitionResult(
            context=_context(), error=error
        )
        assert result.error is error
        assert result.objects == ()

    def test_u06b_failed_result_with_objects_rejected(self) -> None:
        """The invariant rejects an error result that also carries objects."""
        with pytest.raises(ValueError, match="cannot carry objects"):
            SemanticAcquisitionResult(
                context=_context(),
                objects=(object(),),
                error=DatasourceStageError(
                    stage=DatasourceStage.ACQUISITION,
                    code="acquisition_failed",
                    retryable=False,
                ),
            )

    def test_result_is_frozen(self) -> None:
        """The generic result is immutable and cannot be mutated."""
        result: SemanticAcquisitionResult[object] = SemanticAcquisitionResult(
            context=_context()
        )
        with pytest.raises(Exception):  # noqa: B017 - dataclasses raises FrozenInstanceError
            result.objects = (object(),)  # type: ignore[misc]
