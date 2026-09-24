# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""LangSmith projection mapping tests (LS-M01..M10).

Deterministic, offline: dataset naming, stable example identity,
required/forbidden behavior projection, sorted tag metadata, identical
canonical projection for identical inputs, digest sensitivity to semantic
change and insensitivity to ordering-only change, no raw/secret fields,
projection schema emission, and fail-closed metadata validation.
"""

from __future__ import annotations

import pytest

from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
    PROJECTION_SCHEMA_VERSION,
    LangSmithProjectionError,
    canonical_json,
    parse_dataset_metadata,
    parse_remote_metadata,
    project_case,
    project_dataset_metadata,
    project_dataset_name,
    project_example_metadata,
    project_remote_metadata,
    projection_index,
    semantic_digest,
)
from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithExampleMetadata,
    LangSmithExampleProjection,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCase,
    ExpectedBehavior,
    ScenarioSpecification,
)
from tests.support.evaluation_common import (
    unit_dataset,
    unit_specification,
)
from tests.support.langsmith_fakes import (
    ScenarioStub,
)
from tests.support.langsmith_fakes import (
    test_scenario as scenario_factory,
)

DIGEST = "a" * 64


def _unit_projection() -> LangSmithExampleProjection:
    """Build the projection of one deterministic unit test scenario."""
    scenario = scenario_factory()
    dataset = unit_dataset()
    return project_case(
        case=_case_of(scenario),
        dataset_id=dataset,
        digest=semantic_digest(scenario),
    )


def _case_of(scenario: ScenarioStub) -> EvaluationCase:
    """Project one test scenario onto the common case."""
    from agentic_threat_investigator.evaluation.common.models import (
        evaluation_case_from,
    )

    return evaluation_case_from(scenario)


class TestDatasetName:
    """LS-M01 deterministic dataset naming."""

    def test_m01_default_namespace(self) -> None:
        """M01 the default remote dataset name is ``ati/<canonical>``."""
        assert project_dataset_name(unit_dataset()) == "ati/evidence-analyst/v1"

    def test_m01_custom_namespace(self) -> None:
        """M01 a custom namespace prefixes the canonical identity."""
        assert (
            project_dataset_name(unit_dataset(), namespace="internal")
            == "internal/evidence-analyst/v1"
        )

    def test_m01_invalid_namespace_fails_closed(self) -> None:
        """M01 invalid namespaces fail closed before any remote call."""
        for namespace in ("", "  ", "Upper", "a/b", "-x"):
            with pytest.raises(LangSmithProjectionError):
                project_dataset_name(unit_dataset(), namespace=namespace)


class TestCaseProjection:
    """LS-M02..M10 stable case identity and projection contents."""

    def test_m02_stable_case_identity_inputs(self) -> None:
        """M02 the example inputs carry exactly the stable ATI identity."""
        projection = _unit_projection()
        assert projection.inputs == {
            "ati_dataset_id": "evidence-analyst/v1",
            "ati_case_id": "unit-case",
            "ati_case_version": 1,
            "ati_target": "evidence-analyst",
        }

    def test_m03_behavior_projected(self) -> None:
        """M03 required/forbidden behavior statements are preserved."""
        projection = _unit_projection()
        expected = unit_specification().expected_behavior
        assert projection.outputs["required_behavior"] == list(expected.required)
        assert projection.outputs["forbidden_behavior"] == list(expected.forbidden)

    def test_m04_tags_sorted_and_architecture_ordered(self) -> None:
        """M04 tag metadata is deterministic (sorted) and refs keep order."""
        specification = unit_specification(
            tags=("regression", "unit", "z-last"),
            architecture_refs=("b-ref", "a-ref"),
        )
        metadata = project_example_metadata(
            case=EvaluationCase.from_scenario(
                case_id="unit-case", version=1, specification=specification
            ),
            dataset_id=unit_dataset(),
            digest=DIGEST,
        )
        assert metadata.ati_tags == ("regression", "unit", "z-last")
        assert metadata.ati_architecture_refs == ("b-ref", "a-ref")

    def test_m05_same_case_twice_identical_projection(self) -> None:
        """M05 the same case always produces an identical canonical projection."""
        scenario = scenario_factory()
        first = projection_index([scenario], dataset_id=unit_dataset())
        second = projection_index([scenario], dataset_id=unit_dataset())
        assert first == second
        assert canonical_json(first) == canonical_json(second)

    def test_m06_semantic_change_changes_digest(self) -> None:
        """M06 any authored semantic change changes the digest."""
        base = scenario_factory()
        changed = scenario_factory(extra_semantic="other")
        assert semantic_digest(base) != semantic_digest(changed)
        changed_spec = scenario_factory(
            specification=unit_specification(
                regression_risk="a different regression risk"
            )
        )
        assert semantic_digest(base) != semantic_digest(changed_spec)

    def test_m07_ordering_only_change_keeps_digest(self) -> None:
        """M07 reordering semantically unordered content keeps the digest."""

        def specification_with(required: tuple[str, ...]) -> ScenarioSpecification:
            """Build an otherwise identical specification variant."""
            return unit_specification(
                expected_behavior=ExpectedBehavior(
                    required=required,
                    forbidden=("The Assessment cites only contextual evidence.",),
                )
            )

        first = scenario_factory(specification=specification_with(("alpha", "beta")))
        second = scenario_factory(specification=specification_with(("beta", "alpha")))
        assert semantic_digest(first) == semantic_digest(second)
        retagged = scenario_factory(
            specification=unit_specification(
                tags=("z-tag", "a-tag"),
                expected_behavior=ExpectedBehavior(
                    required=("alpha", "beta"),
                    forbidden=("The Assessment cites only contextual evidence.",),
                ),
            )
        )
        retagged_reversed = retagged.model_copy(
            update={
                "specification": unit_specification(
                    tags=("a-tag", "z-tag"),
                    expected_behavior=ExpectedBehavior(
                        required=("beta", "alpha"),
                        forbidden=("The Assessment cites only contextual evidence.",),
                    ),
                )
            }
        )
        assert semantic_digest(retagged) == semantic_digest(retagged_reversed)

    def test_m08_no_secret_or_runtime_fields(self) -> None:
        """M08 the projection contains no secrets or raw runtime payloads."""
        projection = _unit_projection()
        rendered = canonical_json(projection.model_dump(mode="python"))
        for forbidden in (
            "api_key",
            "secret",
            "prompt",
            "model_output",
            "chain_of_thought",
            "uuid",
            "fixture_payload",
        ):
            assert forbidden not in rendered

    def test_m09_projection_schema_emitted(self) -> None:
        """M09 the projection schema version is part of the projection."""
        projection = _unit_projection()
        assert (
            projection.metadata.ati_projection_schema_version
            == PROJECTION_SCHEMA_VERSION
        )
        remote = project_remote_metadata(projection.metadata)
        assert remote["ati.projection_schema_version"] == PROJECTION_SCHEMA_VERSION

    def test_m10_unsupported_metadata_rejected(self) -> None:
        """M10 malformed projection metadata fails closed before any remote call."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            LangSmithExampleMetadata(
                ati_dataset_id="evidence-analyst/v1",
                ati_case_id="case",
                ati_case_version=1,
                ati_target="evidence-analyst",
                ati_title="t",
                ati_purpose="p",
                ati_operational_relevance="o",
                ati_regression_risk="r",
                ati_projection_schema_version=1,
                ati_content_digest="zz-not-a-digest",
            )


class TestMetadataRoundTrip:
    """Dotted-key round trip between typed and remote metadata."""

    def test_round_trip_preserves_identity(self) -> None:
        """A remote metadata round trip preserves every projected field."""
        projection = _unit_projection()
        remote = project_remote_metadata(projection.metadata)
        parsed = parse_remote_metadata(remote)
        assert parsed == projection.metadata

    def test_remote_parse_rejects_missing_identity(self) -> None:
        """A remote example missing ATI identity metadata fails closed."""
        with pytest.raises(LangSmithProjectionError):
            parse_remote_metadata({"ati.case_id": "case-1"})

    def test_parse_dataset_metadata_round_trip(self) -> None:
        """Dataset-level metadata round trips and rejects foreign values."""
        metadata = project_dataset_metadata(unit_dataset())
        assert parse_dataset_metadata(metadata) == (
            "evidence-analyst/v1",
            PROJECTION_SCHEMA_VERSION,
        )
        with pytest.raises(LangSmithProjectionError):
            parse_dataset_metadata({})


class TestCanonicalSerialization:
    """Deterministic canonical JSON rules."""

    def test_sets_are_order_independent(self) -> None:
        """Canonical JSON orders set members deterministically."""
        assert canonical_json({"tags": {"b", "a"}}) == canonical_json(
            {"tags": {"a", "b"}}
        )

    def test_mapping_keys_sorted(self) -> None:
        """Canonical JSON sorts mapping keys recursively."""
        assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'
        assert canonical_json({"b": {"y": 1, "x": 2}}) == '{"b":{"x":2,"y":1}}'

    def test_tuple_order_preserved_for_structured_collections(self) -> None:
        """Canonical JSON preserves order for structured object collections."""
        assert canonical_json(
            {"findings": [{"label": "b"}, {"label": "a"}]}
        ) != canonical_json({"findings": [{"label": "a"}, {"label": "b"}]})

    def test_string_collections_order_normalized(self) -> None:
        """Canonical JSON normalizes semantically unordered string collections."""
        assert canonical_json({"statements": ("b", "a")}) == canonical_json(
            {"statements": ("a", "b")}
        )

    def test_unserializable_value_fails_closed(self) -> None:
        """Canonical JSON rejects objects it cannot serialize truthfully."""
        with pytest.raises(TypeError):
            canonical_json({"bad": object()})
