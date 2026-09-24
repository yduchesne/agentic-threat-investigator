# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic ATI dataset/case to LangSmith projection (PR 30B).

Pure functions only: no SDK imports, no I/O, no environment access. All
projection decisions (dataset name, example identity, inputs/outputs,
metadata, canonical JSON serialization, semantic digest) are deterministic
so equal ATI inputs always produce equal LangSmith projections.

The semantic digest covers the complete authored typed scenario object
(every typed field including target-specific fixtures and expectation
envelopes) through strict typed loading, not a partial common projection:
a target-specific semantic change must change the digest.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time
from enum import Enum
from typing import cast
from uuid import UUID

from pydantic import BaseModel

from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithExampleMetadata,
    LangSmithExampleProjection,
)
from agentic_threat_investigator.evaluation.common.models import (
    EvaluationCase,
    EvaluationDatasetId,
    JsonValue,
    ScenarioLike,
    evaluation_case_from,
)

PROJECTION_SCHEMA_VERSION = 1
"""Versions the LangSmith representation, never benchmark semantics."""

DEFAULT_NAMESPACE = "ati"
"""Default namespace prefix for remote LangSmith dataset names."""

_NAMESPACE_RE = re.compile(r"^[a-z][a-z0-9._-]*$")
"""Stable lowercase namespace prefix: letter then letters, digits, dot, dash, underscore."""

_MAX_NAMESPACE_LENGTH = 64
"""Bounded namespace prefix length."""

_MAX_NARRATIVE_LENGTH = 2000
"""Bounded narrative metadata values (title, purpose, ...) on one projection."""

_MAX_METADATA_ENTRIES = 32
"""Bounded number of ``ati.`` metadata entries emitted per example."""

_MAX_TAGS = 10
"""Bounded descriptive tag count (the common scenario contract allows 10)."""

_MAX_ARCHITECTURE_REFS = 10
"""Bounded architecture-reference count (the common scenario contract allows 10)."""


class LangSmithProjectionError(ValueError):
    """A projection or remote-metadata violation fails before any remote call.

    Malformed remote ATI metadata, unsupported projection schemas, and
    invalid projection inputs all surface through this bounded error; the
    caller fails closed instead of guessing.
    """

    def __init__(self, message: str) -> None:
        """Record the bounded failure message."""
        super().__init__(message)


def project_dataset_name(
    dataset_id: EvaluationDatasetId, *, namespace: str = DEFAULT_NAMESPACE
) -> str:
    """Return the deterministic remote dataset name ``<namespace>/<canonical>``.

    A nondefault namespace must match the stable lowercase namespace
    pattern; an invalid namespace fails closed before any remote call.
    """
    stripped = namespace.strip()
    if not stripped or not _NAMESPACE_RE.fullmatch(stripped):
        raise LangSmithProjectionError("namespace must match " + _NAMESPACE_RE.pattern)
    if len(stripped) > _MAX_NAMESPACE_LENGTH:
        raise LangSmithProjectionError(
            f"namespace exceeds the {_MAX_NAMESPACE_LENGTH} character bound"
        )
    return f"{stripped}/{dataset_id.canonical}"


def project_case_inputs(
    case: EvaluationCase, *, dataset_id: EvaluationDatasetId
) -> dict[str, str | int]:
    """Return the stable ATI identity inputs for one case example.

    Only stable repository identity is projected: no secrets, raw provider
    payloads, prompts, or runtime UUIDs.
    """
    return {
        "ati_dataset_id": dataset_id.canonical,
        "ati_case_id": case.case_id,
        "ati_case_version": case.version,
        "ati_target": dataset_id.target.value,
    }


def project_case_outputs(case: EvaluationCase) -> dict[str, list[str]]:
    """Return the canonical narrative expected-behavior reference outputs.

    Required/forbidden behavior statements are projected in authored order;
    no exact golden prose answer is invented.
    """
    expected = case.specification.expected_behavior
    return {
        "required_behavior": list(expected.required),
        "forbidden_behavior": list(expected.forbidden),
    }


def project_example_metadata(
    case: EvaluationCase,
    *,
    dataset_id: EvaluationDatasetId,
    digest: str,
) -> LangSmithExampleMetadata:
    """Build the bounded projection metadata envelope for one case.

    Tags are sorted so the same authored set always projects identically;
    empty tag/architecture-ref collections stay empty.
    """
    specification = case.specification
    return LangSmithExampleMetadata(
        ati_dataset_id=dataset_id.canonical,
        ati_case_id=case.case_id,
        ati_case_version=case.version,
        ati_target=dataset_id.target.value,
        ati_title=specification.title,
        ati_purpose=specification.purpose,
        ati_operational_relevance=specification.operational_relevance,
        ati_regression_risk=specification.regression_risk,
        ati_tags=tuple(sorted(specification.tags)),
        ati_architecture_refs=tuple(specification.architecture_refs),
        ati_projection_schema_version=PROJECTION_SCHEMA_VERSION,
        ati_content_digest=digest,
    )


def project_case(
    case: EvaluationCase,
    *,
    dataset_id: EvaluationDatasetId,
    digest: str,
) -> LangSmithExampleProjection:
    """Project one canonical case plus its semantic digest onto one example."""
    return LangSmithExampleProjection(
        inputs=project_case_inputs(case, dataset_id=dataset_id),
        outputs=project_case_outputs(case),
        metadata=project_example_metadata(
            case=case, dataset_id=dataset_id, digest=digest
        ),
    )


def project_remote_metadata(
    metadata: LangSmithExampleMetadata,
) -> dict[str, JsonValue]:
    """Serialize one typed metadata envelope onto the dotted ``ati.*`` wire keys."""
    return {
        "ati.dataset_id": metadata.ati_dataset_id,
        "ati.case_id": metadata.ati_case_id,
        "ati.case_version": metadata.ati_case_version,
        "ati.target": metadata.ati_target,
        "ati.title": metadata.ati_title,
        "ati.purpose": metadata.ati_purpose,
        "ati.operational_relevance": metadata.ati_operational_relevance,
        "ati.regression_risk": metadata.ati_regression_risk,
        "ati.tags": list(metadata.ati_tags),
        "ati.architecture_refs": list(metadata.ati_architecture_refs),
        "ati.projection_schema_version": metadata.ati_projection_schema_version,
        "ati.content_digest": metadata.ati_content_digest,
    }


def project_dataset_metadata(dataset_id: EvaluationDatasetId) -> dict[str, JsonValue]:
    """Return the dataset-level ATI metadata stored on the remote dataset."""
    return {
        "ati.dataset_id": dataset_id.canonical,
        "ati.projection_schema_version": PROJECTION_SCHEMA_VERSION,
    }


def parse_dataset_metadata(
    metadata: Mapping[str, JsonValue],
) -> tuple[str, int]:
    """Strictly parse one remote dataset's ATI metadata.

    Returns ``(ati_dataset_id, projection_schema_version)`` and raises
    :class:`LangSmithProjectionError` when the metadata is absent or
    malformed, so the adapter refuses to write into a foreign dataset.
    """
    dataset_id = metadata.get("ati.dataset_id")
    schema = metadata.get("ati.projection_schema_version")
    if not isinstance(dataset_id, str) or not dataset_id.strip():
        raise LangSmithProjectionError(
            "remote dataset carries no valid ati.dataset_id metadata"
        )
    if not isinstance(schema, int) or isinstance(schema, bool) or schema < 1:
        raise LangSmithProjectionError(
            "remote dataset carries no valid ati.projection_schema_version"
        )
    return dataset_id.strip(), schema


def _text_entry(metadata: Mapping[str, JsonValue], key: str) -> str:
    """Extract one required remote text metadata value."""
    value = metadata.get(key)
    if not isinstance(value, str) or not value.strip():
        raise LangSmithProjectionError(
            f"remote example metadata {key!r} is missing or invalid"
        )
    return value.strip()


def _int_entry(metadata: Mapping[str, JsonValue], key: str) -> int:
    """Extract one required remote integer metadata value."""
    value = metadata.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise LangSmithProjectionError(
            f"remote example metadata {key!r} is missing or invalid"
        )
    return value


def _list_entry(metadata: Mapping[str, JsonValue], key: str) -> tuple[str, ...]:
    """Extract one required remote list-of-texts metadata value."""
    value = metadata.get(key)
    if not isinstance(value, list):
        raise LangSmithProjectionError(
            f"remote example metadata {key!r} is missing or invalid"
        )
    entries: list[str] = []
    for entry in value:
        if not isinstance(entry, str) or not entry.strip():
            raise LangSmithProjectionError(
                f"remote example metadata {key!r} contains an invalid entry"
            )
        entries.append(entry.strip())
    return tuple(entries)


def parse_remote_metadata(
    metadata: Mapping[str, JsonValue],
) -> LangSmithExampleMetadata:
    """Strictly parse one bounded remote example's ATI metadata.

    Every ATI-owned key the projection writes must be present and valid; a
    missing or malformed identity fails closed through
    :class:`LangSmithProjectionError` so synchronization never guesses.
    """
    return LangSmithExampleMetadata(
        ati_dataset_id=_text_entry(metadata, "ati.dataset_id"),
        ati_case_id=_text_entry(metadata, "ati.case_id"),
        ati_case_version=_int_entry(metadata, "ati.case_version"),
        ati_target=_text_entry(metadata, "ati.target"),
        ati_title=_text_entry(metadata, "ati.title"),
        ati_purpose=_text_entry(metadata, "ati.purpose"),
        ati_operational_relevance=_text_entry(metadata, "ati.operational_relevance"),
        ati_regression_risk=_text_entry(metadata, "ati.regression_risk"),
        ati_tags=_list_entry(metadata, "ati.tags"),
        ati_architecture_refs=_list_entry(metadata, "ati.architecture_refs"),
        ati_projection_schema_version=_int_entry(
            metadata, "ati.projection_schema_version"
        ),
        ati_content_digest=_text_entry(metadata, "ati.content_digest"),
    )


def canonical_json(value: object) -> str:
    """Serialize any scenario-derived value to deterministic canonical JSON.

    Rules: mappings (including pydantic model dumps) have recursively sorted
    keys; ``set``/``frozenset`` members are ordered by their canonical
    encoding because sets are semantically unordered and Python iteration
    order is process-random; ``list``/``tuple`` collections whose members are
    all strings are sorted because repository scenario string collections
    (required/forbidden statements, tags, architecture references, citation
    labels) are semantically unordered sets compared by membership, while
    structured object collections (findings, observations, expected claims)
    keep their authored order, which evaluation may treat as meaningful;
    enums, UUIDs, dates, and datetimes serialize to their canonical wire
    values; non-string mapping keys are encoded through their own canonical
    form so tuple-keyed projection indexes stay injective; NaN/infinite
    floats and other unserializable objects fail closed.
    """
    return json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def semantic_digest(value: object) -> str:
    """Return the SHA-256 hex digest of one object's canonical JSON form."""
    encoded = canonical_json(value).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonicalize(value: object) -> object:
    """Recursively convert one object to its deterministic canonical form."""
    if isinstance(value, BaseModel):
        return _canonicalize(value.model_dump(mode="python"))
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if isinstance(key, str):
                result[key] = _canonicalize(item)
            else:
                encoded_key = json.dumps(
                    _canonicalize(key),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
                result[encoded_key] = _canonicalize(item)
        return result
    if isinstance(value, (set, frozenset)):
        canonical_items = [_canonicalize(item) for item in value]
        canonical_items.sort(key=canonical_json)
        return canonical_items
    if isinstance(value, (list, tuple)):
        items = [_canonicalize(item) for item in value]
        if all(isinstance(item, str) for item in items):
            return sorted(cast(list[str], items))
        return items
    if isinstance(value, Enum):
        return _canonicalize(value.value)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (date, time)):
        return value.isoformat()
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("canonical JSON cannot encode NaN or infinite floats")
        return value
    if isinstance(value, UUID):
        return str(value)
    raise TypeError(f"cannot canonically serialize {type(value).__name__}")


def scenario_semantic_digest(scenario: ScenarioLike) -> str:
    """Return the semantic digest of one fully typed repository scenario.

    The digest covers the complete authored semantic object after strict
    typed loading: the common identity/specification plus every typed
    target-specific field (fixtures, expectation envelopes). The typed
    scenario's canonical serialization is what makes a later
    target-specific semantic change observable as digest drift.
    """
    return semantic_digest(scenario.model_dump(mode="python"))


def projection_index(
    scenarios: Sequence[ScenarioLike],
    *,
    dataset_id: EvaluationDatasetId,
) -> dict[tuple[str, int], LangSmithExampleProjection]:
    """Project every typed scenario onto deterministic example projections.

    Returns an identity-indexed mapping keyed by ``(case_id, case_version)``;
    duplicate identities fail closed before any remote operation.
    """
    projections: dict[tuple[str, int], LangSmithExampleProjection] = {}
    for scenario in scenarios:
        digest = scenario_semantic_digest(scenario)
        case = _scenario_case(scenario)
        identity = (case.case_id, case.version)
        if identity in projections:
            raise LangSmithProjectionError(
                f"duplicate case identity {identity!r} in the loaded dataset"
            )
        projections[identity] = project_case(
            case=case, dataset_id=dataset_id, digest=digest
        )
    return projections


def _scenario_case(scenario: ScenarioLike) -> EvaluationCase:
    """Project one typed scenario onto the common case form."""
    return evaluation_case_from(scenario)
