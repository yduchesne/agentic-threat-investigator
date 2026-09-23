# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded LangSmith evaluation-adapter DTOs (PR 30B).

These DTOs are the entire data contract between the adapter and the LangSmith
SDK boundary. LangSmith UUIDs and API objects are bounded here into
adapter-owned references and never enter common ATI evaluation models;
remote metadata is restricted to the ``ati.`` wire namespace with bounded,
JSON-safe values.

No module here imports the LangSmith SDK; the SDK is only constructed and
called by :mod:`agentic_threat_investigator.evaluation.backends.langsmith.client`.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from agentic_threat_investigator.evaluation.common.models import JsonValue

_MAX_IDENTIFIER_LENGTH = 200
"""Bounded length of adapter-owned remote identifiers (dataset/example ids)."""

_MAX_METADATA_ENTRIES = 32
"""Bounded number of ``ati.`` metadata entries kept from remote payloads."""

_MAX_METADATA_STRING = 4096
"""Bounded length of one metadata string kept from remote payloads."""

_MAX_METADATA_DEPTH = 8
"""Bounded nesting depth of remote metadata values."""

_ATI_METADATA_PREFIX = "ati."
"""Wire namespace for every ATI-owned metadata key on remote objects."""

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
"""SHA-256 hex digests are exactly 64 lowercase hexadecimal characters."""

_FORBIDDEN_PARAMETER_KEY_RE = re.compile(
    r"(api[_-]?key|secret|token|password|credential)", re.IGNORECASE
)
"""Guardlist removing credential-bearing model-parameter keys fail-closed.

    Model parameters are bounded generic JSON; the builder never invents
    credentials, and this guardlist makes it impossible to smuggle an
    obvious secret into published experiment metadata.
    """

_MAX_TAGS = 16
"""Bounded descriptive tag count on one projected example."""

_MAX_TAG_LENGTH = 120
"""Bounded length of one descriptive tag."""

_MAX_ARCHITECTURE_REFS = 16
"""Bounded architecture-reference count on one projected example."""

_MAX_ARCHITECTURE_REF_LENGTH = 120
"""Bounded length of one architecture reference."""

_MAX_NARRATIVE_LENGTH = 2000
"""Bounded narrative metadata values (title, purpose, ...) on one projection."""

_MAX_FEEDBACK_ITEMS = 512
"""Upper bound defending publication validation against pathological inputs."""


def _require_nonblank_bounded(value: str, field: str, *, max_length: int) -> str:
    """Trim, reject blank, and bound one canonical text value."""
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{field} must not be blank")
    if len(stripped) > max_length:
        raise ValueError(f"{field} exceeds the {max_length} character bound")
    return stripped


def _bound_json_safe(value: object, *, field: str, depth: int = 0) -> None:
    """Require a JSON-safe, bounded metadata value (no unbounded/deeply nested data)."""
    if depth > _MAX_METADATA_DEPTH:
        raise ValueError(
            f"{field} exceeds the {_MAX_METADATA_DEPTH} level nesting bound"
        )
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        return
    if isinstance(value, str):
        if len(value) > _MAX_METADATA_STRING:
            raise ValueError(f"{field} strings exceed the {_MAX_METADATA_STRING} bound")
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError(f"{field} must not contain NaN or infinite floats")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        if len(value) > _MAX_METADATA_ENTRIES:
            raise ValueError(f"{field} collections exceed the bounded size")
        for item in value:
            _bound_json_safe(item, field=field, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > _MAX_METADATA_ENTRIES:
            raise ValueError(f"{field} collections exceed the bounded size")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{field} keys must be strings")
            _bound_json_safe(item, field=field, depth=depth + 1)
        return
    raise ValueError(f"{field} contains unsupported values")


def bound_remote_metadata(value: object) -> dict[str, JsonValue]:
    """Bound untrusted remote metadata to the ATI wire namespace.

    Only ``ati.``-prefixed keys are retained (foreign keys such as
    ``tenant_id`` never enter the adapter), and values must be JSON-safe
    within explicit entry/depth/string bounds. An unacceptably large payload
    fails closed rather than being truncated silently.
    """
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError("remote metadata must be a JSON object")
    result: dict[str, JsonValue] = {}
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValueError("remote metadata keys must be strings")
        if not key.startswith(_ATI_METADATA_PREFIX):
            continue
        _bound_json_safe(item, field=key)
        result[key] = item
    if len(result) > _MAX_METADATA_ENTRIES:
        raise ValueError("remote ATI metadata exceeds the bounded size")
    return result


class LangSmithDatasetRef(BaseModel):
    """Bounded reference to one remote LangSmith dataset.

    ``dataset_id`` is the LangSmith UUID string, owned by the adapter only;
    it is never an ATI semantic identity.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    dataset_id: str
    example_count: int | None = None
    metadata: Mapping[str, JsonValue] = Field(default_factory=dict)

    @field_validator("name", "dataset_id", mode="after")
    @classmethod
    def identifiers_bounded(cls, value: str, info: ValidationInfo) -> str:
        """Require nonblank bounded remote identifiers."""
        return _require_nonblank_bounded(
            value, info.field_name or "identifier", max_length=_MAX_IDENTIFIER_LENGTH
        )

    @field_validator("metadata", mode="before")
    @classmethod
    def metadata_bounded(cls, value: object) -> dict[str, JsonValue]:
        """Restrict remote dataset metadata to bounded ATI keys."""
        return bound_remote_metadata(value)


class LangSmithExampleRef(BaseModel):
    """Bounded reference to one remote LangSmith example.

    The remote inputs/outputs are not retained: ATI compares remote examples
    by stable identity and semantic digest only. Remote metadata is bounded
    to the ATI wire namespace so no SDK object or foreign payload escapes
    the adapter boundary.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    example_id: str
    dataset_id: str
    metadata: Mapping[str, JsonValue] = Field(default_factory=dict)

    @field_validator("example_id", "dataset_id", mode="after")
    @classmethod
    def identifiers_bounded(cls, value: str, info: ValidationInfo) -> str:
        """Require nonblank bounded remote identifiers."""
        return _require_nonblank_bounded(
            value, info.field_name or "identifier", max_length=_MAX_IDENTIFIER_LENGTH
        )

    @field_validator("metadata", mode="before")
    @classmethod
    def metadata_bounded(cls, value: object) -> dict[str, JsonValue]:
        """Restrict remote example metadata to bounded ATI keys."""
        return bound_remote_metadata(value)


class LangSmithExampleMetadata(BaseModel):
    """One deterministic ATI example projection metadata envelope.

    Carries the stable ATI identity, bounded descriptive metadata, the
    projection schema version, and the semantic content digest. The digest
    is the repository-owned drift signal: a different digest for the same
    identity means the authored semantics changed, which synchronization
    refuses to overwrite.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ati_dataset_id: str
    ati_case_id: str
    ati_case_version: int = Field(ge=1)
    ati_target: str
    ati_title: str
    ati_purpose: str
    ati_operational_relevance: str
    ati_regression_risk: str
    ati_tags: tuple[str, ...] = ()
    ati_architecture_refs: tuple[str, ...] = ()
    ati_projection_schema_version: int = Field(ge=1)
    ati_content_digest: str

    @field_validator(
        "ati_dataset_id",
        "ati_target",
        "ati_title",
        "ati_purpose",
        "ati_operational_relevance",
        "ati_regression_risk",
        mode="after",
    )
    @classmethod
    def narrative_bounded(cls, value: str, info: ValidationInfo) -> str:
        """Require nonblank bounded narrative metadata values."""
        return _require_nonblank_bounded(
            value, info.field_name or "field", max_length=_MAX_NARRATIVE_LENGTH
        )

    @field_validator("ati_case_id", mode="after")
    @classmethod
    def case_id_bounded(cls, value: str) -> str:
        """Require a nonblank bounded case identifier."""
        return _require_nonblank_bounded(
            value, "ati_case_id", max_length=_MAX_IDENTIFIER_LENGTH
        )

    @field_validator("ati_tags", "ati_architecture_refs", mode="after")
    @classmethod
    def collections_bounded(
        cls, value: tuple[str, ...], info: ValidationInfo
    ) -> tuple[str, ...]:
        """Bound projection list metadata and reject blank entries."""
        field = info.field_name or "field"
        limit = _MAX_TAGS if field == "ati_tags" else _MAX_ARCHITECTURE_REFS
        length = (
            _MAX_TAG_LENGTH if field == "ati_tags" else _MAX_ARCHITECTURE_REF_LENGTH
        )
        if len(value) > limit:
            raise ValueError(f"{field} are bounded to {limit} entries")
        for entry in value:
            stripped = entry.strip()
            if not stripped:
                raise ValueError(f"{field} entries must not be blank")
            if len(stripped) > length:
                raise ValueError(f"{field} entries exceed the {length} character bound")
        return value

    @field_validator("ati_content_digest", mode="after")
    @classmethod
    def digest_valid(cls, value: str) -> str:
        """Require exactly one canonical SHA-256 hex semantic digest."""
        if not _DIGEST_RE.fullmatch(value):
            raise ValueError(
                "ati_content_digest must be a 64-character SHA-256 hex digest"
            )
        return value


class LangSmithExampleProjection(BaseModel):
    """One deterministic ATI case projected onto a LangSmith dataset example.

    ``inputs`` carries only the stable ATI identity; ``outputs`` carries the
    canonical narrative expected-behavior statements; ``metadata`` carries
    the bounded projection envelope including the semantic digest. No
    secrets, raw provider payloads, prompts, or runtime UUIDs are present.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    inputs: Mapping[str, str | int]
    outputs: Mapping[str, Sequence[str]]
    metadata: LangSmithExampleMetadata

    @field_validator("inputs", "outputs", mode="after")
    @classmethod
    def projections_bounded(
        cls,
        value: Mapping[str, str | int] | Mapping[str, Sequence[str]],
        info: ValidationInfo,
    ) -> Mapping[str, str | int] | Mapping[str, Sequence[str]]:
        """Bound the projected inputs/outputs and reject unknown keys."""
        field = info.field_name or "field"
        if len(value) > 8:
            raise ValueError(f"{field} are bounded to 8 entries")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{field} keys must be strings")
            if field == "inputs" and key not in {
                "ati_dataset_id",
                "ati_case_id",
                "ati_case_version",
                "ati_target",
            }:
                raise ValueError(f"unknown projected input key: {key!r}")
            if field == "outputs" and key not in {
                "required_behavior",
                "forbidden_behavior",
            }:
                raise ValueError(f"unknown projected output key: {key!r}")
            if field == "inputs" and not isinstance(item, (str, int)):
                raise ValueError(f"projected input {key!r} must be text or integer")
            if field == "outputs" and not isinstance(item, Sequence):
                raise ValueError(f"projected output {key!r} must be a list")
        return value


class LangSmithSyncReceipt(BaseModel):
    """Deterministic receipt of one successful dataset synchronization."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    dataset: str
    local_cases: int = Field(ge=0)
    created: int = Field(ge=0)
    unchanged: int = Field(ge=0)
    status: Literal["synchronized"] = "synchronized"

    @field_validator("dataset", mode="after")
    @classmethod
    def dataset_bounded(cls, value: str) -> str:
        """Require a nonblank bounded dataset name."""
        return _require_nonblank_bounded(value, "dataset", max_length=256)


class LangSmithVerifyReport(BaseModel):
    """Deterministic report of one successful read-only dataset verification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    dataset: str
    local_cases: int = Field(ge=0)
    remote_examples: int = Field(ge=0)
    status: Literal["verified"] = "verified"

    @field_validator("dataset", mode="after")
    @classmethod
    def dataset_bounded(cls, value: str) -> str:
        """Require a nonblank bounded dataset name."""
        return _require_nonblank_bounded(value, "dataset", max_length=256)


class LangSmithPublicationFeedback(BaseModel):
    """One categorical LangSmith feedback item projected from ATI results.

    ``value`` is strictly categorical (``pass``/``fail``/``error``); ATI
    never introduces a numeric correctness score, percentage, weight, or
    threshold through this boundary. ``comment`` is bounded and sanitized.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    key: str
    value: Literal["pass", "fail", "error"]
    comment: str = ""

    @field_validator("key", mode="after")
    @classmethod
    def key_bounded(cls, value: str, info: ValidationInfo) -> str:
        """Require a nonblank bounded feedback key."""
        return _require_nonblank_bounded(
            value, info.field_name or "field", max_length=_MAX_IDENTIFIER_LENGTH
        )

    @field_validator("comment", mode="after")
    @classmethod
    def comment_bounded(cls, value: str) -> str:
        """Allow an empty comment; otherwise collapse whitespace and bound it."""
        collapsed = " ".join(value.split())
        if not collapsed:
            return ""
        return _require_nonblank_bounded(
            collapsed, "comment", max_length=_MAX_NARRATIVE_LENGTH
        )


class LangSmithEvaluationPublication(BaseModel):
    """One deterministic projection of one ATI run onto LangSmith feedback.

    The content is derived exclusively from :class:`EvaluationRunResult`
    through the frozen categorical mapping; experiment-level metadata
    (commit, model, ...) is built separately by
    :func:`~agentic_threat_investigator.evaluation.backends.langsmith.results.build_experiment_metadata`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    dataset_id: str
    run_status: Literal["pass", "fail", "error"]
    feedback: tuple[LangSmithPublicationFeedback, ...]

    @field_validator("dataset_id", mode="after")
    @classmethod
    def dataset_bounded(cls, value: str) -> str:
        """Require a nonblank bounded dataset identity."""
        return _require_nonblank_bounded(value, "dataset_id", max_length=64)

    @field_validator("feedback", mode="after")
    @classmethod
    def feedback_bounded(
        cls, value: tuple[LangSmithPublicationFeedback, ...]
    ) -> tuple[LangSmithPublicationFeedback, ...]:
        """Require a nonempty, bounded feedback list."""
        if not value:
            raise ValueError("publication feedback must not be empty")
        if len(value) > _MAX_FEEDBACK_ITEMS:
            raise ValueError("publication feedback exceeds the supported bound")
        return value


class LangSmithExperimentMetadata(BaseModel):
    """Optional, adapter-only experiment metadata (PR 30C+ support fields).

    Every field is optional and omitted when unset; values are bounded and
    JSON-safe. This model deliberately lives outside the common evaluation
    models and outside :class:`EvaluationRunResult`.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    commit_sha: str | None = None
    dataset_id: str | None = None
    projection_schema_version: int | None = Field(default=None, ge=1)
    agent_implementation_version: str | None = None
    prompt_version: str | None = None
    model_provider: str | None = None
    model_name: str | None = None
    model_parameters: Mapping[str, JsonValue] | None = None
    fixture_set_version: str | None = None
    normalization_version: str | None = None
    retriever_version: str | None = None
    embedding_version: str | None = None
    evaluator_version: str | None = None
    judge_model: str | None = None
    judge_prompt_version: str | None = None
    timestamp: str | None = None

    @field_validator(
        "commit_sha",
        "dataset_id",
        "agent_implementation_version",
        "prompt_version",
        "model_provider",
        "model_name",
        "fixture_set_version",
        "normalization_version",
        "retriever_version",
        "embedding_version",
        "evaluator_version",
        "judge_model",
        "judge_prompt_version",
        "timestamp",
        mode="after",
    )
    @classmethod
    def optional_text_bounded(
        cls, value: str | None, info: ValidationInfo
    ) -> str | None:
        """Bound optional metadata text values when present."""
        if value is None:
            return value
        return _require_nonblank_bounded(
            value, info.field_name or "field", max_length=256
        )

    @field_validator("model_parameters", mode="before")
    @classmethod
    def model_parameters_bounded(cls, value: object) -> Mapping[str, JsonValue] | None:
        """Require bounded, JSON-safe, credential-free model parameters when present."""
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise ValueError("model_parameters must be a JSON object")
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("model_parameters keys must be strings")
            if _FORBIDDEN_PARAMETER_KEY_RE.search(key):
                raise ValueError(
                    f"model_parameters key {key!r} looks like a credential and is rejected"
                )
            _bound_json_safe(item, field="model_parameters")
            result[key] = item
        if len(result) > 16:
            raise ValueError("model_parameters are bounded to 16 entries")
        return result


class LangSmithExperimentRef(BaseModel):
    """Bounded reference to one ATI experiment recorded as a LangSmith run.

    The experiment run is created by the adapter itself from the ATI
    execution identity; the LangSmith run id is adapter-owned and never
    enters common ATI evaluation models. ``metadata`` is bounded to the
    ``ati.`` wire namespace exactly like remote dataset/example metadata.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    name: str
    metadata: Mapping[str, JsonValue] = Field(default_factory=dict)

    @field_validator("run_id", "name", mode="after")
    @classmethod
    def identifiers_bounded(cls, value: str, info: ValidationInfo) -> str:
        """Require nonblank bounded remote identifiers."""
        return _require_nonblank_bounded(
            value, info.field_name or "identifier", max_length=_MAX_IDENTIFIER_LENGTH
        )

    @field_validator("metadata", mode="before")
    @classmethod
    def metadata_bounded(cls, value: object) -> dict[str, JsonValue]:
        """Restrict remote experiment metadata to bounded ATI keys."""
        return bound_remote_metadata(value)


class LangSmithFeedbackItem(BaseModel):
    """One categorical feedback item read back from a LangSmith run.

    Values are bounded text; the adapter only ever writes and reads the
    categorical ``pass``/``fail``/``error`` vocabulary.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    key: str
    value: str

    @field_validator("key", "value", mode="after")
    @classmethod
    def values_bounded(cls, value: str, info: ValidationInfo) -> str:
        """Require nonblank bounded feedback fields."""
        return _require_nonblank_bounded(
            value, info.field_name or "field", max_length=_MAX_IDENTIFIER_LENGTH
        )


class LangSmithExperimentConfirmation(BaseModel):
    """Deterministic confirmation of one published ATI experiment.

    Produced only after remote state proves the experiment run exists, the
    expected case/run association is present, and every expected categorical
    feedback key was accepted. Remote averages never determine ATI
    correctness; this is an existence/association confirmation only.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    experiment_name: str
    feedback_count: int = Field(ge=0)
    status: Literal["confirmed"] = "confirmed"

    @field_validator("run_id", "experiment_name", mode="after")
    @classmethod
    def identifiers_bounded(cls, value: str, info: ValidationInfo) -> str:
        """Require nonblank bounded remote identifiers."""
        return _require_nonblank_bounded(
            value, info.field_name or "identifier", max_length=_MAX_IDENTIFIER_LENGTH
        )
