# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Semantic-format-driven Evidence conversion boundary (PR 27D + PR 28A).

One :class:`ToEvidenceConverter` transforms **one already-validated semantic
source object** plus explicit ATI conversion context into zero, one, or
multiple :class:`ConvertedEvidence` values (each a stable global
:class:`Evidence` plus its immutable :class:`EvidenceObservationCandidate`).
Selection is based only on ``semantic_format``; converters perform no I/O,
no persistence, no clock or random reads, no secret/config lookup, and
never assign observation versions, verdicts, relationships, pivots,
attribution, or Investigation control flow.

The boundary is deliberately narrower than the roadmap's conceptual
``convert(source)``: conversion receives an :class:`EvidenceConversionContext`
carrying only the cross-cutting semantic acquisition provenance
(:class:`SemanticSourceContext`). Since PR 28A, conversion is global and
Investigation-independent — the context carries no Investigation identity
and no subject binding. The registry is immutable and keyed only by
:class:`SemanticFormatId`; duplicate registration and unknown formats fail
closed. The flattening helper preserves deterministic ordering: semantic
source-object order, then each converter's return order.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from agentic_threat_investigator.app.datasource_semantics import (
    SemanticSourceContext,
)
from agentic_threat_investigator.domain.evidence import ConvertedEvidence
from agentic_threat_investigator.domain.identifiers import SemanticFormatId

TSource = TypeVar("TSource")
"""One validated source-native semantic object type."""


class ConversionError(ValueError):
    """Raised when a converter contract is violated for one source object.

    A converter contract violation is a deterministic local programming or
    contract failure of the conversion boundary (for example a non-matching
    source object type or a missing required source member), never an
    acquisition, parsing, or persistence failure. Callers map every
    ``ConversionError`` to the bounded durable ``conversion_failed`` code
    without ever persisting the exception text.
    """


class DuplicateConverterError(ValueError):
    """Raised when two converters claim the same semantic format.

    The registry accepts at most one converter per semantic format; a
    duplicate registration is a composition bug and fails closed at
    construction.
    """


class UnknownSemanticFormatError(KeyError):
    """Raised when no converter is registered for a semantic format.

    The registry has no default converter and never falls back to provider,
    protocol, serialization, or object-shape inference: an unknown
    semantic format is a typed deterministic lookup failure.
    """


@dataclass(frozen=True)
class EvidenceConversionContext:
    """Immutable cross-cutting context of one conversion pass (PR 28A).

    Carries only the reused semantic acquisition context; there is
    deliberately no Investigation identity and no subject binding — global
    Evidence conversion is Investigation-independent, and exact Observation
    admission happens later through ``InvestigationEvidence`` at a separate
    boundary.
    """

    semantic_source: SemanticSourceContext


class ToEvidenceConverter(ABC, Generic[TSource]):
    """Pure converter from validated semantic source objects to Evidence.

    Implementations are stateless, reusable, and deterministic: converting
    the same validated object with the same context always yields
    structurally equal immutable :class:`ConvertedEvidence` values.
    ``convert`` is synchronous local mapping performed with no I/O or
    persistence. A converter assigns the deterministic stable Evidence
    identity (derived from the approved source-record identity) but never
    fabricates a persisted observation ID, version, or diff.
    """

    @property
    @abstractmethod
    def semantic_format(self) -> SemanticFormatId:
        """Return the single semantic format this converter owns."""

    @abstractmethod
    def convert(
        self,
        source: TSource,
        context: EvidenceConversionContext,
    ) -> tuple[ConvertedEvidence, ...]:
        """Convert one validated source object into zero or more ConvertedEvidence."""


class ToEvidenceConverterRegistry:
    """Immutable semantic-format-keyed converter registry.

    Exactly one converter may be registered per semantic format; duplicate
    registration fails closed at construction. Lookup is keyed only by
    :class:`SemanticFormatId` — never by SourceId, DatasourceId, provider
    class, protocol, serialization, filename, endpoint, or object shape —
    and an unknown format raises :class:`UnknownSemanticFormatError`.
    There is no global mutable registration, no decorator registration,
    no import-time side effect, and no plugin discovery.
    """

    def __init__(self, converters: Iterable[ToEvidenceConverter[Any]]) -> None:
        """Index the supplied converters by their claimed semantic format.

        The registry is immutable after construction: later mutation of the
        iterable cannot reach it.
        """
        self._by_format: dict[SemanticFormatId, ToEvidenceConverter[Any]] = {}
        for converter in converters:
            semantic_format = converter.semantic_format
            if semantic_format in self._by_format:
                raise DuplicateConverterError(
                    f"a converter is already registered for semantic format "
                    f"{semantic_format.value}"
                )
            self._by_format[semantic_format] = converter

    def get(self, semantic_format: SemanticFormatId) -> ToEvidenceConverter[Any]:
        """Return the converter registered for one semantic format.

        Raises :class:`UnknownSemanticFormatError` when no converter is
        registered; there is no default and no fallback.
        """
        try:
            return self._by_format[semantic_format]
        except KeyError as exc:
            raise UnknownSemanticFormatError(
                f"no converter registered for semantic format {semantic_format.value}"
            ) from exc


def convert_semantic_source_objects(
    objects: tuple[TSource, ...],
    context: EvidenceConversionContext,
    registry: ToEvidenceConverterRegistry,
) -> tuple[ConvertedEvidence, ...]:
    """Flatten 0..N ConvertedEvidence from one bounded tuple of validated objects.

    Each source object is converted through the semantic-format-selected
    converter (`registry.get(context.semantic_source.semantic_format)`), and
    every converter return is concatenated in deterministic order: semantic
    source-object order first, then each converter's return order. The
    helper performs no sorting, no deduplication, no I/O, and no
    persistence; ``objects`` stays a bounded tuple so no unbounded generator
    is ever drained here.
    """
    converter = registry.get(context.semantic_source.semantic_format)
    return tuple(
        converted
        for source_object in objects
        for converted in converter.convert(source_object, context)
    )
