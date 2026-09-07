# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Typed fake providers for deterministic provider-contract and collector tests.

This module is test-only support; no production package may import from it.
The fake implements the application-layer ``EvidenceProvider`` ABC without
network, persistence, or other production dependencies.
"""

from __future__ import annotations

from uuid import UUID

from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderResult,
    validate_investigation_entity,
)
from agentic_threat_investigator.domain.entities import Entity, EntityType


class FakeEvidenceProvider(EvidenceProvider):
    """A small typed fake implementing ``EvidenceProvider`` for tests.

    It exposes a stable test source URN, a deterministic tuple of supported
    entity types, and a configurable canned ``ProviderResult`` returned from
    every supported investigation. The fake honors the full behavioral
    contract of the ABC: an unsupported or invalid entity never receives the
    canned result and instead produces the standard single non-retryable
    ``UNSUPPORTED_INDICATOR`` result attributed to the fake, exactly as a
    production provider must. Every invocation is recorded when
    ``record_calls`` is enabled — including unsupported dispatches — so
    collector tests can detect erroneous provider dispatch. A canned result
    attributed to a different provider is rejected at construction.
    """

    SOURCE_URN = "urn:ati:source:test"
    """Stable test source URN shared by the fake's results and errors."""

    SUPPORTED_TYPES: tuple[EntityType, ...] = (EntityType.DOMAIN,)
    """Deterministic supported entity types for applicability assertions."""

    def __init__(
        self,
        *,
        result: ProviderResult | None = None,
        record_calls: bool = False,
    ) -> None:
        """Initialize with an optional canned result and call recording.

        When ``result`` is omitted, an empty successful result attributed to
        :data:`SOURCE_URN` is returned. A supplied result attributed to any
        other provider is rejected immediately with ``ValueError`` so a
        contract-breaking fixture cannot be constructed.
        """
        if result is not None and result.provider != self.SOURCE_URN:
            raise ValueError(
                "canned ProviderResult provider does not match the fake provider id"
            )
        self._result = result or ProviderResult(provider=self.SOURCE_URN)
        self._record_calls = record_calls
        self.calls: tuple[tuple[UUID, Entity], ...] = ()

    @property
    def id(self) -> str:
        """Return the stable test source URN."""
        return self.SOURCE_URN

    def supports(self, entity: Entity) -> bool:
        """Report support deterministically from :data:`SUPPORTED_TYPES`."""
        return entity.type in self.SUPPORTED_TYPES

    async def investigate(
        self, investigation_id: UUID, entity: Entity
    ) -> ProviderResult:
        """Return the canned result for supported, valid entities only.

        The invocation is recorded first when call recording is enabled
        (including unsupported dispatches). Unsupported or non-canonicalizable
        entities return the standard single non-retryable
        ``UNSUPPORTED_INDICATOR`` result attributed to the fake, never the
        canned result, mirroring the behavioral contract of the ABC.
        """
        if self._record_calls:
            self.calls = (*self.calls, (investigation_id, entity))
        _, error_result = validate_investigation_entity(self, entity)
        if error_result is not None:
            return error_result
        return self._result
