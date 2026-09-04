# SPDX-License-Identifier: AGPL-3.0-only
"""Application port for narrative research retrieval."""

from abc import ABC, abstractmethod

from agentic_threat_investigator.domain.research import ResearchQuery, RetrievedChunk


class ResearchRetrievalError(RuntimeError):
    """Raised when a retriever cannot produce a contract-valid result."""


class ResearchRetriever(ABC):  # pylint: disable=too-few-public-methods
    """Narrow application boundary for bounded research retrieval."""

    @abstractmethod
    async def retrieve(self, query: ResearchQuery) -> list[RetrievedChunk]:
        """Return at most max_results compatible chunks in relevance order."""
