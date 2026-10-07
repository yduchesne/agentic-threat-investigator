# SPDX-License-Identifier: AGPL-3.0-only
"""Application service for durable LLM usage accounting and usage metrics.

One actual model attempt produces exactly one normalized :class:`LlmUsage`
event. This service consumes that single event: it computes known cost from
explicit versioned pricing, emits bounded aggregate usage metrics, and appends
one append-only durable ledger row in a short UnitOfWork that never spans LLM
I/O. Missing usage/cost stays unknown; zero is never fabricated.

Durable-accounting failure policy: metric emission happens from the normalized
event independent of persistence, and a ledger append failure is fail-open
(logged safely) so an observability/accounting outage never fails an
investigation. The exact policy is tested.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from agentic_threat_investigator.app.llm_pricing import (
    DEFAULT_PRICING_CATALOG,
    LlmCost,
    PricingCatalog,
    bounded_model_label,
)
from agentic_threat_investigator.app.llm_usage import LlmUsage, validate_scope_urn
from agentic_threat_investigator.app.persistence.repositories import (
    LlmUsageRecord,
    UnitOfWork,
)
from agentic_threat_investigator.telemetry.attributes import (
    AttributeKeys,
    validate_bounded_attributes,
)
from agentic_threat_investigator.telemetry.metrics import Metrics, get_counter

logger = logging.getLogger(__name__)


class LlmUsageService:
    """Append durable per-invocation usage and export bounded usage metrics."""

    def __init__(
        self,
        uow_factory: Callable[[], UnitOfWork],
        *,
        provider: str,
        model: str,
        pricing_catalog: PricingCatalog = DEFAULT_PRICING_CATALOG,
    ) -> None:
        """Bind the UnitOfWork, bounded provider/model identity, and pricing."""
        if not provider.strip() or not model.strip():
            raise ValueError("provider and model must be non-blank")
        self._uow_factory = uow_factory
        self._provider = provider
        self._model = model
        self._pricing = pricing_catalog

    async def record_usage(
        self,
        *,
        investigation_id: UUID | None,
        scope_urn: str,
        operation_name: str,
        invocation_id: UUID,
        usage: LlmUsage,
        occurred_at: datetime | None = None,
    ) -> LlmUsageRecord | None:
        """Account one successful, authoritative model attempt.

        Emits bounded usage metrics from the normalized event and appends one
        append-only ledger row in a short transaction. Returns the durable
        record, or ``None`` when the fail-open append failed.
        """
        validate_scope_urn(scope_urn)
        if not operation_name.strip():
            raise ValueError("operation_name must not be blank")
        occurred = occurred_at if occurred_at is not None else datetime.now(UTC)
        cost = self._known_cost(usage, occurred)
        self._emit_metrics(scope_urn, operation_name, usage, cost)
        record = LlmUsageRecord(
            scope_urn=scope_urn,
            operation_name=operation_name,
            invocation_id=invocation_id,
            provider=self._provider,
            model=self._model,
            occurred_at=occurred,
            investigation_id=investigation_id,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cached_tokens=usage.cached_tokens,
            reasoning_tokens=usage.reasoning_tokens,
            total_tokens=usage.total_tokens,
            input_cost=cost.input_cost if cost else None,
            output_cost=cost.output_cost if cost else None,
            cached_cost=cost.cached_cost if cost else None,
            reasoning_cost=cost.reasoning_cost if cost else None,
            total_cost=cost.total_cost if cost else None,
            currency=cost.currency if cost else None,
            pricing_id=cost.pricing_id if cost else None,
            pricing_version=cost.pricing_version if cost else None,
        )
        return await self._append(record)

    async def _append(self, record: LlmUsageRecord) -> LlmUsageRecord | None:
        """Append the ledger row fail-open in a short transaction."""
        try:
            async with self._uow_factory() as uow:
                return await uow.llm_usage.append(record)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - observability-owned fail-open boundary
            logger.warning(
                "durable LLM usage accounting append failed",
                extra={"operation_name": record.operation_name},
            )
            return None

    def _known_cost(self, usage: LlmUsage, occurred_at: datetime) -> LlmCost | None:
        """Return known cost from versioned pricing, or ``None`` when unknown."""
        price = self._pricing.resolve(
            self._provider, self._model, at=occurred_at.date()
        )
        if price is None:
            return None
        return self._pricing.compute_cost(usage, price)

    def _emit_metrics(
        self,
        scope_urn: str,
        operation_name: str,
        usage: LlmUsage,
        cost: LlmCost | None,
    ) -> None:
        """Emit bounded aggregate usage counters from the normalized event."""
        attributes = validate_bounded_attributes(
            {
                AttributeKeys.OPERATION: operation_name,
                AttributeKeys.LLM_SCOPE: scope_urn,
                AttributeKeys.LLM_PROVIDER: self._provider,
                AttributeKeys.LLM_MODEL: bounded_model_label(self._model),
                AttributeKeys.OUTCOME: "success",
            }
        )
        get_counter(Metrics.LLM_CALLS).add(1, attributes)
        self._add_tokens(Metrics.LLM_TOKENS_INPUT, usage.input_tokens, attributes)
        self._add_tokens(Metrics.LLM_TOKENS_OUTPUT, usage.output_tokens, attributes)
        self._add_tokens(Metrics.LLM_TOKENS_CACHED, usage.cached_tokens, attributes)
        self._add_tokens(
            Metrics.LLM_TOKENS_REASONING, usage.reasoning_tokens, attributes
        )
        self._add_tokens(Metrics.LLM_TOKENS_TOTAL, usage.total_tokens, attributes)
        if cost is not None and cost.total_cost is not None:
            get_counter(Metrics.LLM_COST).add(float(cost.total_cost), attributes)

    @staticmethod
    def _add_tokens(
        metric: str, tokens: int | None, attributes: dict[str, str]
    ) -> None:
        """Increment one token counter only when the value is authoritative."""
        if tokens is not None and tokens > 0:
            get_counter(metric).add(tokens, attributes)


__all__ = ["LlmUsageService"]
