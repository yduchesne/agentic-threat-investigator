# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic, versioned ATI LLM pricing and known-cost computation.

Pricing is an ATI-owned, code-controlled catalog. Investigation execution
never performs a live price lookup; cost is computed only from authoritative
usage and an explicit, versioned price entry. Unknown pricing yields unknown
cost (``None``), never zero. All monetary arithmetic uses :class:`Decimal`;
binary floats are never used for persisted cost.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal

from agentic_threat_investigator.app.llm_usage import LlmUsage

# Bounded provider/model telemetry identity. Models outside the catalog collapse
# to ``other`` so arbitrary configured model strings can never create unbounded
# metric cardinality.
_UNKNOWN_MODEL_LABEL = "other"
_KNOWN_MODEL_LABELS = frozenset(
    {
        "gpt-4o-mini",
        "gpt-4o",
        "gpt-4.1-mini",
        "deterministic",
    }
)


def bounded_model_label(model: str) -> str:
    """Return a bounded telemetry model label (unknown collapses to ``other``)."""
    return model if model in _KNOWN_MODEL_LABELS else _UNKNOWN_MODEL_LABEL


@dataclass(frozen=True)
class ModelPrice:
    """One versioned price entry for a provider/model pair.

    ``input_price``/``output_price`` are per-token prices in ``currency``.
    ``cached_input_price``/``reasoning_price`` are optional because cached and
    reasoning tokens are not always billed like ordinary tokens.
    """

    provider: str
    model: str
    effective_from: date
    input_price: str
    output_price: str
    currency: str = "USD"
    pricing_id: str = ""
    pricing_version: str = ""
    cached_input_price: str | None = None
    reasoning_price: str | None = None


@dataclass(frozen=True)
class LlmCost:
    """Known itemized and total monetary cost for one usage event."""

    input_cost: Decimal | None
    output_cost: Decimal | None
    cached_cost: Decimal | None
    reasoning_cost: Decimal | None
    total_cost: Decimal | None
    currency: str
    pricing_id: str
    pricing_version: str


class PricingCatalog:
    """Deterministic versioned pricing catalog with explicit resolution rules.

    The catalog is ordered newest-first; ``resolve`` returns the most recent
    entry effective on the accounting date. There is deliberately no network
    or environment lookup.
    """

    def __init__(self, entries: tuple[ModelPrice, ...] = ()) -> None:
        """Bind the immutable catalog entries."""
        self._entries = tuple(entries)

    @property
    def entries(self) -> tuple[ModelPrice, ...]:
        """Return the immutable catalog entries."""
        return self._entries

    def resolve(
        self, provider: str, model: str, *, at: date | None = None
    ) -> ModelPrice | None:
        """Return the effective price entry for ``provider``/``model`` or None."""
        effective = at or date.max
        candidates = [
            entry
            for entry in self._entries
            if entry.provider == provider
            and entry.model == model
            and entry.effective_from <= effective
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda entry: entry.effective_from)

    def compute_cost(self, usage: LlmUsage, price: ModelPrice) -> LlmCost:
        """Compute known itemized/total cost from authoritative usage.

        A component cost is emitted only when both the token value and the
        applicable price are present. ``total_cost`` is the exact sum of the
        known itemized costs; it is unknown when no component is computable.
        Cached and reasoning tokens are never assumed to be billed like
        ordinary tokens.
        """
        input_cost = _component(usage.input_tokens, price.input_price)
        output_cost = _component(usage.output_tokens, price.output_price)
        cached_cost = _component(usage.cached_tokens, price.cached_input_price)
        reasoning_cost = _component(usage.reasoning_tokens, price.reasoning_price)
        known = [c for c in (input_cost, output_cost, cached_cost, reasoning_cost) if c]
        total = sum(known, Decimal(0)) if known else None
        return LlmCost(
            input_cost=input_cost,
            output_cost=output_cost,
            cached_cost=cached_cost,
            reasoning_cost=reasoning_cost,
            total_cost=total,
            currency=price.currency,
            pricing_id=price.pricing_id,
            pricing_version=price.pricing_version,
        )


def _component(tokens: int | None, price: str | None) -> Decimal | None:
    """Return ``tokens * price`` as an exact Decimal, or None when unknown."""
    if tokens is None or price is None:
        return None
    return Decimal(tokens) * Decimal(price)


#: v0.1 deterministic default catalog. Entries are code-controlled and
#: versioned; adding or changing a price requires a new ``effective_from`` and
#: ``pricing_version`` so historical cost never changes.
DEFAULT_PRICING_CATALOG = PricingCatalog(
    (
        ModelPrice(
            provider="openai",
            model="gpt-4o-mini",
            effective_from=date(2024, 7, 18),
            input_price="0.00000015",
            output_price="0.0000006",
            cached_input_price="0.000000075",
            currency="USD",
            pricing_id="openai-gpt-4o-mini",
            pricing_version="2024-07-18",
        ),
        ModelPrice(
            provider="deterministic",
            model="deterministic",
            effective_from=date(2024, 1, 1),
            input_price="0",
            output_price="0",
            currency="USD",
            pricing_id="deterministic",
            pricing_version="v1",
        ),
    )
)


__all__ = [
    "DEFAULT_PRICING_CATALOG",
    "LlmCost",
    "ModelPrice",
    "PricingCatalog",
    "bounded_model_label",
]
