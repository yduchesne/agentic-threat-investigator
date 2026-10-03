# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI-owned structural STIX 2.1 Patterning whitelist adapter (PR 33B).

This module isolates the third-party OASIS ``stix2-patterns`` grammar
dependency behind an ATI-owned pure adapter. Indicator ``pattern`` strings
are parsed by the maintained standards parser (:class:`Pattern`) into ANTLR
parse trees; ATI then applies a narrow structural whitelist by walking the
parse tree with an ATI-owned walker that duck-types the ANTLR visitor
protocol. No regex, string
splitting, substring matching, or handwritten lexer ever re-parses a
pattern: the parser establishes syntax/structure, and this adapter only
proves that the **entire** tree is composed of approved non-temporal
IOC equality leaves.

The three-way outcome contract:

- ``SUPPORTED``: the whole pattern is one non-temporal observation
  expression composed solely of approved equality leaves; the ordered
  left-to-right leaf values (exact STIX object type + raw string-literal
  value) are returned without deduplication or sorting.
- ``VALID_BUT_UNSUPPORTED``: the pattern is syntactically valid STIX
  Patterning but uses a construct outside the approved whitelist; ATI
  converts it to zero Evidence. This is never a failure.
- ``MALFORMED``: the pattern is not syntactically valid STIX Patterning;
  the conversion boundary fails closed with a bounded error.

The adapter is pure: it performs no I/O, no network, no clock or random
reads, no writing, and no secret resolution. It never includes pattern
content in messages: a malformed parse is reported as a typed status (with
``error_kind``) whose text contains no input echo (the third-party parser's
parse errors can contain the offending input text and must never be
propagated verbatim).

Approved leaves (exact, total):

.. code-block:: text

    domain-name:value = '<string literal>'
    ipv4-addr:value = '<string literal>'
    ipv6-addr:value = '<string literal>'

Approved composition is exactly one or more of those leaves combined with
``AND``/``OR`` and parentheses. Arrays of brackets (``[a] OR [b]``) are
approved; everything temporal or otherwise unsupported (``FOLLOWEDBY``,
``WITHIN``, ``START ... STOP``, ``REPEATS``, ``MATCHES``, ``LIKE``,
``ISSUBSET``, ``ISSUPERSET``, inequalities, sets, ``EXISTS``, ``!=``,
``NOT``-prefixed operators, extra path steps, wildcards, indexes, or
non-string comparison literals) makes the whole pattern
``VALID_BUT_UNSUPPORTED``. Mixed approved/unsupported trees are never
partially extracted.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from stix2patterns.exceptions import ParseException
from stix2patterns.pattern import Pattern

__all__ = [
    "APPROVED_STIX_IOC_OBJECT_TYPES",
    "Stix21PatternInterpretation",
    "Stix21PatternStatus",
    "interpret_stix21_pattern",
]

APPROVED_STIX_IOC_OBJECT_TYPES: frozenset[str] = frozenset(
    {"domain-name", "ipv4-addr", "ipv6-addr"}
)
"""Exact STIX object types whose ``value`` path may produce an IOC leaf.

Membership is deliberate and total; no other object type or path ever
produces an approved comparison.
"""


class Stix21PatternStatus(str, Enum):
    """Three-way deterministic outcome of the STIX pattern whitelist.

    ``SUPPORTED`` means the whole pattern is an approved composition of
    approved IOC equality leaves. ``VALID_BUT_UNSUPPORTED`` means the
    pattern is syntactically valid STIX Patterning that ATI does not
    convert (zero Evidence is a success). ``MALFORMED`` means the pattern
    is not syntactically valid STIX Patterning at all; the conversion
    boundary treats that as a contract failure.
    """

    SUPPORTED = "supported"
    VALID_BUT_UNSUPPORTED = "valid_but_unsupported"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class Stix21PatternInterpretation:
    """One deterministic structural interpretation of a STIX pattern.

    ``status`` is the three-way verdict. For ``SUPPORTED`` patterns,
    ``iocs`` carries the ordered left-to-right approved leaves as
    ``{"stix_type", "value"}`` where ``stix_type`` is one of
    :data:`APPROVED_STIX_IOC_OBJECT_TYPES` and ``value`` is the decoded
    string-literal comparison value (unquoted, still in its source form —
    ATI canonicalization is applied by the Evidence converter only after
    the whole tree is admitted). ``iocs`` is empty for the two non-SUPPORTED
    statuses. ``error_kind`` is a fixed safe label used only for the
    ``MALFORMED`` status and never carries parser or pattern content.
    """

    status: Stix21PatternStatus
    iocs: tuple[dict[str, str], ...]
    error_kind: str | None = None


class _StixIocWhitelistWalker:
    """Structural whole-tree whitelist walker over a STIX pattern parse tree.

    Implements the narrow approved subset as a walker: any approved leaf
    is collected in source order, and any construct outside the whitelist
    marks the whole tree unsupported. The walker never inspects raw pattern
    text beyond the lexer-provided token text of individual approved
    literal values.

    Dispatch duck-types the ANTLR ParseTreeVisitor protocol: every rule
    context's ``accept(visitor)`` invokes ``visitor.visit<Rule>`` when the
    method exists and otherwise ``visitor.visitChildren``, and terminal
    nodes invoke ``visitor.visitTerminal``. No third-party visitor base
    class is subclassed, so the walker stays a self-contained ATI-owned
    adapter over the third-party syntax parser.
    """

    def __init__(self) -> None:
        """Initialize the empty ordered leaf accumulator."""
        self._iocs: list[dict[str, str]] = []
        self._unsupported = False

    def visit(self, tree: Any) -> None:
        """Dispatch on one parse-tree node via the ANTLR accept protocol."""
        tree.accept(self)

    def visitChildren(self, ctx: Any) -> None:
        """Descend into every child of one rule context, unless done."""
        if self._unsupported:
            return
        for child in ctx.getChildren():
            child.accept(self)

    def visitTerminal(self, _node: Any) -> None:
        """Ignore individual terminals; rule contexts carry the meaning."""

    def visitErrorNode(self, _node: Any) -> None:
        """Ignore synthetic error nodes (never produced by a valid parse)."""

    def _mark_unsupported(self, _ctx: Any) -> None:
        """Flag the whole tree unsupported and stop traversal."""
        self._unsupported = True

    def _visit_children(self, ctx: Any) -> None:
        """Continue descending unless the tree is already unsupported."""
        if self._unsupported:
            return None
        return self.visitChildren(ctx)

    def visitPattern(self, ctx: Any) -> Any:
        """Visit the observation-expression list beneath the root."""
        return self._visit_children(ctx)

    def visitObservationExpressions(self, ctx: Any) -> Any:
        """Reject any FOLLOWEDBY-timed observation-expression chain."""
        if getattr(ctx, "FOLLOWEDBY", lambda: None)() is not None:
            self._mark_unsupported(ctx)
            return None
        return self._visit_children(ctx)

    def visitObservationExpressionOr(self, ctx: Any) -> Any:
        """Approved observation-level ``OR``; descend into both sides."""
        return self._visit_children(ctx)

    def visitObservationExpressionAnd(self, ctx: Any) -> Any:
        """Approved observation-level ``AND``; descend into both sides."""
        return self._visit_children(ctx)

    def visitObservationExpression(self, ctx: Any) -> Any:
        """Descend into the unlabeled observation-expression child."""
        return self._visit_children(ctx)

    def visitObservationExpressionCompound(self, ctx: Any) -> Any:
        """Approved parenthesized observation expressions; descend.

        The inner ``observationExpressions`` is itself checked for
        ``FOLLOWEDBY`` by :meth:`visitObservationExpressions`.
        """
        return self._visit_children(ctx)

    def visitObservationExpressionSimple(self, ctx: Any) -> Any:
        """Approved bracketed comparison expression; descend."""
        return self._visit_children(ctx)

    def visitObservationExpressionWithin(self, ctx: Any) -> Any:
        """Reject the ``WITHIN`` temporal qualifier."""
        self._mark_unsupported(ctx)
        return None

    def visitObservationExpressionStartStop(self, ctx: Any) -> Any:
        """Reject the ``START ... STOP`` temporal qualifier."""
        self._mark_unsupported(ctx)
        return None

    def visitObservationExpressionRepeated(self, ctx: Any) -> Any:
        """Reject the ``REPEATS`` temporal qualifier."""
        self._mark_unsupported(ctx)
        return None

    def visitComparisonExpression(self, ctx: Any) -> Any:
        """Approved comparison-level ``OR``; descend into operands."""
        return self._visit_children(ctx)

    def visitComparisonExpressionAnd(self, ctx: Any) -> Any:
        """Approved comparison-level ``AND``; descend into operands."""
        return self._visit_children(ctx)

    def visitPropTestParen(self, ctx: Any) -> Any:
        """Approved parenthesized comparison; descend."""
        return self._visit_children(ctx)

    def visitPropTestEqual(self, ctx: Any) -> Any:
        """The only approved leaf: an exact equality against a string literal.

        ``object_path == '<string>'`` with an approved ``<object-type>:value``
        path and nothing else (no ``!=``, no ``NOT`` prefix). Any other
        property test (regex, LIKE, subset, superset, order, sets, EXISTS)
        is dispatched to its own unsupported handler, so only equality can
        reach this method.
        """
        if (
            getattr(ctx, "NEQ", lambda: None)() is not None
            or getattr(ctx, "NOT", lambda: None)() is not None
        ):
            self._mark_unsupported(ctx)
            return None
        path = ctx.objectPath()
        literal = ctx.primitiveLiteral()
        if path is None or literal is None:
            self._mark_unsupported(ctx)
            return None
        leaf = _extract_approved_leaf(path, literal)
        if leaf is None:
            self._mark_unsupported(ctx)
            return None
        self._iocs.append(leaf)
        return None

    def visitPropTestRegex(self, ctx: Any) -> Any:
        """Reject ``MATCHES`` comparisons."""
        self._mark_unsupported(ctx)
        return None

    def visitPropTestLike(self, ctx: Any) -> Any:
        """Reject ``LIKE`` comparisons."""
        self._mark_unsupported(ctx)
        return None

    def visitPropTestIsSubset(self, ctx: Any) -> Any:
        """Reject ``ISSUBSET`` comparisons."""
        self._mark_unsupported(ctx)
        return None

    def visitPropTestIsSuperset(self, ctx: Any) -> Any:
        """Reject ``ISSUPERSET`` comparisons."""
        self._mark_unsupported(ctx)
        return None

    def visitPropTestOrder(self, ctx: Any) -> Any:
        """Reject inequality/range comparisons."""
        self._mark_unsupported(ctx)
        return None

    def visitPropTestSet(self, ctx: Any) -> Any:
        """Reject ``IN`` set comparisons."""
        self._mark_unsupported(ctx)
        return None

    def visitPropTestExists(self, ctx: Any) -> Any:
        """Reject ``EXISTS`` path tests."""
        self._mark_unsupported(ctx)
        return None


def _extract_approved_leaf(object_path: Any, literal: Any) -> dict[str, str] | None:
    """Extract one approved equality leaf, or ``None`` when not approved.

    Requires the exact ``<object-type>:value`` path with no additional
    path steps (no key steps, indexes, or wildcards) and a plain string
    literal operand (never a boolean, number, timestamp, binary, or hex
    literal). The returned leaf is ``{"stix_type", "value"}`` where
    ``value`` is the decoded (unquoted, unescaped) string-literal text.
    """
    object_ctx = object_path.objectType()
    first = object_path.firstPathComponent()
    if object_ctx is None or first is None:
        return None
    object_type = object_ctx.getText()
    if object_type not in APPROVED_STIX_IOC_OBJECT_TYPES:
        return None
    if first.getText() != "value":
        return None
    if object_path.objectPathComponent():
        return None
    orderable = literal.orderableLiteral()
    if orderable is None or literal.BoolLiteral() is not None:
        return None
    string_token = orderable.StringLiteral()
    if string_token is None:
        return None
    if any(
        getattr(orderable, member, lambda: None)() is not None
        for member in (
            "BinaryLiteral",
            "FloatNegLiteral",
            "FloatPosLiteral",
            "HexLiteral",
            "IntNegLiteral",
            "IntPosLiteral",
            "TimestampLiteral",
        )
    ):
        return None
    return {
        "stix_type": object_type,
        "value": _unquote_stix_string_literal(string_token.getText()),
    }


def _unquote_stix_string_literal(token_text: str) -> str:
    """Decode one lexer-produced STIX string literal to plain text.

    The parser itself delivered ``token_text`` including the surrounding
    single quotes; decoding removes the quotes and resolves the two STIX
    single-quote escapes (``\\'`` -> ``'`` and ``\\\\`` -> ``\\``). This is
    value decoding of a lexer token, not grammar parsing, and mirrors the
    maintained library's own decoder. Deterministic and pure.
    """
    return token_text[1:-1].replace("\\'", "'").replace("\\\\", "\\")


def interpret_stix21_pattern(pattern: str) -> Stix21PatternInterpretation:
    """Interpret one STIX 2.1 ``pattern`` string through the whitelist.

    A syntactically malformed pattern returns a ``MALFORMED`` interpretation
    with a fixed safe ``error_kind`` (no parser text, which may echo the
    input, is ever exposed). A syntactically valid pattern that is not an
    approved whole-tree composition returns ``VALID_BUT_UNSUPPORTED`` with
    zero leaves. An approved whole-tree pattern returns ``SUPPORTED`` with
    the ordered left-to-right leaf values. The call is pure and performs no
    I/O.
    """
    try:
        tree = Pattern(pattern)
    except ParseException:
        return Stix21PatternInterpretation(
            status=Stix21PatternStatus.MALFORMED,
            iocs=(),
            error_kind="indicator_pattern_syntax",
        )
    visitor = _StixIocWhitelistWalker()
    tree.visit(visitor)
    if visitor._unsupported:
        return Stix21PatternInterpretation(
            status=Stix21PatternStatus.VALID_BUT_UNSUPPORTED, iocs=()
        )
    return Stix21PatternInterpretation(
        status=Stix21PatternStatus.SUPPORTED,
        iocs=tuple(visitor._iocs),
    )
