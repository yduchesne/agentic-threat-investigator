# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33B STIX 2.1 Patterning whitelist adapter tests.

Pins the ATI-owned structural adapter around the maintained OASIS
``stix2-patterns`` parser: the three-way outcome (SUPPORTED with ordered
left-to-right leaves, VALID_BUT_UNSUPPORTED, MALFORMED), the exact approved
equality-only leaf subset, whole-tree whitelisting with no partial
extraction, deterministic error classification that never echoes pattern
content, and the module-level isolation contract (no regex/string-splitting
grammar implementation, no network/clock/random behavior).
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from agentic_threat_investigator.infrastructure.datasources import stix21_pattern
from agentic_threat_investigator.infrastructure.datasources.stix21_pattern import (
    APPROVED_STIX_IOC_OBJECT_TYPES,
    Stix21PatternInterpretation,
    Stix21PatternStatus,
    interpret_stix21_pattern,
)

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parents[4]


def _supported(pattern: str) -> tuple[dict[str, str], ...]:
    """Interpret one pattern and require the SUPPORTED status."""
    interpretation = interpret_stix21_pattern(pattern)
    assert interpretation.status is Stix21PatternStatus.SUPPORTED
    return interpretation.iocs


def _unsupported(pattern: str) -> None:
    """Interpret one pattern and require VALID_BUT_UNSUPPORTED."""
    interpretation = interpret_stix21_pattern(pattern)
    assert interpretation.status is Stix21PatternStatus.VALID_BUT_UNSUPPORTED
    assert interpretation.iocs == ()


def _malformed(pattern: str) -> None:
    """Interpret one pattern and require MALFORMED with a safe error kind."""
    interpretation = interpret_stix21_pattern(pattern)
    assert interpretation.status is Stix21PatternStatus.MALFORMED
    assert interpretation.iocs == ()
    assert interpretation.error_kind == "indicator_pattern_syntax"


class TestApprovedLeaves:
    """Approved equality leaves and value decoding."""

    def test_approved_object_types_are_exact_three(self) -> None:
        """Only domain-name/ipv4-addr/ipv6-addr value paths are approved."""
        assert frozenset({"domain-name", "ipv4-addr", "ipv6-addr"}) == (
            APPROVED_STIX_IOC_OBJECT_TYPES
        )

    def test_domain_leaf_value_decoded(self) -> None:
        """A single domain equality yields the decoded unquoted value."""
        assert _supported("[domain-name:value = 'example.test']") == (
            {"stix_type": "domain-name", "value": "example.test"},
        )

    def test_ipv4_leaf_value_decoded(self) -> None:
        """A single IPv4 equality yields the decoded unquoted value."""
        assert _supported("[ipv4-addr:value = '192.0.2.1']") == (
            {"stix_type": "ipv4-addr", "value": "192.0.2.1"},
        )

    def test_ipv6_leaf_value_decoded(self) -> None:
        """A single IPv6 equality yields the decoded unquoted value."""
        assert _supported("[ipv6-addr:value = '2001:db8::1']") == (
            {"stix_type": "ipv6-addr", "value": "2001:db8::1"},
        )

    def test_escaped_quote_value_decoded(self) -> None:
        """A ``\\'``-escaped string literal decodes to a plain quote."""
        assert _supported("[domain-name:value = 'it\\'s.test']") == (
            {"stix_type": "domain-name", "value": "it's.test"},
        )

    def test_escaped_backslash_value_decoded(self) -> None:
        """A ``\\\\``-escaped string literal decodes to a backslash."""
        assert _supported("[domain-name:value = 'back\\\\slash.test']") == (
            {"stix_type": "domain-name", "value": "back\\slash.test"},
        )

    def test_duplicate_leaves_preserved_in_order(self) -> None:
        """Exact duplicate leaves stay present and ordered."""
        assert _supported(
            "[ipv4-addr:value = '192.0.2.1' OR ipv4-addr:value = '192.0.2.1']"
        ) == (
            {"stix_type": "ipv4-addr", "value": "192.0.2.1"},
            {"stix_type": "ipv4-addr", "value": "192.0.2.1"},
        )


class TestBooleanComposition:
    """Approved AND/OR and parenthesis composition order."""

    def test_and_order_preserved(self) -> None:
        """Comparison-level AND preserves left-to-right leaf order."""
        assert _supported(
            "[domain-name:value = 'a.test' AND ipv4-addr:value = '192.0.2.1']"
        ) == (
            {"stix_type": "domain-name", "value": "a.test"},
            {"stix_type": "ipv4-addr", "value": "192.0.2.1"},
        )

    def test_or_order_preserved(self) -> None:
        """Observation-level OR preserves left-to-right leaf order."""
        assert _supported(
            "[domain-name:value = 'a.test'] OR [ipv4-addr:value = '192.0.2.1']"
        ) == (
            {"stix_type": "domain-name", "value": "a.test"},
            {"stix_type": "ipv4-addr", "value": "192.0.2.1"},
        )

    def test_nested_parentheses_deterministic(self) -> None:
        """Nested approved parentheses preserve deterministic leaf order."""
        assert _supported(
            "[domain-name:value = 'a.test' AND "
            "(ipv4-addr:value = '192.0.2.1' OR ipv6-addr:value = '2001:db8::1')]"
        ) == (
            {"stix_type": "domain-name", "value": "a.test"},
            {"stix_type": "ipv4-addr", "value": "192.0.2.1"},
            {"stix_type": "ipv6-addr", "value": "2001:db8::1"},
        )

    def test_bracketed_or_within_one_pattern(self) -> None:
        """Bracketed parenthesized OR inside one bracket stays approved."""
        assert _supported(
            "[domain-name:value = 'a.test' OR ipv4-addr:value = '192.0.2.1']"
        ) == (
            {"stix_type": "domain-name", "value": "a.test"},
            {"stix_type": "ipv4-addr", "value": "192.0.2.1"},
        )

    def test_three_way_or_left_to_right(self) -> None:
        """A three-way OR preserves strict left-to-right leaf order."""
        assert _supported(
            "[domain-name:value = 'a.test'] OR [ipv4-addr:value = '192.0.2.1'] "
            "OR [ipv6-addr:value = '2001:db8::1']"
        ) == (
            {"stix_type": "domain-name", "value": "a.test"},
            {"stix_type": "ipv4-addr", "value": "192.0.2.1"},
            {"stix_type": "ipv6-addr", "value": "2001:db8::1"},
        )


class TestValidButUnsupported:
    """Syntactically valid patterns outside the whitelist produce no leaves."""

    @pytest.mark.parametrize(
        "pattern",
        [
            "[domain-name:value MATCHES '^evil']",
            "[domain-name:value LIKE 'a%']",
            "[ipv4-addr:value ISSUBSET '192.0.2.0/24']",
            "[ipv4-addr:value ISSUPERSET '10.0.0.0/8']",
            "[domain-name:value > 'zzz']",
            "[domain-name:value < 'aaa']",
            "[domain-name:value >= 'aaa']",
            "[domain-name:value <= 'zzz']",
            "[domain-name:value != 'example.test']",
            "[domain-name:value NOT = 'example.test']",
            "[domain-name:value IN ('a.test', 'b.test')]",
            "[file:hashes.'SHA-256' = 'abc']",
            "[url:value = 'https://example.test']",
            "[file:name = 'x.exe']",
            "[ipv4-addr:value[0] = 'x']",
            "[ipv4-addr:value[*] = 'x']",
            "[domain-name:value = true]",
            "[ipv4-addr:value = 42]",
            "[domain-name:value = 3.14]",
            "[x-custom:value = 'x']",
        ],
    )
    def test_unsupported_constructs(self, pattern: str) -> None:
        """Each non-whitelist construct yields zero leaves, never a failure."""
        _unsupported(pattern)

    def test_mixed_supported_unsupported_whole_tree_unsupported(self) -> None:
        """A mixed pattern is never partially extracted."""
        _unsupported("[domain-name:value = 'a.test' AND file:name = 'x.exe']")

    def test_followedby_unsupported(self) -> None:
        """FOLLOWEDBY timing chains are unsupported as a whole."""
        _unsupported(
            "[domain-name:value = 'a.test'] FOLLOWEDBY [ipv4-addr:value = '192.0.2.1']"
        )

    def test_within_qualifier_unsupported(self) -> None:
        """WITHIN qualifies an observation as temporal and unsupported."""
        _unsupported("[domain-name:value = 'a.test'] WITHIN 5 SECONDS")

    def test_repeats_qualifier_unsupported(self) -> None:
        """REPEATS qualifies an observation as temporal and unsupported."""
        _unsupported("[domain-name:value = 'a.test'] REPEATS 3 TIMES")

    def test_compound_followedby_unsupported(self) -> None:
        """FOLLOWEDBY hidden inside parentheses stays whole-tree unsupported."""
        _unsupported(
            "([domain-name:value = 'a.test'] FOLLOWEDBY "
            "[ipv4-addr:value = '192.0.2.1'])"
        )

    def test_non_string_literal_unsupported(self) -> None:
        """A non-string literal operand in a valid comparison is unsupported."""
        _unsupported("[domain-name:value = 123]")


class TestMalformedSyntax:
    """Syntactically invalid patterns are classified MALFORMED safely."""

    @pytest.mark.parametrize(
        "pattern",
        [
            "",
            "   ",
            "domain-name:value = 'example.test'",
            "[x= 'a']",
            "[domain-name:value = 'unterminated]",
            "[domain-name:value = 'a.test'] trailing",
            "[domain-name:value =",
            "[domain-name:value = 2026-01-01T00:00:00Z]",
            "[ipv4-addr:value = 203.0.113.42]",
            "[domain-name:value = 3.14e5]",
        ],
    )
    def test_malformed_syntax(self, pattern: str) -> None:
        """Each malformed pattern is MALFORMED with a safe error kind."""
        _malformed(pattern)

    def test_malformed_error_kind_does_not_echo_input(self) -> None:
        """The MALFORMED status never carries parser or pattern content."""
        interpretation = interpret_stix21_pattern(
            "[sensitive-super-secret-pattern = 'x']"
        )
        assert interpretation.status is Stix21PatternStatus.MALFORMED
        assert interpretation.error_kind == "indicator_pattern_syntax"
        assert "secret" not in interpretation.error_kind


class TestAdapterContract:
    """Determinism and module isolation of the adapter."""

    def test_interpretation_is_frozen_dataclass(self) -> None:
        """Results are immutable frozen dataclass values."""
        interpretation = interpret_stix21_pattern("[domain-name:value = 'a.test']")
        assert isinstance(interpretation, Stix21PatternInterpretation)
        with pytest.raises(AttributeError):
            interpretation.iocs = ()  # type: ignore[misc]

    def test_deterministic_repeat(self) -> None:
        """Repeated interpretation of one pattern is structural-equal."""
        pattern = "[domain-name:value = 'a.test' OR ipv4-addr:value = '192.0.2.1']"
        assert interpret_stix21_pattern(pattern) == interpret_stix21_pattern(pattern)

    def test_no_regex_grammar_implementation(self) -> None:
        """The adapter never regex-parses or string-splits a pattern."""
        source = inspect.getsource(stix21_pattern)
        assert "import re" not in source
        assert "re.compile" not in source
        assert "re.search" not in source
        assert "re.match" not in source
        assert "re.fullmatch" not in source
        assert ".split(" not in source
        # The maintained standards parser is the only grammar boundary.
        assert "stix2patterns" in source

    def test_no_network_clock_random_behavior(self) -> None:
        """The adapter performs no network/clock/random I/O or imports."""
        source = inspect.getsource(stix21_pattern)
        for banned in (
            "import httpx",
            "import requests",
            "import socket",
            "import urllib",
            "import aiohttp",
            "import time",
            "import random",
            "import secrets",
            "import os",
            "datetime",
            "async def",
            "await ",
        ):
            assert banned not in source
