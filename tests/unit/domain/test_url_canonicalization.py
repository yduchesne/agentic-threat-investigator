# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the v0.1 canonical URL identity contract.

The matrix covers the accepted normalizations, the conservative
preservation rules, and every documented rejection of the
``canonicalize_url`` contract.
"""

import pytest

from agentic_threat_investigator.domain.entities import (
    EntityType,
    canonicalize,
    canonicalize_url,
)

# -- Accepted normalizations --------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # Scheme and DNS host case.
        ("http://example.com", "http://example.com/"),
        ("HTTPS://EXAMPLE.COM/Path", "https://example.com/Path"),
        ("HtTp://ExAmPlE.CoM/", "http://example.com/"),
        # IDNA host.
        ("http://MÜNCHEN.de/", "http://xn--mnchen-3ya.de/"),
        ("http://xn--mnchen-3ya.de/", "http://xn--mnchen-3ya.de/"),
        # IPv4 host.
        ("http://192.0.2.1/a", "http://192.0.2.1/a"),
        # IPv6 host with and without brackets.
        ("http://[2001:0DB8:0000::1]/a", "http://[2001:db8::1]/a"),
        ("http://[2001:db8::1]:80/x", "http://[2001:db8::1]/x"),
        ("https://[2001:db8::1]/", "https://[2001:db8::1]/"),
        # Default port omission.
        ("http://example.com:80/", "http://example.com/"),
        ("https://example.com:443/", "https://example.com/"),
        # Non-default port preserved.
        ("http://example.com:8080/", "http://example.com:8080/"),
        ("https://example.com:8443/p", "https://example.com:8443/p"),
        # Empty path becomes "/".
        ("http://example.com", "http://example.com/"),
        ("https://example.com", "https://example.com/"),
        # Explicit "/" stays "/".
        ("http://example.com/", "http://example.com/"),
        # Query preserved verbatim, including parameter order.
        ("http://example.com/p?b=2&a=1", "http://example.com/p?b=2&a=1"),
        ("http://example.com/p?a=1&a=2", "http://example.com/p?a=1&a=2"),
        # Trailing slash in a non-empty path is preserved.
        ("http://example.com/dir/", "http://example.com/dir/"),
        # Percent-encoding preserved byte-for-byte.
        (
            "http://example.com/a%20b%2fc?x=%41",
            "http://example.com/a%20b%2fc?x=%41",
        ),
        # Surrounding whitespace is stripped like other canonicalizers.
        ("  http://example.com/ ", "http://example.com/"),
        # Terminal DNS root dot on the host.
        ("http://example.com./", "http://example.com/"),
    ],
)
def test_canonical_url_accepted(raw: str, expected: str) -> None:
    """Valid URLs canonicalize to the documented identity form."""

    assert canonicalize_url(raw) == expected


def test_url_registered_in_shared_dispatch() -> None:
    """EntityType.URL participates in the shared canonicalize() dispatch."""

    assert canonicalize(EntityType.URL, "HTTP://Example.COM") == "http://example.com/"


def test_canonical_url_is_idempotent() -> None:
    """Canonicalizing a canonical URL is a fixed point."""

    canonical = canonicalize_url("HTTPS://Example.COM:8443/a%20b?y=2&x=1")

    assert canonicalize_url(canonical) == canonical


def test_canonical_equivalents_produce_identical_output() -> None:
    """Meaning-preserving spellings canonicalize to one identity."""

    spellings = [
        "HTTP://EXAMPLE.COM:80/a%20b",
        "http://example.com/a%20b",
        "http://EXAMPLE.com./a%20b",
        " http://example.com/a%20b ",
    ]
    canonicalized = {canonicalize_url(spelling) for spelling in spellings}

    assert canonicalized == {"http://example.com/a%20b"}


@pytest.mark.parametrize(
    ("left", "right"),
    [
        # Different paths.
        ("http://example.com/a", "http://example.com/b"),
        # Different queries.
        ("http://example.com/p?a=1", "http://example.com/p?a=2"),
        # Query ordering is significant under the conservative contract.
        ("http://example.com/p?a=1&b=2", "http://example.com/p?b=2&a=1"),
        # Different ports.
        ("http://example.com:8080/", "http://example.com/"),
        # Percent-encoded octet differences are significant.
        ("http://example.com/a%2fb", "http://example.com/a%2Fb"),
        ("http://example.com/a%20b", "http://example.com/a%21b"),
        # Trailing slash inside a path is significant.
        ("http://example.com/dir", "http://example.com/dir/"),
        # Different schemes.
        ("http://example.com/", "https://example.com/"),
    ],
)
def test_meaningfully_different_urls_remain_different(left: str, right: str) -> None:
    """URLs that differ in preserved components never share an identity."""

    assert canonicalize_url(left) != canonicalize_url(right)


# -- Rejections ----------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        # Userinfo.
        "http://user:pass@example.com/",
        "http://user@example.com/",
        # Fragments.
        "http://example.com/p#frag",
        "http://example.com/p#",
        # Missing host.
        "http:///path",
        "http://",
        # Unsupported schemes.
        "ftp://example.com/",
        "file:///etc/passwd",
        "mailto:user@example.com",
        "ws://example.com/",
        # Invalid ports.
        "http://example.com:0/",
        "http://example.com:65536/",
        "http://example.com:port/",
        # Embedded whitespace.
        "http://exa mple.com/",
        "http://example.com/pa th",
        "http://example.com/\t",
        # Control characters.
        "http://example.com/\x00",
        "http://example.com/\x1f",
        "http://example.com/\x7f",
        # Invalid DNS hosts.
        "http://under_score.example.com/",
        "http://example.com../",
        "http://-leadinghyphen.example.com/",
        # Malformed percent encoding.
        "http://example.com/%zz",
        "http://example.com/%2",
        "http://example.com/%",
        "http://example.com/p?q=%A",
        # Malformed IPv6.
        "http://[2001:db8::1/x",
        "http://[not-an-ip]/",
        # Empty and garbage input.
        "",
        "   ",
        "not a url",
    ],
)
def test_canonical_url_rejected(raw: str) -> None:
    """Inputs outside the v0.1 contract raise ValueError."""

    with pytest.raises(ValueError):
        canonicalize_url(raw)
