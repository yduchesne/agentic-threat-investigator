# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the filesystem source artifact cache."""

from pathlib import Path

import pytest

from agentic_threat_investigator.infrastructure.source_cache import FileSourceCache


@pytest.mark.asyncio
async def test_write_then_read_roundtrip(tmp_path: Path) -> None:
    """Writing creates parent directories and reads return the artifact."""
    cache = FileSourceCache(tmp_path)
    path = await cache.write("feed/daily/a.json", b"payload")
    assert path.is_file()
    assert path.read_bytes() == b"payload"
    assert await cache.read("feed/daily/a.json") == b"payload"


@pytest.mark.asyncio
async def test_read_missing_key_returns_none(tmp_path: Path) -> None:
    """Absent keys read as None instead of raising."""
    cache = FileSourceCache(tmp_path)
    assert await cache.read("absent.bin") is None


@pytest.mark.asyncio
async def test_write_replaces_atomically_without_temp_debris(
    tmp_path: Path,
) -> None:
    """A second write atomically replaces the first and leaves no temp files."""
    cache = FileSourceCache(tmp_path)
    await cache.write("k.bin", b"first")
    await cache.write("k.bin", b"second")
    assert await cache.read("k.bin") == b"second"
    assert [
        entry.name for entry in tmp_path.iterdir() if entry.name.startswith(".")
    ] == []


@pytest.mark.asyncio
async def test_remove_deletes_and_tolerates_absence(tmp_path: Path) -> None:
    """Removal deletes the artifact and ignores already absent keys."""
    cache = FileSourceCache(tmp_path)
    await cache.write("k.bin", b"payload")
    await cache.remove("k.bin")
    assert await cache.read("k.bin") is None
    await cache.remove("k.bin")


@pytest.mark.asyncio
async def test_get_delegates_to_read(tmp_path: Path) -> None:
    """The compatibility alias returns the same artifact as read."""
    cache = FileSourceCache(tmp_path)
    await cache.write("k.bin", b"payload")
    assert await cache.get("k.bin") == b"payload"
    assert await cache.get("absent.bin") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "key", ["", "/etc/passwd", "../escape", "a/../escape", "a/..", "bad\x00key"]
)
async def test_unsafe_keys_are_rejected(tmp_path: Path, key: str) -> None:
    """Traversal, absolute, empty, and NUL keys never reach the filesystem."""
    cache = FileSourceCache(tmp_path)
    with pytest.raises(ValueError):
        await cache.read(key)
    with pytest.raises(ValueError):
        await cache.write(key, b"payload")
    with pytest.raises(ValueError):
        await cache.remove(key)


@pytest.mark.asyncio
async def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    """A key resolving through a symlink outside the root is rejected."""
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    try:
        (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
        cache = FileSourceCache(tmp_path)
        with pytest.raises(ValueError, match="escapes cache root"):
            await cache.read("linked/escape.bin")
    finally:
        outside.rmdir()


@pytest.mark.asyncio
async def test_paths_stay_inside_the_cache_root(tmp_path: Path) -> None:
    """Returned write paths resolve below the injected root."""
    cache = FileSourceCache(tmp_path)
    path = await cache.write("nested/key.bin", b"payload")
    root = tmp_path.resolve()
    assert root in path.parents
