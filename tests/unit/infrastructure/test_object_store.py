# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for URI-oriented filesystem artifact storage."""

from pathlib import Path

import pytest

from agentic_threat_investigator.infrastructure.object_store import (
    ArtifactNotFoundError,
    FileSystemObjectStore,
    object_store_for_uri,
)


def _uri(path: Path) -> str:
    """Support the test uri behavior."""
    return path.absolute().as_uri()


@pytest.mark.asyncio
async def test_write_read_replace_and_remove(tmp_path: Path) -> None:
    """Verify write read replace and remove."""
    store = FileSystemObjectStore(tmp_path)
    target = tmp_path / "feed" / "input.json"
    path = await store.write(_uri(target), b"first")
    assert path == target
    assert await store.read(_uri(target)) == b"first"
    await store.write(_uri(target), b"second")
    assert await store.read(_uri(target)) == b"second"
    assert not list(target.parent.glob(f".{target.name}.*"))
    await store.remove(_uri(target))
    await store.remove(_uri(target))
    with pytest.raises(ArtifactNotFoundError):
        await store.read(_uri(target))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "uri",
    [
        "s3://bucket/key",
        "file://localhost/tmp/input",
        "file://user:secret@localhost/tmp/input",
        "file:///tmp/input?query=1",
        "file:///tmp/input#fragment",
        "file:///tmp/bad%00name",
        "file:",
    ],
)
async def test_rejects_unsupported_or_malformed_uris(tmp_path: Path, uri: str) -> None:
    """Verify rejects unsupported or malformed uris."""
    store = FileSystemObjectStore(tmp_path)
    with pytest.raises(ValueError):
        await store.read(uri)


@pytest.mark.asyncio
async def test_rejects_path_outside_root_and_symlink_escape(tmp_path: Path) -> None:
    """Verify rejects path outside root and symlink escape."""
    store = FileSystemObjectStore(tmp_path)
    with pytest.raises(ValueError, match="escapes"):
        await store.read(_uri(tmp_path.parent / "outside.json"))

    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    try:
        (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
        with pytest.raises(ValueError, match="escapes"):
            await store.write(_uri(tmp_path / "linked" / "input.json"), b"payload")
    finally:
        (tmp_path / "linked").unlink()
        outside.rmdir()


def test_resolver_selects_file_store_and_rejects_other_schemes(tmp_path: Path) -> None:
    """Verify resolver selects file store and rejects other schemes."""
    store = FileSystemObjectStore(tmp_path)
    assert object_store_for_uri(_uri(tmp_path / "input"), store) is store
    with pytest.raises(ValueError, match="unsupported"):
        object_store_for_uri("s3://bucket/key", store)
