# SPDX-License-Identifier: AGPL-3.0-only
"""Safe filesystem implementation of the source artifact cache port."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from agentic_threat_investigator.app.sources import SourceCache


def _safe_relative_key(key: str) -> Path:
    """Validate a cache key as a relative POSIX path."""
    candidate = Path(key)
    if not key or candidate.is_absolute() or "\x00" in key:
        raise ValueError("cache key must be a non-empty relative path")
    if any(part in ("", ".", "..") for part in candidate.parts):
        raise ValueError("cache key contains an unsafe path component")
    return candidate


class FileSourceCache(SourceCache):
    """Store artifacts below an injected directory using atomic replacement."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root).expanduser()

    def _path(self, key: str) -> Path:
        """Resolve a validated key without allowing root escape."""
        relative = _safe_relative_key(key)
        path = (self._root / relative).resolve()
        root = self._root.resolve()
        if path != root and root not in path.parents:
            raise ValueError("cache key escapes cache root")
        return path

    async def read(self, key: str) -> bytes | None:
        """Read a complete artifact without exposing partial temporary files."""
        path = self._path(key)
        try:
            return await asyncio.to_thread(path.read_bytes)
        except FileNotFoundError:
            return None

    async def write(self, key: str, content: bytes) -> Path:
        """Write an artifact through a same-directory fsync and atomic rename."""
        path = self._path(key)
        await asyncio.to_thread(self._write_atomic, path, content)
        return path

    @staticmethod
    def _write_atomic(path: Path, content: bytes) -> None:
        """Synchronously perform the atomic write in a worker thread."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as temp:
            temporary = Path(temp.name)
            temp.write(content)
            temp.flush()
            os.fsync(temp.fileno())
        try:
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            temporary.unlink(missing_ok=True)

    async def remove(self, key: str) -> None:
        """Remove an artifact, ignoring an already absent entry."""
        path = self._path(key)
        await asyncio.to_thread(path.unlink, True)
