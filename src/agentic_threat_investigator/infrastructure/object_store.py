# SPDX-License-Identifier: AGPL-3.0-only
"""Filesystem implementation of the URI-oriented artifact store."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import unquote, urlsplit

from agentic_threat_investigator.app.sources import ObjectStore


class ArtifactNotFoundError(FileNotFoundError):
    """Raised when an explicitly requested artifact does not exist."""


class FileSystemObjectStore(ObjectStore):
    """Store local ``file://`` artifacts below an injected datasets root."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root).expanduser().resolve()

    def _path(self, uri: str) -> Path:
        """Validate a file URI and resolve it without symlink escape."""
        parsed = urlsplit(uri)
        if parsed.scheme != "file" or parsed.netloc:
            raise ValueError("only authority-free file:// artifact URIs are supported")
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("artifact URI contains unsupported or sensitive parts")
        raw_path = unquote(parsed.path)
        if not raw_path or "\x00" in raw_path:
            raise ValueError("artifact URI has an invalid path")
        path = Path(raw_path).resolve()
        if path != self._root and self._root not in path.parents:
            raise ValueError("artifact URI escapes the datasets root")
        return path

    async def read(self, uri: str) -> bytes:
        """Read one complete artifact asynchronously."""
        path = self._path(uri)
        try:
            return await asyncio.to_thread(path.read_bytes)
        except FileNotFoundError as exc:
            raise ArtifactNotFoundError(uri) from exc

    async def write(self, uri: str, content: bytes) -> Path:
        """Atomically write an artifact; intended for acquisition/test setup."""
        path = self._path(uri)
        await asyncio.to_thread(self._write_atomic, path, content)
        return path

    @staticmethod
    def _write_atomic(path: Path, content: bytes) -> None:
        """Perform fsync-backed same-directory replacement."""
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

    async def remove(self, uri: str) -> None:
        """Remove an artifact if present."""
        path = self._path(uri)
        await asyncio.to_thread(path.unlink, True)


# Explicit composition boundary: sources never resolve URI schemes.
def object_store_for_uri(uri: str, file_store: FileSystemObjectStore) -> ObjectStore:
    """Select the configured store for a URI scheme."""
    if urlsplit(uri).scheme != "file":
        raise ValueError("unsupported artifact URI scheme")
    return file_store
