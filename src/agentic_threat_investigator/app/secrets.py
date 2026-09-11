# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Secret-resolution abstraction for bootstrap/composition credential wiring.

Implements the documented ``SecretsResolver`` contract from
``CONFIGURATION.md``: secrets are resolved by logical reference name during
application bootstrap/composition, and constructed providers receive only
the resolved credentials they require. Resolved values must never be logged,
persisted, or embedded in configuration or artifact URIs.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from collections.abc import Mapping


class SecretNotFoundError(RuntimeError):
    """A required secret reference could not be resolved.

    Raised during bootstrap/composition so a missing credential fails
    clearly at startup instead of producing authenticated-as-nothing
    provider behavior at request time.
    """

    def __init__(self, name: str) -> None:
        """Initialize with the unresolved secret reference name."""
        self.name = name
        super().__init__(f"required secret not found: {name}")


class SecretsResolver(ABC):
    """Abstract resolver for secrets by logical reference name.

    Configuration stores secret reference names, never resolved values.
    Bootstrap/composition uses a resolver to obtain the credential values
    and passes them to providers and infrastructure components, which remain
    independent of secret-storage infrastructure.
    """

    @abstractmethod
    def get(self, name: str) -> str | None:
        """Return the secret value for a reference name, or ``None``."""

    def require(self, name: str) -> str:
        """Return the secret value for a reference name or raise.

        A missing reference and a present-but-blank value (empty or
        whitespace-only) both raise ``SecretNotFoundError`` naming only the
        configured reference name, so blank credentials can never reach a
        provider as if they were resolved. The returned value is passed
        through unchanged; normalization is the consumer's contract.
        """
        value = self.get(name)
        if value is None or not value.strip():
            raise SecretNotFoundError(name)
        return value


class EnvVarSecretsResolver(SecretsResolver):
    """The required v0.1 resolver obtaining secret values from the environment.

    The environment mapping is injectable so unit tests remain deterministic
    without mutating process-global environment state.
    """

    # The ``os.environ`` default is intentional, not an accidental mutable
    # default: the process environment is the documented v0.1 secret store and
    # must be observed live; tests inject an explicit mapping instead.
    def __init__(
        self,
        env: Mapping[str, str] = os.environ,
    ) -> None:
        """Initialize with the environment mapping to resolve references from."""
        self._env = env

    def get(self, name: str) -> str | None:
        """Return the environment value for a reference name, or ``None``."""
        return self._env.get(name)
