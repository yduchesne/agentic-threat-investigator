# SPDX-License-Identifier: AGPL-3.0-only
"""Public authentication DTOs.

Login requests are strict and bounded; authenticated-user responses expose
only stable public identity fields and never credentials, password hashes,
or session material.
"""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from agentic_threat_investigator.domain.identity import UserRole

MAX_USERNAME_LENGTH = 128
MAX_PASSWORD_LENGTH = 1024


class LoginRequest(BaseModel):
    """Public login request DTO."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    username: str = Field(min_length=1, max_length=MAX_USERNAME_LENGTH)
    password: SecretStr = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class AuthenticatedUserResponse(BaseModel):
    """Public authenticated-user DTO.

    ``alias`` is the normalized public username; no credential, password
    hash, or session information is ever exposed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    alias: str
    role: UserRole
