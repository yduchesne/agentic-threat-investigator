// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Narrow frontend API type aliases (PR 24A).
//
// Components import from this module instead of referencing giant generated
// schema expressions. The generated file remains the single type source of
// truth; nothing here duplicates backend DTO fields.

import type { AuthenticatedUserResponse, ErrorResponse, LoginRequest, RuntimeInfoResponse, UserRole } from "./schema.generated";

/** The public authenticated-user DTO delivered by `/auth/me` and login. */
export type PublicUser = AuthenticatedUserResponse;

/** The login request DTO. */
export type LoginCredentials = LoginRequest;

/** The authenticated `/runtime` metadata DTO. */
export type RuntimeInfo = RuntimeInfoResponse;

/** Roles supported by local authentication. */
export type UserRoleName = UserRole;

/** The stable public API error envelope. */
export type { ErrorResponse };