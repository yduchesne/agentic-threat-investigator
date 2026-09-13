// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Narrow frontend API type aliases (PR 24A / PR 24B).
//
// Components import from this module instead of referencing giant generated
// schema expressions. The generated file remains the single type source of
// truth; nothing here duplicates backend DTO fields.

import type {
  AssessmentConfidence,
  AssessmentResponse,
  AuthenticatedUserResponse,
  CreateInvestigationRequest,
  CreateInvestigationResponse,
  EntityType,
  ErrorResponse,
  FindingResponse,
  FindingSupportResponse,
  IndicatorRequest,
  InvestigationResponse,
  InvestigationStatus,
  LoginRequest,
  NarrativeStatementResponse,
  PageResponseInvestigationResponse,
  ReportFindingResponse,
  ReportResearchClaimResponse,
  ReportResponse,
  RuntimeInfoResponse,
  UserRole,
  Verdict,
} from "./schema.generated";

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

/** One typed raw indicator submitted for Investigation creation (PR 24B). */
export type IndicatorInput = IndicatorRequest;

/** The strict create-Investigation request payload (PR 24B). */
export type CreateInvestigationInput = CreateInvestigationRequest;

/** The authoritative 202 result of an asynchronous creation (PR 24B). */
export type CreateInvestigationResult = CreateInvestigationResponse;

/** The canonical entity types that can participate in relationships. */
export type EntityTypeName = EntityType;

/** The exact Investigation lifecycle statuses (never invented client-side). */
export type InvestigationStatusName = InvestigationStatus;

/** One Investigation's stable public operational state (PR 24B). */
export type Investigation = InvestigationResponse;

/** One bounded cursor page of Investigations (PR 24B). */
export type InvestigationPage = PageResponseInvestigationResponse;

/** One versioned Assessment output (PR 24B). */
export type Assessment = AssessmentResponse;

/** Confidence in the verdict, never severity (PR 24B). */
export type AssessmentConfidenceName = AssessmentConfidence;

/** The verdict taxonomy (PR 24B). */
export type VerdictName = Verdict;

/** One structured Assessment finding with typed support (PR 24B). */
export type Finding = FindingResponse;

/** One typed provenance reference of a Finding (PR 24B). */
export type FindingSupportRef = FindingSupportResponse;

/** One versioned structured InvestigationReport (PR 24B). */
export type Report = ReportResponse;

/** One application-copied Report finding snapshot (PR 24B). */
export type ReportFinding = ReportFindingResponse;

/** One model-authored narrative statement with explicit typed support. */
export type NarrativeStatement = NarrativeStatementResponse;

/** One persisted ResearchClaim snapshot in report research context. */
export type ReportResearchClaim = ReportResearchClaimResponse;