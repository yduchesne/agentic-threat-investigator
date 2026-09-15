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
  EvidenceResponse,
  EvidenceType,
  FindingResponse,
  FindingSupportResponse,
  GeoPrecision,
  HistoryOperation,
  HistoryRecordResponse,
  IndicatorRequest,
  InvestigationGeolocationCollectionResponse,
  InvestigationGeolocationResponse,
  InvestigationResponse,
  InvestigationStatus,
  InvestigationTimelineEventType,
  LoginRequest,
  NarrativeStatementResponse,
  PageResponseEvidenceResponse,
  PageResponseHistoryRecordResponse,
  PageResponseInvestigationResponse,
  PageResponseRelationshipObservationResponse,
  PageResponseRelationshipResponse,
  PageResponseResearchResultResponse,
  PageResponseTimelineEventResponse,
  RelationshipObservationResponse,
  RelationshipResponse,
  RelationshipDirection,
  RelationshipType,
  ReportFindingResponse,
  ReportResearchClaimResponse,
  ReportResponse,
  ResearchCitationResponse,
  ResearchClaimResponse,
  ResearchResultResponse,
  RuntimeInfoResponse,
  TimelineEventResponse,
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

/** One immutable Evidence observation (PR 24C). */
export type Evidence = EvidenceResponse;

/** One bounded cursor page of Evidence observations (PR 24C). */
export type EvidencePage = PageResponseEvidenceResponse;

/** The exact v0.1 Evidence type URNs (PR 24C). */
export type EvidenceTypeName = EvidenceType;

/** One stable relationship edge (PR 24C). */
export type Relationship = RelationshipResponse;

/** One bounded cursor page of Relationships (PR 24C). */
export type RelationshipPage = PageResponseRelationshipResponse;

/** The exact v0.1 Relationship type URNs (PR 24C). */
export type RelationshipTypeName = RelationshipType;

/** The focal-entity direction accepted by entity-centric observation queries
 * (PR 24E): ``source``/``target``/``either`` relative to ``entity_id``. */
export type RelationshipDirectionName = RelationshipDirection;

/** One immutable historical relationship observation (PR 24C). */
export type RelationshipObservation = RelationshipObservationResponse;

/** One bounded cursor page of RelationshipObservations (PR 24C). */
export type RelationshipObservationPage = PageResponseRelationshipObservationResponse;

/** One contextual ResearchResult artifact (PR 24C). */
export type ResearchResult = ResearchResultResponse;

/** One bounded cursor page of ResearchResults (PR 24C). */
export type ResearchResultPage = PageResponseResearchResultResponse;

/** One persisted Research claim (PR 24C). */
export type ResearchClaim = ResearchClaimResponse;

/** One immutable retrieved-chunk citation snapshot (PR 24C). */
export type ResearchCitation = ResearchCitationResponse;

/** One safe observable workflow timeline event (PR 24C). */
export type TimelineEvent = TimelineEventResponse;

/** One bounded cursor page of Timeline events (PR 24C). */
export type TimelineEventPage = PageResponseTimelineEventResponse;

/** The exact v0.1 timeline event types (PR 24C). */
export type TimelineEventTypeName = InvestigationTimelineEventType;

/** One allowlisted public history row (PR 24C). */
export type HistoryRecord = HistoryRecordResponse;

/** One current approximate geolocation context item for one IP entity (PR 25A). */
export type InvestigationGeolocation = InvestigationGeolocationResponse;

/** One bounded Investigation geolocation projection (PR 25A). */
export type InvestigationGeolocationCollection = InvestigationGeolocationCollectionResponse;

/** The exact v0.1 geolocation precision vocabulary (PR 25A). */
export type GeoPrecisionName = GeoPrecision;

/** One bounded cursor page of history rows (PR 24C). */
export type HistoryPage = PageResponseHistoryRecordResponse;

/** The exact immutable history operations (PR 24C). */
export type HistoryOperationName = HistoryOperation;

/** One application-copied Report finding snapshot (PR 24B). */
export type ReportFinding = ReportFindingResponse;

/** One model-authored narrative statement with explicit typed support. */
export type NarrativeStatement = NarrativeStatementResponse;

/** One persisted ResearchClaim snapshot in report research context. */
export type ReportResearchClaim = ReportResearchClaimResponse;