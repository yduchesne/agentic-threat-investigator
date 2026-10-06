// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Narrow frontend API type aliases (PR 24A / PR 24B).
//
// Components import from this module instead of referencing giant generated
// schema expressions. The generated file remains the single type source of
// truth; nothing here duplicates backend DTO fields.

import type {
  AssessmentConfidence,
  AssessmentFindingRefResponse,
  AssessmentResponse,
  AuthenticatedUserResponse,
  CreateInvestigationRequest,
  CreateInvestigationResponse,
  EntityType,
  ErrorResponse,
  EvidenceResponse,
  EvidenceSupportPresentationResponse,
  EvidenceType,
  FindingCriticality,
  FindingResponse,
  FindingSupportResponse,
  GeoPrecision,
  GeointEntityLocationResponse,
  GeointLocationEntitiesResponseGeointEntityLocationResponse,
  GeointLocationObservationsResponseGeointObservationResponse,
  GeointLocationResponse,
  GeointObservationDetailResponse,
  GeointObservationResponse,
  GeointPrecisionCountsResponse,
  GeointSummaryResponse,
  GeointTopLocationResponse,
  GraphEdgeResponse,
  GraphNeighborhoodResponse,
  GraphNodeResponse,
  GraphPathDto,
  GraphPathResponse,
  GraphScope,
  HistoryOperation,
  HistoryRecordResponse,
  IndicatorRequest,
  InvestigationGeolocationCollectionResponse,
  InvestigationGeolocationResponse,
  InvestigationResponse,
  InvestigationStatus,
  InvestigationTimelineEventType,
  LocationPrecision,
  LocationType,
  PageResponseGeointObservationResponse,
  LoginRequest,
  PageResponseEvidenceResponse,
  PageResponseHistoryRecordResponse,
  PageResponseInvestigationResponse,
  PageResponseRelationshipObservationResponse,
  PageResponseRelationshipResponse,
  PageResponseResearchResultResponse,
  PageResponseTimelineEventResponse,
  RelationshipObservationResponse,
  RelationshipObservationSupportPresentationResponse,
  RelationshipResponse,
  RelationshipDirection,
  RelationshipType,
  ReportFindingResponse,
  ReportResearchClaimResponse,
  ReportResponse,
  ReportSummaryItemResponse,
  ResearchCitationResponse,
  ResearchClaimResponse,
  ResearchResultResponse,
  RuntimeInfoResponse,
  SupportPresentationResponse,
  TimelineEventResponse,
  UserRole,
  Verdict,
} from "./schema.generated";

/** One bounded canonical Location display reference (PR 26D). */
export type GeointLocation = GeointLocationResponse;

/** One immutable geographic observation with exact provenance (PR 26D). */
export type GeointObservation = GeointObservationResponse;

/** One Entity's Investigation-relative current geographic context (PR 26D). */
export type GeointEntityLocation = GeointEntityLocationResponse;

/** One exact geographic observation with bounded display context (PR 26D). */
export type GeointObservationDetail = GeointObservationDetailResponse;

/** One bounded Investigation-scoped geographic summary (PR 26D). */
export type GeointSummary = GeointSummaryResponse;

/** One exact observed Location group in the bounded summary (PR 26D). */
export type GeointTopLocation = GeointTopLocationResponse;

/** Precision/type counts of the bounded summary (PR 26D). */
export type GeointPrecisionCounts = GeointPrecisionCountsResponse;

/** One page of Investigation-scoped observations (PR 26D). */
export type GeointObservationPage = PageResponseGeointObservationResponse;

/** One Location-scoped page of Entities with current context (PR 26D). */
export type GeointLocationEntitiesPage =
  GeointLocationEntitiesResponseGeointEntityLocationResponse;

/** One Location-scoped page of observations (PR 26D). */
export type GeointLocationObservationsPage =
  GeointLocationObservationsResponseGeointObservationResponse;

/** The exact v0.1 canonical Location-type vocabulary (PR 26D). */
export type LocationTypeName = LocationType;

/** The exact v0.1 observation precision vocabulary (PR 26D). */
export type LocationPrecisionName = LocationPrecision;

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

/** One finding-like artifact row (Assessment finding or Report snapshot). */
export type FindingLike = Finding | ReportFinding;

/** One typed provenance reference of a Finding (PR 24B). */
export type FindingSupportRef = FindingSupportResponse;

/** One Evidence support presentation projection (PR 31F-5). */
export type EvidenceSupportPresentation = EvidenceSupportPresentationResponse;

/** One RelationshipObservation support presentation projection (PR 31F-5). */
export type RelationshipObservationSupportPresentation =
  RelationshipObservationSupportPresentationResponse;

/** The bounded resolved support presentation map (PR 31F-5). */
export type SupportPresentation = SupportPresentationResponse;

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

/** One canonical Entity projected as a graph node (PR 31C). */
export type GraphNode = GraphNodeResponse;

/** One canonical Relationship projected as a graph edge (PR 31C; PR 31G). */
export type GraphEdge = GraphEdgeResponse;

/** One bounded Investigation-scoped one-hop neighborhood (PR 31C). */
export type GraphNeighborhood = GraphNeighborhoodResponse;

/** One ordered simple path of canonical graph references (PR 31I). */
export type GraphPath = GraphPathDto;

/** One bounded deterministic path-finding projection (PR 31I). */
export type GraphPathResult = GraphPathResponse;

/** The exact two-value graph scope vocabulary (PR 31G). */
export type GraphScopeName = GraphScope;

/** One bounded cursor page of history rows (PR 24C). */
export type HistoryPage = PageResponseHistoryRecordResponse;

/** The exact immutable history operations (PR 24C). */
export type HistoryOperationName = HistoryOperation;

/** One application-copied Report finding snapshot (PR 24B). */
export type ReportFinding = ReportFindingResponse;

/** The bounded authoritative finding criticality vocabulary (PR 35-5). */
export type ReportCriticalityName = FindingCriticality;

/** One finding-centric Report Summary projection item (PR 35-5). */
export type ReportSummaryItem = ReportSummaryItemResponse;

/** One typed reference to a canonical Report Summary finding (PR 35-5). */
export type ReportSummarySupport = AssessmentFindingRefResponse;

/** One persisted ResearchClaim snapshot in report research context. */
export type ReportResearchClaim = ReportResearchClaimResponse;
