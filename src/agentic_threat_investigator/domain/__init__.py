"""ATI domain layer."""

from .documents import (
    Document,
    DocumentChunk,
    EmbeddingModelInfo,
    document_chunk_citation_id,
    document_chunk_content_hash,
    document_content_hash,
)
from .entities import Entity, EntityType
from .evidence import (
    ConvertedEvidence,
    Evidence,
    EvidenceMaterialState,
    EvidenceObservation,
    EvidenceObservationCandidate,
    EvidenceObservationEntity,
    EvidenceTransition,
    EvidenceType,
    InvestigationEvidence,
    InvestigationEvidenceActor,
    InvestigationEvidenceReason,
    decide_evidence_transition,
    evidence_id_for_source_record,
    material_state_diff,
)
from .legacy_evidence import EntityRef, LegacyEvidence
from .relationships import Relationship, RelationshipObservation, RelationshipType
from .research import (
    ResearchCitation,
    ResearchClaim,
    ResearchQuery,
    ResearchResult,
    RetrievedChunk,
    research_citation_from_retrieved_chunk,
)
from .research_agent import (
    ResearchAgentClaim,
    ResearchAgentDecision,
    ResearchAgentRequest,
)
from .source import SourceRecord, source_record_content_hash

__all__ = [
    "Entity",
    "EntityRef",
    "EntityType",
    "ConvertedEvidence",
    "Evidence",
    "EvidenceMaterialState",
    "EvidenceObservation",
    "EvidenceObservationCandidate",
    "EvidenceObservationEntity",
    "EvidenceTransition",
    "EvidenceType",
    "InvestigationEvidence",
    "InvestigationEvidenceActor",
    "InvestigationEvidenceReason",
    "LegacyEvidence",
    "decide_evidence_transition",
    "evidence_id_for_source_record",
    "material_state_diff",
    "Relationship",
    "RelationshipObservation",
    "RelationshipType",
    "SourceRecord",
    "source_record_content_hash",
    "Document",
    "DocumentChunk",
    "EmbeddingModelInfo",
    "document_content_hash",
    "document_chunk_content_hash",
    "document_chunk_citation_id",
    "ResearchQuery",
    "RetrievedChunk",
    "ResearchCitation",
    "ResearchClaim",
    "ResearchResult",
    "research_citation_from_retrieved_chunk",
    "ResearchAgentRequest",
    "ResearchAgentClaim",
    "ResearchAgentDecision",
]
