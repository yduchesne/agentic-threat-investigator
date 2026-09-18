-- ---------------------------------------------------------------------------
-- PR 28B SQL API v0026 (provenance repoint, applied after the Python
-- backfill): repoint legacy provenance FKs onto ati.evidence_observation.
--
-- These ALTERs are split out of global_evidence_persistence.sql so the
-- migration backfill (migration 0031, Python) can populate
-- ati.evidence_observation BEFORE PostgreSQL validates the new FK
-- constraints. Running the constraint ADD before the backfill would fail
-- closed on every legacy database that holds pre-28B GEOINT/observation
-- rows; the previous PR 28B session only exercised the empty-database
-- path. source: migration 0031 upgrade: global DDL -> backfill -> this file
-- -> repointed_write_functions.sql.
-- ---------------------------------------------------------------------------
-- Part 4: repoint RelationshipObservation provenance
-- ---------------------------------------------------------------------------
-- The immutable observation row references the exact EvidenceObservation;
-- the v0.1 Investigation correlation column is removed (scope now comes
-- exclusively from ati.investigation_evidence admission).

ALTER TABLE ati.relationship_observation
  DROP CONSTRAINT IF EXISTS relationship_observation_evidence_fk;
ALTER TABLE ati.relationship_observation
  RENAME COLUMN evidence_id TO evidence_observation_id;

ALTER TABLE ati.relationship_observation
  DROP COLUMN investigation_id;

ALTER TABLE ati.relationship_observation
  ADD CONSTRAINT relationship_observation_evidence_observation_fk
  FOREIGN KEY (evidence_observation_id)
  REFERENCES ati.evidence_observation(id);

-- Admission traversal from RelationshipObservation to Investigation.
CREATE INDEX relationship_observation_evidence_observation_idx
  ON ati.relationship_observation(evidence_observation_id, relationship_id);

-- ---------------------------------------------------------------------------
-- Part 5: repoint GEOINT and assessment/report provenance FKs
-- ---------------------------------------------------------------------------
-- EntityLocationObservation and GeoResolution provenance become exact
-- EvidenceObservation identities; the assessment_finding_support FK follows.

ALTER TABLE ati.entity_location_observation
  DROP CONSTRAINT IF EXISTS entity_location_observation_evidence_id_fkey;
ALTER TABLE ati.entity_location_observation
  DROP CONSTRAINT IF EXISTS entity_location_observation_evidence_fkey;
ALTER TABLE ati.entity_location_observation
  RENAME COLUMN evidence_id TO evidence_observation_id;
ALTER TABLE ati.entity_location_observation
  ADD CONSTRAINT entity_location_observation_evidence_observation_fk
  FOREIGN KEY (evidence_observation_id)
  REFERENCES ati.evidence_observation(id);

ALTER TABLE ati.geo_resolution
  DROP CONSTRAINT IF EXISTS geo_resolution_evidence_id_fkey;
ALTER TABLE ati.geo_resolution
  DROP CONSTRAINT IF EXISTS geo_resolution_evidence_fkey;
ALTER TABLE ati.geo_resolution
  RENAME COLUMN evidence_id TO evidence_observation_id;
ALTER TABLE ati.geo_resolution
  ADD CONSTRAINT geo_resolution_evidence_observation_fk
  FOREIGN KEY (evidence_observation_id)
  REFERENCES ati.evidence_observation(id);

ALTER TABLE ati.assessment_finding_support
  DROP CONSTRAINT IF EXISTS assessment_finding_support_evidence_fk;
ALTER TABLE ati.assessment_finding_support
  ADD CONSTRAINT assessment_finding_support_evidence_fk
  FOREIGN KEY (evidence_id)
  REFERENCES ati.evidence_observation(id);

-- ---------------------------------------------------------------------------
