-- Immutable SQL v0010 for the analyst-facing investigation timeline.
--
-- The timeline is a distinct, append-only record of safe observable workflow
-- actions. It is separate from audit events, domain-object history, and
-- distributed tracing, and it never carries prose reasoning, raw provider
-- payloads, secrets, or chain-of-thought.
--
-- Append-only semantics: no update or delete function is provided and none
-- may be added. Row-level triggers are never used. The foreign key to
-- ati.investigation rejects events for unknown investigations.

CREATE SEQUENCE ati.investigation_timeline_event_seq AS bigint;

CREATE TABLE ati.investigation_timeline_event (
  id uuid PRIMARY KEY,
  investigation_id uuid NOT NULL REFERENCES ati.investigation(id),
  event_type text NOT NULL,
  occurred_at timestamptz NOT NULL,
  provider text,
  target_entity_id uuid,
  evidence_ids uuid[] NOT NULL DEFAULT '{}',
  entity_ids uuid[] NOT NULL DEFAULT '{}',
  relationship_ids uuid[] NOT NULL DEFAULT '{}',
  error_code text,
  sequence bigint NOT NULL DEFAULT nextval('ati.investigation_timeline_event_seq'),
  CONSTRAINT investigation_timeline_event_type_check CHECK (
    event_type IN (
      'investigation_started',
      'provider_work_started',
      'provider_work_completed',
      'provider_work_failed',
      'evidence_persisted',
      'entities_discovered'
    )
  )
);

CREATE INDEX investigation_timeline_event_chronological_idx
  ON ati.investigation_timeline_event(investigation_id, occurred_at, sequence);
