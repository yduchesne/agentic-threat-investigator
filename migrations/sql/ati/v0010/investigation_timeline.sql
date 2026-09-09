-- Immutable SQL v0010 for the analyst-facing investigation timeline.
--
-- The timeline is a distinct, append-only record of safe observable workflow
-- actions. It is separate from audit events, domain-object history, and
-- distributed tracing, and it never carries prose reasoning, raw provider
-- payloads, secrets, or chain-of-thought.
--
-- Append-only enforcement boundary: normal application code is append-only
-- through an ABC/repository that exposes append and chronological read only;
-- no ATI routine (function/procedure) updates, deletes, or upserts timeline
-- events, and no row-level trigger or history mechanism exists. Direct
-- owner/admin SQL is outside the application immutability boundary, and
-- deployment-role privilege separation is future hardening if required.

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
  ),
  -- Stable bounded error-code grammar mirroring the domain contract:
  -- lowercase snake-case, at most 64 characters, no surrounding whitespace.
  -- The database rejects an invalid code even if model validation is
  -- bypassed.
  CONSTRAINT investigation_timeline_event_error_code_check CHECK (
    error_code IS NULL OR error_code ~ '^[a-z][a-z0-9_]{0,63}$'
  )
);

-- The sequence is owned by its table column so dropping the table drops the
-- sequence deterministically during a downgrade.
ALTER SEQUENCE ati.investigation_timeline_event_seq
  OWNED BY ati.investigation_timeline_event.sequence;

CREATE INDEX investigation_timeline_event_chronological_idx
  ON ati.investigation_timeline_event(investigation_id, occurred_at, sequence);
