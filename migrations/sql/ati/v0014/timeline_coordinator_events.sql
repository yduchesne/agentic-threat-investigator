-- SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
-- SPDX-License-Identifier: AGPL-3.0-only
-- PR 21: extend the immutable investigation timeline with coordinator event
-- types and the bounded pivot-depth/reason/budget fields consumed by
-- coordinator trajectory evaluation.
ALTER TABLE ati.investigation_timeline_event
  ADD COLUMN pivot_depth integer,
  ADD COLUMN reason_code text,
  ADD COLUMN provider_calls_used bigint,
  ADD COLUMN replans_used bigint,
  ADD COLUMN entity_count integer;

ALTER TABLE ati.investigation_timeline_event
  DROP CONSTRAINT investigation_timeline_event_type_check;

ALTER TABLE ati.investigation_timeline_event
  ADD CONSTRAINT investigation_timeline_event_type_check CHECK (
    event_type IN (
      'investigation_started',
      'provider_work_started',
      'provider_work_completed',
      'provider_work_failed',
      'evidence_persisted',
      'entities_discovered',
      'pivot_enqueued',
      'pivot_executed',
      'pivot_skipped',
      'assessment_requested',
      'investigation_stopped'
    )
  );

-- Bounded reason-code grammar mirrors the domain contract.
ALTER TABLE ati.investigation_timeline_event
  ADD CONSTRAINT investigation_timeline_event_reason_code_check CHECK (
    reason_code IS NULL OR reason_code ~ '^[a-z][a-z0-9_]{0,63}$'
  );