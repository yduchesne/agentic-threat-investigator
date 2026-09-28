-- SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
-- SPDX-License-Identifier: AGPL-3.0-only
-- PR 31F-2: bounded nullable analyst-facing failure diagnostic on the
-- append-only investigation timeline.
--
-- Add a single nullable text column carrying the sanitized human diagnostic
-- for failure-bearing events only (PROVIDER_WORK_FAILED, mixed partial
-- PROVIDER_WORK_COMPLETED, INVESTIGATION_STOPPED with reason fatal_error).
-- The value is bounded at the database level consistently with the domain
-- maximum (4096 chars) so no over-limit payload can be persisted even if a
-- caller bypasses the application sanitizer. Existing rows remain valid
-- with NULL; no backfill is performed and append-only semantics are
-- unchanged. No index is required: reads never filter on the diagnostic.
--
-- The downgrade removes only the new column and its constraint.
ALTER TABLE ati.investigation_timeline_event
  ADD COLUMN error_message text;

ALTER TABLE ati.investigation_timeline_event
  ADD CONSTRAINT investigation_timeline_event_error_message_check CHECK (
    error_message IS NULL OR char_length(error_message) <= 4096
  );
