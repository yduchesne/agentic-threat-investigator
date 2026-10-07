-- SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
-- SPDX-License-Identifier: AGPL-3.0-only
-- PR 38-9: durable append-only LLM usage accounting (SQL API v0035).
--
-- One row per actual model attempt that reported authoritative usage.
-- ``invocation_id`` is the deterministic idempotency identity: an exact replay
-- returns the existing row unchanged, while a replay carrying different
-- accounting fails closed with a typed SQLSTATE. The table is append-only by
-- construction: there is deliberately no update/delete stored function and no
-- prompt, output, Evidence, credential, or raw provider payload column.
--
-- Nullable token/cost columns mean unknown, never zero. Itemized costs are
-- retained; a total cost always carries its immutable pricing identity and
-- version so historical cost never changes when the catalog changes.
--
-- Typed SQLSTATE:
--   U38A1 invalid LLM usage accounting input
--   U38A2 conflicting replay for one invocation identity

CREATE TABLE ati.llm_usage (
  llm_usage_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  investigation_id uuid REFERENCES ati.investigation(id),
  scope_urn text NOT NULL,
  operation_name text NOT NULL,
  invocation_id uuid NOT NULL,
  provider text NOT NULL,
  model text NOT NULL,
  input_tokens bigint,
  output_tokens bigint,
  cached_tokens bigint,
  reasoning_tokens bigint,
  total_tokens bigint,
  input_cost numeric,
  output_cost numeric,
  cached_cost numeric,
  reasoning_cost numeric,
  total_cost numeric,
  currency text,
  pricing_id text,
  pricing_version text,
  occurred_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  CONSTRAINT llm_usage_invocation_unique UNIQUE (invocation_id),
  CONSTRAINT llm_usage_scope_check CHECK (
    scope_urn = btrim(scope_urn)
    AND scope_urn ~ '^urn:ati:llm:usage:[a-z0-9:_-]+$'
    AND length(scope_urn) <= 200
  ),
  CONSTRAINT llm_usage_operation_check CHECK (
    operation_name = btrim(operation_name)
    AND operation_name <> ''
    AND length(operation_name) <= 200
  ),
  CONSTRAINT llm_usage_provider_check CHECK (
    provider = btrim(provider) AND provider <> '' AND length(provider) <= 100
  ),
  CONSTRAINT llm_usage_model_check CHECK (
    model = btrim(model) AND model <> '' AND length(model) <= 100
  ),
  CONSTRAINT llm_usage_tokens_nonnegative_check CHECK (
    (input_tokens IS NULL OR input_tokens >= 0)
    AND (output_tokens IS NULL OR output_tokens >= 0)
    AND (cached_tokens IS NULL OR cached_tokens >= 0)
    AND (reasoning_tokens IS NULL OR reasoning_tokens >= 0)
    AND (total_tokens IS NULL OR total_tokens >= 0)
  ),
  CONSTRAINT llm_usage_costs_nonnegative_check CHECK (
    (input_cost IS NULL OR input_cost >= 0)
    AND (output_cost IS NULL OR output_cost >= 0)
    AND (cached_cost IS NULL OR cached_cost >= 0)
    AND (reasoning_cost IS NULL OR reasoning_cost >= 0)
    AND (total_cost IS NULL OR total_cost >= 0)
  ),
  CONSTRAINT llm_usage_currency_required_check CHECK (
    (input_cost IS NULL AND output_cost IS NULL AND cached_cost IS NULL
      AND reasoning_cost IS NULL AND total_cost IS NULL)
    OR (currency IS NOT NULL AND currency ~ '^[A-Z]{3}$')
  ),
  CONSTRAINT llm_usage_pricing_required_check CHECK (
    total_cost IS NULL
    OR (pricing_id IS NOT NULL AND pricing_id <> ''
        AND pricing_version IS NOT NULL AND pricing_version <> '')
  ),
  CONSTRAINT llm_usage_occurred_at_check CHECK (occurred_at IS NOT NULL)
);

CREATE INDEX llm_usage_investigation_idx
  ON ati.llm_usage (investigation_id, occurred_at DESC);
CREATE INDEX llm_usage_scope_time_idx
  ON ati.llm_usage (scope_urn, occurred_at DESC);

CREATE OR REPLACE FUNCTION ati.append_llm_usage(
  p_investigation_id uuid,
  p_scope_urn text,
  p_operation_name text,
  p_invocation_id uuid,
  p_provider text,
  p_model text,
  p_input_tokens bigint,
  p_output_tokens bigint,
  p_cached_tokens bigint,
  p_reasoning_tokens bigint,
  p_total_tokens bigint,
  p_input_cost numeric,
  p_output_cost numeric,
  p_cached_cost numeric,
  p_reasoning_cost numeric,
  p_total_cost numeric,
  p_currency text,
  p_pricing_id text,
  p_pricing_version text,
  p_occurred_at timestamptz)
RETURNS TABLE(
  llm_usage_id uuid, investigation_id uuid, scope_urn text,
  operation_name text, invocation_id uuid, provider text, model text,
  input_tokens bigint, output_tokens bigint, cached_tokens bigint,
  reasoning_tokens bigint, total_tokens bigint, input_cost numeric,
  output_cost numeric, cached_cost numeric, reasoning_cost numeric,
  total_cost numeric, currency text, pricing_id text, pricing_version text,
  occurred_at timestamptz, created_at timestamptz, created boolean)
LANGUAGE plpgsql AS $$
DECLARE v_row ati.llm_usage%ROWTYPE; v_conflict boolean; v_created boolean;
BEGIN
  IF p_scope_urn IS NULL OR p_scope_urn <> btrim(p_scope_urn)
     OR p_scope_urn !~ '^urn:ati:llm:usage:[a-z0-9:_-]+$'
     OR length(p_scope_urn) > 200 THEN
    RAISE EXCEPTION 'invalid llm usage scope' USING ERRCODE = 'U38A1';
  END IF;
  IF p_operation_name IS NULL OR p_operation_name <> btrim(p_operation_name)
     OR p_operation_name = '' OR length(p_operation_name) > 200
     OR p_provider IS NULL OR p_provider = '' OR length(p_provider) > 100
     OR p_model IS NULL OR p_model = '' OR length(p_model) > 100
     OR p_invocation_id IS NULL OR p_occurred_at IS NULL THEN
    RAISE EXCEPTION 'invalid llm usage identity' USING ERRCODE = 'U38A1';
  END IF;

  IF p_total_cost IS NOT NULL
     AND (p_pricing_id IS NULL OR p_pricing_id = ''
          OR p_pricing_version IS NULL OR p_pricing_version = '') THEN
    RAISE EXCEPTION 'missing pricing identity' USING ERRCODE = 'U38A1';
  END IF;
  IF (p_input_cost IS NOT NULL OR p_output_cost IS NOT NULL
      OR p_cached_cost IS NOT NULL OR p_reasoning_cost IS NOT NULL
      OR p_total_cost IS NOT NULL)
     AND (p_currency IS NULL OR p_currency !~ '^[A-Z]{3}$') THEN
    RAISE EXCEPTION 'currency required for cost' USING ERRCODE = 'U38A1';
  END IF;

  INSERT INTO ati.llm_usage (
    investigation_id, scope_urn, operation_name, invocation_id, provider,
    model, input_tokens, output_tokens, cached_tokens, reasoning_tokens,
    total_tokens, input_cost, output_cost, cached_cost, reasoning_cost,
    total_cost, currency, pricing_id, pricing_version, occurred_at)
  VALUES (
    p_investigation_id, p_scope_urn, p_operation_name, p_invocation_id,
    p_provider, p_model, p_input_tokens, p_output_tokens, p_cached_tokens,
    p_reasoning_tokens, p_total_tokens, p_input_cost, p_output_cost,
    p_cached_cost, p_reasoning_cost, p_total_cost, p_currency, p_pricing_id,
    p_pricing_version, p_occurred_at)
  ON CONFLICT ON CONSTRAINT llm_usage_invocation_unique DO NOTHING
  RETURNING * INTO v_row;

  IF NOT FOUND THEN
    SELECT * INTO v_row FROM ati.llm_usage u
     WHERE u.invocation_id = p_invocation_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'llm usage invocation conflict'
        USING ERRCODE = 'U38A2';
    END IF;
    v_conflict :=
      v_row.scope_urn IS DISTINCT FROM p_scope_urn
      OR v_row.operation_name IS DISTINCT FROM p_operation_name
      OR v_row.provider IS DISTINCT FROM p_provider
      OR v_row.model IS DISTINCT FROM p_model
      OR v_row.investigation_id IS DISTINCT FROM p_investigation_id
      OR v_row.input_tokens IS DISTINCT FROM p_input_tokens
      OR v_row.output_tokens IS DISTINCT FROM p_output_tokens
      OR v_row.cached_tokens IS DISTINCT FROM p_cached_tokens
      OR v_row.reasoning_tokens IS DISTINCT FROM p_reasoning_tokens
      OR v_row.total_tokens IS DISTINCT FROM p_total_tokens
      OR v_row.input_cost IS DISTINCT FROM p_input_cost
      OR v_row.output_cost IS DISTINCT FROM p_output_cost
      OR v_row.cached_cost IS DISTINCT FROM p_cached_cost
      OR v_row.reasoning_cost IS DISTINCT FROM p_reasoning_cost
      OR v_row.total_cost IS DISTINCT FROM p_total_cost
      OR v_row.currency IS DISTINCT FROM p_currency
      OR v_row.pricing_id IS DISTINCT FROM p_pricing_id
      OR v_row.pricing_version IS DISTINCT FROM p_pricing_version
      OR v_row.occurred_at IS DISTINCT FROM p_occurred_at;
    IF v_conflict THEN
      RAISE EXCEPTION 'llm usage invocation conflict'
        USING ERRCODE = 'U38A2';
    END IF;
    -- Exact replay: the invocation is already durably accounted.
    v_created := FALSE;
  ELSE
    -- The INSERT atomically accepted a new invocation event.
    v_created := TRUE;
  END IF;

  llm_usage_id := v_row.llm_usage_id;
  investigation_id := v_row.investigation_id;
  scope_urn := v_row.scope_urn;
  operation_name := v_row.operation_name;
  invocation_id := v_row.invocation_id;
  provider := v_row.provider;
  model := v_row.model;
  input_tokens := v_row.input_tokens;
  output_tokens := v_row.output_tokens;
  cached_tokens := v_row.cached_tokens;
  reasoning_tokens := v_row.reasoning_tokens;
  total_tokens := v_row.total_tokens;
  input_cost := v_row.input_cost;
  output_cost := v_row.output_cost;
  cached_cost := v_row.cached_cost;
  reasoning_cost := v_row.reasoning_cost;
  total_cost := v_row.total_cost;
  currency := v_row.currency;
  pricing_id := v_row.pricing_id;
  pricing_version := v_row.pricing_version;
  occurred_at := v_row.occurred_at;
  created_at := v_row.created_at;
  created := v_created;
  RETURN NEXT;
END $$;
