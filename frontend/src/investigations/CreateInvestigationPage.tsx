// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// Create Investigation page (PR 24B §11-§13).
//
// Typed indicator rows plus an objective. Local validation enforces
// requiredness and the exact backend bounds already exposed in OpenAPI
// (objective <= 4000, indicator value <= 2048, at least one indicator,
// non-blank values); no client-side canonicalizer is invented and other
// bounds surface as public backend validation errors. Each logical
// submission uses a cryptographically strong in-memory Idempotency-Key;
// transport-uncertain retries reuse the same key, a 202 navigates
// immediately to the workspace.

import {
  Alert,
  Box,
  Button,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import type { ReactElement } from "react";
import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";

import type {
  CreateInvestigationInput,
  EntityTypeName,
} from "../api/schema-types";
import { ErrorNotice } from "../components/ErrorNotice";
import {
  payloadFingerprint,
  IdempotencyAttemptStore,
} from "./idempotency";
import {
  isIdempotencyConflict,
  isValidationError,
  useCreateInvestigation,
} from "./investigation-queries";

/** Exact supported EntityType values with presentation labels. */
export const ENTITY_TYPE_OPTIONS: readonly EntityTypeName[] = [
  "domain",
  "ip_address",
  "url",
  "network_prefix",
  "asn",
  "organization",
  "malware",
  "attack_technique",
  "vulnerability",
];

/** Exact backend bounds exposed in the committed OpenAPI snapshot. */
export const OBJECTIVE_MAX_LENGTH = 4000;
export const INDICATOR_VALUE_MAX_LENGTH = 2048;

interface IndicatorRow {
  key: number;
  type: EntityTypeName;
  value: string;
}

interface FormErrors {
  objective?: string;
  indicators?: string;
  submit?: string;
}

let nextRowKey = 0;

/** The bounded create form. */
export function CreateInvestigationPage(): ReactElement {
  const { t } = useTranslation("investigations");
  const navigate = useNavigate();
  const attemptStore = useRef(new IdempotencyAttemptStore());
  const [objective, setObjective] = useState("");
  const [rows, setRows] = useState<IndicatorRow[]>([
    { key: nextRowKey++, type: "domain", value: "" },
  ]);
  const [errors, setErrors] = useState<FormErrors>({});

  const handleMutationError = useCallback((mutError: unknown) => {
    if (
      typeof mutError === "object" &&
      mutError !== null &&
      (mutError as { kind?: unknown }).kind === "transport"
    ) {
      attemptStore.current.markUncertain();
    } else {
      attemptStore.current.settle();
    }
  }, []);

  const { run, isPending, error: submissionError } =
    useCreateInvestigation(handleMutationError);

  const updateRow = (key: number, patch: Partial<IndicatorRow>) => {
    setRows((current) =>
      current.map((row) => (row.key === key ? { ...row, ...patch } : row)),
    );
  };

  const removeRow = (key: number) => {
    setRows((current) =>
      current.length === 1 ? current : current.filter((row) => row.key !== key),
    );
  };

  const addRow = () => {
    setRows((current) => [
      ...current,
      { key: nextRowKey++, type: "domain", value: "" },
    ]);
  };

  const validate = (): CreateInvestigationInput | null => {
    const next: FormErrors = {};
    if (objective.trim().length === 0) {
      next.objective = t("create.objective.required");
    }
    const filled = rows.filter((row) => row.value.trim().length > 0);
    if (filled.length === 0) {
      next.indicators = t("create.indicatorsRequired");
    }
    setErrors(next);
    if (Object.keys(next).length > 0) {
      return null;
    }
    return {
      objective: objective.trim(),
      indicators: filled.map((row) => ({
        type: row.type,
        value: row.value.trim(),
      })),
    };
  };

  const submit = () => {
    const payload = validate();
    if (payload === null) {
      return;
    }
    const attempt = attemptStore.current.begin(payloadFingerprint(payload));
    run({ input: payload, idempotencyKey: attempt.key });
  };

  const uncertain = submissionError?.kind === "transport";
  const conflict = submissionError !== null && isIdempotencyConflict(submissionError);
  const validationFailure =
    submissionError !== null && isValidationError(submissionError);

  return (
    <Box sx={{ mx: "auto", maxWidth: 720, py: 2 }}>
      <Typography variant="h1" sx={{ mb: 2 }}>
        {t("create.title")}
      </Typography>

      <Stack component="form" spacing={2} noValidate onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}>
        <TextField
          label={t("create.objective.label")}
          value={objective}
          onChange={(event) => setObjective(event.target.value)}
          multiline
          minRows={2}
          required
          fullWidth
          inputProps={{ maxLength: OBJECTIVE_MAX_LENGTH }}
          error={errors.objective !== undefined}
          helperText={errors.objective}
          id="objective"
        />

        <Box>
          <Typography variant="h2" sx={{ mb: 1 }}>
            {t("create.indicators.heading")}
          </Typography>
          {errors.indicators !== undefined ? (
            <Alert severity="error" role="alert" sx={{ mb: 1 }}>
              {errors.indicators}
            </Alert>
          ) : null}
          <Stack spacing={1}>
            {rows.map((row, index) => (
              <Stack key={row.key} direction="row" spacing={1} alignItems="center">
                <FormControl size="small" sx={{ minWidth: 180 }}>
                  <InputLabel id={`indicator-type-${row.key}`}>
                    {t("create.indicatorType.label")}
                  </InputLabel>
                  <Select
                    labelId={`indicator-type-${row.key}`}
                    label={t("create.indicatorType.label")}
                    value={row.type}
                    onChange={(event) =>
                      updateRow(row.key, { type: event.target.value as EntityTypeName })
                    }
                  >
                    {ENTITY_TYPE_OPTIONS.map((type) => (
                      <MenuItem key={type} value={type}>
                        {t(`indicatorTypes.${type}`)}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <TextField
                  size="small"
                  placeholder={t("create.indicatorValue.label")}
                  value={row.value}
                  onChange={(event) =>
                    updateRow(row.key, { value: event.target.value })
                  }
                  fullWidth
                  inputProps={{
                    maxLength: INDICATOR_VALUE_MAX_LENGTH,
                    "aria-label": `${t("create.indicatorValue.label")} ${index + 1}`,
                  }}
                />
                <IconButton
                  size="small"
                  aria-label={t("create.removeIndicator", { index: index + 1 })}
                  onClick={() => removeRow(row.key)}
                  disabled={rows.length === 1}
                >
                  <span aria-hidden="true">✕</span>
                </IconButton>
              </Stack>
            ))}
          </Stack>
          <Button size="small" onClick={addRow} sx={{ mt: 1, textTransform: "none" }}>
            {t("create.addIndicator")}
          </Button>
        </Box>

        {uncertain ? (
          <Alert severity="warning" role="alert">
            {t("create.submitUncertain")}
          </Alert>
        ) : null}
        {conflict ? (
          <Alert severity="warning" role="alert">
            {t("create.conflict")}
          </Alert>
        ) : null}
        {submissionError !== null &&
        submissionError.kind === "csrf" ? (
          <Alert severity="warning" role="alert">
            {t("create.csrf")}
          </Alert>
        ) : null}
        {submissionError !== null &&
        !uncertain &&
        !conflict &&
        submissionError.kind !== "csrf" ? (
          <ErrorNotice
            title={t("create.submitError")}
            message={
              validationFailure ? submissionError.message : null
            }
          />
        ) : null}

        <Stack direction="row" spacing={1}>
          <Button
            type="submit"
            variant="contained"
            disabled={isPending}
            sx={{ textTransform: "none" }}
          >
            {isPending ? t("create.submitting") : t("create.submit")}
          </Button>
          <Button
            variant="outlined"
            disabled={isPending}
            onClick={() => navigate("/investigations")}
            sx={{ textTransform: "none" }}
          >
            {t("create.cancel")}
          </Button>
        </Stack>
      </Stack>
    </Box>
  );
}