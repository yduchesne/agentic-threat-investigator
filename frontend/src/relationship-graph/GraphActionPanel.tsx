// SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
// SPDX-License-Identifier: AGPL-3.0-only
// PR 31K: the bounded in-flow panel that routes ONE canonical graph Entity
// into ATI's existing durable Investigation command.
//
// The panel is non-modal (no Portal/Dialog/fixed backdrop/focus trap) and
// owns only browser-local workbench state: the editable objective draft and
// the idempotency attempt for this graph-originated submission. It never
// calls providers, the ResearchAgent, or a graph-specific executor; the
// exact reused application command is ``POST /api/v1/investigations`` via
// the existing ``useCreateInvestigation`` mutation, which preserves
// ``apiRequest``/CSRF/Idempotency-Key, typed errors, cancellation, and the
// accepted-result navigation to the new Investigation workspace. The
// durable worker and Coordinator decide and execute all investigation work.

import { Alert, Box, Button, Stack, TextField, Typography } from "@mui/material";
import type { ReactElement } from "react";
import { useCallback, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "../api/errors";
import type { CreateInvestigationInput } from "../api/schema-types";
import { ErrorNotice } from "../components/ErrorNotice";
import { OBJECTIVE_MAX_LENGTH } from "../investigations/CreateInvestigationPage";
import {
  IdempotencyAttemptStore,
  isCreateAttemptOutcomeUncertain,
  payloadFingerprint,
} from "../investigations/idempotency";
import {
  isIdempotencyConflict,
  isValidationError,
  useCreateInvestigation,
} from "../investigations/investigation-queries";
import {
  buildGraphActionObjective,
  isValidGraphActionObjective,
  type GraphActionEntity,
} from "./graph-actions";

export interface GraphActionPanelProps {
  /** The canonical graph Entity selected for the action (authoritative). */
  selection: GraphActionEntity;
  /** Entity type -> analyst label (exact text, non-color cue). */
  entityTypeLabel: (type: string) => string;
  /** Clear/cancel the transient action selection (no request). */
  onCancel: () => void;
}

/**
 * The bounded graph action panel.
 *
 * The caller keeps the panel mounted with ``key={selection.entityId}`` so a
 * different canonical Entity remounts the panel: the objective draft is
 * reset to the factual ``Investigate <type> <value>`` wording and the
 * idempotency attempt store starts fresh (a new Entity is a new logical
 * submission surface, never a silent resubmission of the previous one).
 * Submission disables itself while pending and a local busy guard blocks a
 * second semantic request for the same attempt; a transport-uncertain
 * failure retains the attempt key exactly like the normal create flow.
 */
export function GraphActionPanel({
  selection,
  entityTypeLabel,
  onCancel,
}: GraphActionPanelProps): ReactElement {
  const { t } = useTranslation("relationshipEvolution");
  const attemptStore = useRef(new IdempotencyAttemptStore());
  const [objective, setObjective] = useState<string>(() =>
    buildGraphActionObjective(
      entityTypeLabel(selection.entityType),
      selection.entityValue,
    ),
  );
  const [objectiveInvalid, setObjectiveInvalid] = useState(false);
  /** Blocks a second semantic submission for the same displayed attempt. */
  const busyRef = useRef(false);

  /**
   * Classify the mutation failure with the exact create-attempt uncertainty
   * policy (PR 24F): transport faults and HTTP >= 500 are commit-uncertain
   * (mark the attempt so an unchanged retry reuses the same key); CSRF
   * before transport and definitive 4xx responses settle the attempt. The
   * callback is invoked synchronously whenever the mutation settles with an
   * error, so it also releases the local busy guard for the next attempt.
   */
  const handleMutationError = useCallback((mutError: unknown) => {
    busyRef.current = false;
    if (
      mutError instanceof ApiError &&
      isCreateAttemptOutcomeUncertain(mutError)
    ) {
      attemptStore.current.markUncertain();
    } else {
      attemptStore.current.settle();
    }
  }, []);

  const { run, isPending, error: submissionError } =
    useCreateInvestigation(handleMutationError);

  const submit = (): void => {
    if (busyRef.current || isPending) {
      return;
    }
    const trimmedObjective = objective.trim();
    if (!isValidGraphActionObjective(trimmedObjective)) {
      setObjectiveInvalid(true);
      return;
    }
    setObjectiveInvalid(false);
    const input: CreateInvestigationInput = {
      objective: trimmedObjective,
      indicators: [
        { type: selection.entityType, value: selection.entityValue },
      ],
    };
    const attempt = attemptStore.current.begin(payloadFingerprint(input));
    busyRef.current = true;
    run({ input, idempotencyKey: attempt.key });
  };

  const uncertain =
    submissionError !== null && isCreateAttemptOutcomeUncertain(submissionError);
  const conflict =
    submissionError !== null && isIdempotencyConflict(submissionError);
  const validationFailure =
    submissionError !== null && isValidationError(submissionError);

  return (
    <Box
      component="section"
      aria-label={t("graph.action.title")}
      sx={{
        mt: 1.5,
        p: 1,
        border: 1,
        borderColor: "divider",
        borderRadius: 1,
      }}
    >
      <Typography variant="subtitle2" component="h4">
        {t("graph.action.title")}
      </Typography>
      <Typography variant="body2" sx={{ mt: 0.5 }}>
        {t("graph.action.intro", {
          type: entityTypeLabel(selection.entityType),
          value: selection.entityValue,
        })}
      </Typography>
      <Typography variant="body2" component="div" sx={{ mt: 0.5 }}>
        {t("graph.action.entityId", { value: selection.entityId })}
      </Typography>
      <TextField
        id="graph-action-objective"
        label={t("graph.action.objective.label")}
        value={objective}
        onChange={(event) => setObjective(event.target.value)}
        multiline
        minRows={2}
        required
        fullWidth
        inputProps={{ maxLength: OBJECTIVE_MAX_LENGTH }}
        error={objectiveInvalid}
        helperText={
          objectiveInvalid ? t("graph.action.objective.required") : undefined
        }
        sx={{ mt: 1 }}
      />
      {uncertain ? (
        <Alert severity="warning" role="alert" sx={{ mt: 1 }}>
          {t("graph.action.submitUncertain")}
        </Alert>
      ) : null}
      {conflict ? (
        <Alert severity="warning" role="alert" sx={{ mt: 1 }}>
          {t("graph.action.conflict")}
        </Alert>
      ) : null}
      {submissionError !== null && submissionError.kind === "csrf" ? (
        <Alert severity="warning" role="alert" sx={{ mt: 1 }}>
          {t("graph.action.csrf")}
        </Alert>
      ) : null}
      {submissionError !== null &&
      !uncertain &&
      !conflict &&
      submissionError.kind !== "csrf" ? (
        <Box sx={{ mt: 1 }}>
          <ErrorNotice
            title={t("graph.action.submitError")}
            message={validationFailure ? submissionError.message : null}
          />
        </Box>
      ) : null}
      <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
        <Button
          variant="contained"
          disabled={isPending}
          onClick={submit}
          sx={{ textTransform: "none" }}
        >
          {isPending
            ? t("graph.action.submitting")
            : t("graph.action.submit")}
        </Button>
        <Button
          variant="outlined"
          disabled={isPending}
          onClick={onCancel}
          sx={{ textTransform: "none" }}
        >
          {t("graph.action.cancel")}
        </Button>
      </Stack>
    </Box>
  );
}
