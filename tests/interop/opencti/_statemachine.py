# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Pure readiness state machine of the OpenCTI interoperability harness (PR 33E).

The state machine owns the deterministic ordered readiness contract
(PR 33E section 10.7): PostgreSQL-persisted ATI domain state is the
authoritative final readiness condition, never fixed sleeps, never broker lag
alone, and never the mere fact that some earlier HTTP stage responded. The
machine is deliberately pure (no I/O) so deterministic unit tests drive every
transition with fabricated probes (section 10.9.1, O01..O14); the real
harness builds probe snapshots from durable application state (PostgreSQL,
datasource lifecycle, broker receipts, OpenCTI feed convergence).

A probe is always **run-scoped**: expected Evidence/Entity/Relationship
identities, the run's execution/message identifiers, and the scenario's
checkpoint expectation come from the deterministic manifest, so unrelated
traffic can never advance this run (O09) and unsupported fixtures honor
their zero-Evidence expectation without waiting forever (O10).
"""

from __future__ import annotations

import time as _time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from time import monotonic

# The exact terminal stage vocabulary of the plan's failure taxonomy.
FAILURE_STAGE_BOOTSTRAP = "OPENCTI_BOOTSTRAP"
FAILURE_STAGE_SEED = "OPENCTI_SEED"
FAILURE_STAGE_FEED_CONVERGENCE = "OPENCTI_FEED_CONVERGENCE"
FAILURE_STAGE_DISCOVERY_OR_AUTH = "TAXII_DISCOVERY_OR_AUTH"
FAILURE_STAGE_ACQUISITION = "TAXII_ACQUISITION"
FAILURE_STAGE_PARSE_OR_CONVERSION = "STIX_PARSE_OR_CONVERSION"
FAILURE_STAGE_PUBLICATION = "EVIDENCE_PUBLICATION"
FAILURE_STAGE_CHECKPOINT_COMMIT = "CHECKPOINT_COMMIT"
FAILURE_STAGE_BROKER_CONSUMPTION = "BROKER_CONSUMPTION"
FAILURE_STAGE_POSTGRES_PERSISTENCE = "POSTGRES_PERSISTENCE"
FAILURE_STAGE_FINAL_ASSERTION = "FINAL_ASSERTION"
FAILURE_STAGE_READINESS_TIMEOUT = "READINESS_TIMEOUT"

# The exact failure classification vocabulary of section 10.8.
FAILURE_CLASS_REGRESSION = "introduced_regression"
FAILURE_CLASS_FEATURE_DEFECT = "feature_implementation_defect"
FAILURE_CLASS_PRE_EXISTING = "deterministic_pre_existing_failure"
FAILURE_CLASS_FLAKY = "nondeterministic_flaky_failure"
FAILURE_CLASS_ENVIRONMENT = "environment_harness_failure"
FAILURE_CLASS_UNCLASSIFIED = "unclassified"


class InteropStage(StrEnum):
    """Ordered readiness stages of one harness run.

    The strings are stable machine-readable stage identifiers used by the
    diagnostic tooling and the bounded wait loop.
    """

    OPENCTI_BOOTSTRAP = "OPENCTI_BOOTSTRAP"
    OPENCTI_SEED_ACCEPTED = "OPENCTI_SEED_ACCEPTED"
    OPENCTI_FEED_CONVERGED = "OPENCTI_FEED_CONVERGED"
    ATI_ACQUISITION_COMPLETED = "ATI_ACQUISITION_COMPLETED"
    ATI_PUBLICATION_COMPLETED = "ATI_PUBLICATION_COMPLETED"
    ATI_PERSISTENCE_CONVERGED = "ATI_PERSISTENCE_CONVERGED"
    READY_FOR_ASSERTIONS = "READY_FOR_ASSERTIONS"


#: Ordered display chain, seed acceptance first, terminal READY last.
STAGE_ORDER = tuple(stage for stage in InteropStage)


@dataclass(frozen=True)
class ProbeSnapshot:
    """Run-scoped durable observations the state machine needs.

    Every field is derived from durable/correlated state, never from wall
    clock timing or unrelated global traffic:

    - ``seed_accepted``: OpenCTI acknowledged the deterministic fixture seed.
    - ``feed_converged``: the seeded STIX objects are all visible through the
      real OpenCTI TAXII 2.1 collection (or an equivalent documented feed
      state proves convergence).
    - ``execution_completed``: the ATI TAXII datasource execution reached the
      successful lifecycle boundary (COMPLETED).
    - ``published``: the expected Evidence messages of that execution were
      published (receipts/counters correlated to the run).
    - ``expected_state_matches``: PostgreSQL contains the exact expected
      Evidence/Entity/Relationship rows and observation/provenance rows for
      the fixture subset under test (the run manifest is the source of truth).
    - ``checkpoint_matches``: the durable TAXII checkpoint has the expected
      value when the scenario requires advancement.
    - ``terminal_failure``: bounded classification/cause of a terminal failure
      (datasource FAILED/CANCELLED, consumer failure, timeout, or manual).
    - ``terminal_stage``: the failed pipeline stage (section 10.8 taxonomy).
    """

    seed_accepted: bool = False
    feed_converged: bool = False
    execution_completed: bool = False
    published: bool = False
    expected_state_matches: bool = False
    checkpoint_matches: bool = True
    terminal_failure: str | None = None
    terminal_stage: str | None = None


@dataclass(frozen=True)
class StageResult:
    """The deterministic outcome of one probe evaluation."""

    stage: InteropStage
    terminal_failure: str | None = None
    terminal_stage: str | None = None

    @property
    def ready(self) -> bool:
        """True exactly when assertions may run."""
        return self.stage is InteropStage.READY_FOR_ASSERTIONS

    @property
    def failed(self) -> bool:
        """True when the run reached a terminal (non-timeout) failure."""
        return self.terminal_failure is not None

    @property
    def timed_out(self) -> bool:
        """True when the bounded wait expired before readiness."""
        return self.terminal_stage == FAILURE_STAGE_READINESS_TIMEOUT


def evaluate(probe: ProbeSnapshot) -> StageResult:
    """Return the current stage from one run-scoped probe snapshot.

    A terminal failure always wins over progress (never read assertions when
    the datasource FAILED or the consumer failed). Otherwise the machine
    returns the earliest not-yet-satisfied gate; ``expected_state_matches``
    and ``checkpoint_matches`` must BOTH hold before READY_FOR_ASSERTIONS
    (O04/O05/O11: broker drain alone or missing checkpoint can never be
    READY).
    """
    if probe.terminal_failure is not None:
        return StageResult(
            stage=InteropStage.OPENCTI_BOOTSTRAP,
            terminal_failure=probe.terminal_failure,
            terminal_stage=probe.terminal_stage or FAILURE_STAGE_BOOTSTRAP,
        )
    if not probe.seed_accepted:
        return StageResult(stage=InteropStage.OPENCTI_SEED_ACCEPTED)
    if not probe.feed_converged:
        return StageResult(stage=InteropStage.OPENCTI_FEED_CONVERGED)
    if not probe.execution_completed:
        return StageResult(stage=InteropStage.ATI_ACQUISITION_COMPLETED)
    if not probe.published:
        return StageResult(stage=InteropStage.ATI_PUBLICATION_COMPLETED)
    if not (probe.expected_state_matches and probe.checkpoint_matches):
        return StageResult(stage=InteropStage.ATI_PERSISTENCE_CONVERGED)
    return StageResult(stage=InteropStage.READY_FOR_ASSERTIONS)


def wait_for_ready(
    probe_callable: Callable[[], ProbeSnapshot],
    *,
    timeout_seconds: float,
    interval_seconds: float = 2.0,
    clock: Callable[[], float] | None = None,
) -> StageResult:
    """Poll one probe callable until READY, a terminal failure, or the timeout.

    Always returns a :class:`StageResult`; the caller maps terminal-failure
    and timeout results to a non-zero exit and diagnostics, and only a
    ``ready`` result may start the assertion suite. The probe callable is
    invoked at a bounded interval; cancellation (KeyboardInterrupt) is
    propagated unchanged so operators can interrupt a wait.
    """
    started = monotonic() if clock is None else clock()
    result = evaluate(probe_callable())
    while not result.ready and not result.failed:
        elapsed = (monotonic() - started) if clock is None else (clock() - started)
        if elapsed >= timeout_seconds:
            return StageResult(
                stage=result.stage,
                terminal_failure="readiness timeout expired before READY_FOR_ASSERTIONS",
                terminal_stage=FAILURE_STAGE_READINESS_TIMEOUT,
            )
        _time.sleep(interval_seconds)
        result = evaluate(probe_callable())
    return result
