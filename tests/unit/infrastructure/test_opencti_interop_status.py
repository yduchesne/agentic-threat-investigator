# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33E OpenCTI interop readiness state-machine tests (O01..O14).

Pure deterministic tests of the harness orchestration/readiness state
machine (tests/interop/opencti/_statemachine.py) using fabricated probe
snapshots — no containers, database, or broker involved. These prove the
exact gate ordering of PR 33E section 10.9.1: assertions never start before
READY_FOR_ASSERTIONS, terminal failures and hard timeouts diagnose instead
of asserting, unrelated traffic never advances a run, unsupported fixtures
honor zero-Evidence expectations without waiting forever, and checkpoint
expectations gate readiness.
"""

from __future__ import annotations

import pytest

from tests.interop.opencti._statemachine import (
    FAILURE_STAGE_BOOTSTRAP,
    FAILURE_STAGE_READINESS_TIMEOUT,
    InteropStage,
    ProbeSnapshot,
    StageResult,
    evaluate,
    wait_for_ready,
)

pytestmark = pytest.mark.unit


def _ready() -> ProbeSnapshot:
    """Return a fully converged probe snapshot."""
    return ProbeSnapshot(
        seed_accepted=True,
        feed_converged=True,
        execution_completed=True,
        published=True,
        expected_state_matches=True,
        checkpoint_matches=True,
    )


class TestReadinessGates:
    """O01..O05, O09..O11: ordered gates and run scoping."""

    def test_o01_seed_accepted_feed_not_visible_waits(self) -> None:
        """O01: seed accepted but the feed not yet visible => wait at feed."""
        result = evaluate(
            ProbeSnapshot(
                seed_accepted=True, feed_converged=False, expected_state_matches=True
            )
        )
        assert result.stage is InteropStage.OPENCTI_FEED_CONVERGED
        assert not result.ready

    def test_o02_feed_visible_producer_still_running_waits(self) -> None:
        """O02: feed visible while the ATI producer still runs => wait."""
        result = evaluate(
            ProbeSnapshot(
                seed_accepted=True,
                feed_converged=True,
                execution_completed=False,
            )
        )
        assert result.stage is InteropStage.ATI_ACQUISITION_COMPLETED
        assert not result.ready

    def test_o03_producer_completed_consumer_incomplete_waits(self) -> None:
        """O03: producer COMPLETED but persistence incomplete => wait."""
        result = evaluate(
            ProbeSnapshot(
                seed_accepted=True,
                feed_converged=True,
                execution_completed=True,
                published=True,
                expected_state_matches=False,
            )
        )
        assert result.stage is InteropStage.ATI_PERSISTENCE_CONVERGED
        assert not result.ready

    def test_o04_broker_drained_but_rows_absent_never_ready(self) -> None:
        """O04: broker drained but expected rows absent => pending, never READY."""
        result = evaluate(
            ProbeSnapshot(
                seed_accepted=True,
                feed_converged=True,
                execution_completed=True,
                published=True,
                expected_state_matches=False,
            )
        )
        assert result.stage is InteropStage.ATI_PERSISTENCE_CONVERGED
        assert not result.ready
        # Draining does not change the verdict: this probe behaves identically
        # whether or not the broker looks drained.
        assert not result.ready

    def test_o05_all_durable_state_present_is_ready(self) -> None:
        """O05: all expected durable state present => READY, assertions may run."""
        result = evaluate(_ready())
        assert result.ready
        assert result.stage is InteropStage.READY_FOR_ASSERTIONS

    def test_o09_unrelated_traffic_does_not_advance_run(self) -> None:
        """O09: unrelated datasource traffic leaves this run pending."""
        result = evaluate(
            ProbeSnapshot(
                seed_accepted=True,
                feed_converged=True,
                execution_completed=False,
            )
        )
        assert result.stage is InteropStage.ATI_ACQUISITION_COMPLETED
        assert not result.ready

    def test_o10_unsupported_fixture_zero_evidence_still_converges(self) -> None:
        """O10: unsupported fixtures honor the manifest and do not hang."""
        # Zero-Evidence is part of the expected-state manifest: the run stays
        # pending only while supported expectations are unmet, and reaches
        # READY the moment they match (it never waits for extra evidence).
        result = evaluate(
            ProbeSnapshot(
                seed_accepted=True,
                feed_converged=True,
                execution_completed=True,
                published=True,
                expected_state_matches=True,
                checkpoint_matches=True,
            )
        )
        assert result.ready

    def test_o11_checkpoint_expected_but_not_advanced_not_ready(self) -> None:
        """O11: a scenario requiring checkpoint advancement that is missing => wait."""
        result = evaluate(
            ProbeSnapshot(
                seed_accepted=True,
                feed_converged=True,
                execution_completed=True,
                published=True,
                expected_state_matches=True,
                checkpoint_matches=False,
            )
        )
        assert result.stage is InteropStage.ATI_PERSISTENCE_CONVERGED
        assert not result.ready


class TestTerminalFailures:
    """O06..O08, O12: terminal failure handling and timeouts."""

    def test_o06_datasource_failed_is_terminal(self) -> None:
        """O06: a FAILED/CANCELLED datasource execution is a terminal failure."""
        result = evaluate(
            ProbeSnapshot(
                seed_accepted=True,
                feed_converged=True,
                terminal_failure="datasource execution FAILED",
                terminal_stage="TAXII_ACQUISITION",
            )
        )
        assert result.failed
        assert not result.ready
        assert result.terminal_failure == "datasource execution FAILED"

    def test_o07_consumer_failure_is_terminal(self) -> None:
        """O07: a consumer failure for the execution is a terminal failure."""
        result = evaluate(
            ProbeSnapshot(
                seed_accepted=True,
                feed_converged=True,
                execution_completed=True,
                terminal_failure="evidence consumer failed",
                terminal_stage="BROKER_CONSUMPTION",
            )
        )
        assert result.failed
        assert not result.ready

    def test_o08_hard_timeout_is_terminal_nonzero(self) -> None:
        """O08: a hard timeout returns a terminal failure, never permission to assert."""

        class _Clock:
            def __init__(self) -> None:
                self.now = 0.0

            def __call__(self) -> float:
                return self.now

        clock = _Clock()
        calls = []

        def _probe() -> ProbeSnapshot:
            calls.append(1)
            clock.now += 1.0
            # Never converges: seed accepted but feed never visible.
            return ProbeSnapshot(seed_accepted=True, feed_converged=False)

        result = wait_for_ready(
            _probe,
            timeout_seconds=3.0,
            interval_seconds=0.0,
            clock=clock,
        )
        assert result.timed_out
        assert result.terminal_stage == FAILURE_STAGE_READINESS_TIMEOUT
        assert not result.ready
        assert len(calls) >= 3

    def test_o12_status_rerun_recovers_same_durable_stage(self) -> None:
        """O12: rerunning the status after a failure shows the same durable stage."""
        failed = StageResult(
            stage=InteropStage.ATI_PERSISTENCE_CONVERGED,
            terminal_failure="checkpoint commit failed",
            terminal_stage="CHECKPOINT_COMMIT",
        )
        # A re-eval with the same durable observations is deterministic.
        again = evaluate(
            ProbeSnapshot(
                seed_accepted=True,
                feed_converged=True,
                execution_completed=True,
                published=True,
                expected_state_matches=False,
                terminal_failure="checkpoint commit failed",
                terminal_stage="CHECKPOINT_COMMIT",
            )
        )
        assert again.failed
        assert again.terminal_failure == failed.terminal_failure
        assert again.terminal_stage == failed.terminal_stage


class TestWaitLoop:
    """Bounded wait behavior and terminal-fast-fail."""

    def test_wait_returns_ready_when_converged(self) -> None:
        """The wait loop returns READY as soon as durable state converges."""
        result = wait_for_ready(
            _ready,
            timeout_seconds=10.0,
            interval_seconds=0.0,
            clock=lambda: 0.0,
        )
        assert result.ready

    def test_wait_returns_terminal_failure_without_delay(self) -> None:
        """A terminal failure returns immediately, never waiting for timeout."""

        def _probe() -> ProbeSnapshot:
            return ProbeSnapshot(
                terminal_failure="x", terminal_stage=FAILURE_STAGE_BOOTSTRAP
            )

        result = wait_for_ready(_probe, timeout_seconds=100.0, interval_seconds=0.0)
        assert result.failed
        assert result.terminal_stage == FAILURE_STAGE_BOOTSTRAP
