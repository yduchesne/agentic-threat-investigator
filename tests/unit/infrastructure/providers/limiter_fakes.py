# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic clock and sleep fakes for BoundedLimiter admission tests.

These fakes keep rate-admission tests free of wall-clock timing: time only
advances when a test explicitly releases a gated sleep or advances the fake
clock, so assertions on reserved slots and reclaim behavior are exact.
"""

from __future__ import annotations

import asyncio


class FakeRateClock:
    """A manually advanced monotonic clock for rate-admission tests."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        """Return the current fake monotonic time."""
        return self.now

    def advance(self, seconds: float) -> None:
        """Advance the fake clock by the given elapsed seconds."""
        self.now += seconds


class GatedSleep:
    """Injected sleep that records delays and blocks until its gate is released.

    Each call records the requested delay, appends one gate, and blocks until
    that gate is set. Releasing a gate models the elapsing of that wait: the
    fake clock advances by the requested delay before the call returns. A
    canceled call leaves its recorded delay and an orphaned gate behind and
    advances nothing.
    """

    def __init__(self, clock: FakeRateClock) -> None:
        self._clock = clock
        self.calls: list[float] = []
        self._gates: list[asyncio.Event] = []

    async def __call__(self, seconds: float) -> None:
        """Record the delay, block on this call's gate, then elapse it."""
        self.calls.append(seconds)
        gate = asyncio.Event()
        self._gates.append(gate)
        await gate.wait()
        self._clock.advance(seconds)

    def gate(self, index: int) -> asyncio.Event:
        """Return the gate controlling the recorded sleep call at ``index``."""
        return self._gates[index]
