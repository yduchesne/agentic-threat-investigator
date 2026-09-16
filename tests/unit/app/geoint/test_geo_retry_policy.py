# SPDX-License-Identifier: AGPL-3.0-only
"""G26C-B matrix: deterministic bounded exponential backoff policy.

The worker-side pure backoff function must mirror the database-owned formula
``base * 2^(attempt_count - 1)`` capped at the configured maximum, with no
jitter: identical inputs always schedule identical delays.
"""

from __future__ import annotations

import pytest

from agentic_threat_investigator.app.geoint.worker import (
    GeoResolutionWorkerConfig,
    retry_delay_seconds,
)


def test_g26c_b01_attempt_one_uses_the_base_delay() -> None:
    """G26C-B01 the first failed attempt schedules exactly the base delay."""
    assert retry_delay_seconds(1, base_seconds=60.0, max_seconds=3600.0) == 60.0


def test_g26c_b02_attempt_two_doubles_the_base_delay() -> None:
    """G26C-B02 the second failed attempt doubles the base delay."""
    assert retry_delay_seconds(2, base_seconds=60.0, max_seconds=3600.0) == 120.0


def test_g26c_b03_high_attempts_are_capped_at_the_maximum() -> None:
    """G26C-B03 exponential growth never exceeds the configured maximum."""
    assert retry_delay_seconds(5, base_seconds=60.0, max_seconds=3600.0) == 960.0
    assert retry_delay_seconds(10, base_seconds=60.0, max_seconds=3600.0) == 3600.0
    assert retry_delay_seconds(50, base_seconds=60.0, max_seconds=3600.0) == 3600.0


def test_g26c_b04_invalid_config_is_rejected() -> None:
    """G26C-B04 invalid worker policy configuration fails closed."""
    with pytest.raises(ValueError, match="max_attempts"):
        GeoResolutionWorkerConfig(
            worker_id="w1",
            batch_size=10,
            lease_seconds=300,
            poll_interval_seconds=1.0,
            max_attempts=0,
            retry_base_seconds=60.0,
            retry_max_seconds=3600.0,
        )
    with pytest.raises(ValueError, match="retry_base_seconds"):
        GeoResolutionWorkerConfig(
            worker_id="w1",
            batch_size=10,
            lease_seconds=300,
            poll_interval_seconds=1.0,
            max_attempts=3,
            retry_base_seconds=0.0,
            retry_max_seconds=3600.0,
        )
    with pytest.raises(ValueError, match="retry_max_seconds"):
        GeoResolutionWorkerConfig(
            worker_id="w1",
            batch_size=10,
            lease_seconds=300,
            poll_interval_seconds=1.0,
            max_attempts=3,
            retry_base_seconds=60.0,
            retry_max_seconds=30.0,
        )
    with pytest.raises(ValueError, match="worker_id"):
        GeoResolutionWorkerConfig(
            worker_id="   ",
            batch_size=10,
            lease_seconds=300,
            poll_interval_seconds=1.0,
            max_attempts=3,
            retry_base_seconds=60.0,
            retry_max_seconds=3600.0,
        )
    with pytest.raises(ValueError, match="attempt_count"):
        retry_delay_seconds(0, base_seconds=60.0, max_seconds=3600.0)


def test_g26c_b05_same_input_yields_the_same_delay_no_jitter() -> None:
    """G26C-B05 identical inputs schedule identical delays (no random jitter)."""
    delays = {
        retry_delay_seconds(3, base_seconds=60.0, max_seconds=3600.0)
        for _ in range(100)
    }
    assert delays == {240.0}
