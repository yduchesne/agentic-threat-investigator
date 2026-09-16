# SPDX-License-Identifier: AGPL-3.0-only
"""G26C-D05/D06: deterministic resolution-produced observation identity.

PR 26C completion never fabricates a random observation identity per retry:
the observation UUID is a deterministic UUIDv5 of the GeoResolution id under
a fixed dedicated ATI namespace, so the exact same successful work always
maps to the same observation identity (replay cannot duplicate) and distinct
work identities never collide.
"""

from __future__ import annotations

from uuid import UUID, uuid4, uuid5

from agentic_threat_investigator.domain.geoint import (
    ATI_OBSERVATION_NAMESPACE,
    observation_uuid_for_resolution,
)


def test_g26c_d05_same_work_yields_stable_observation_uuid() -> None:
    """G26C-D05 the same work identity always maps to the same observation UUID."""
    resolution_id = uuid4()
    first = observation_uuid_for_resolution(resolution_id)
    second = observation_uuid_for_resolution(resolution_id)
    assert first == second
    assert isinstance(first, UUID)
    # The identity is exactly UUIDv5 of the work id under the dedicated
    # fixed ATI namespace — a byte-deterministic contract.
    assert first == uuid5(ATI_OBSERVATION_NAMESPACE, str(resolution_id))
    assert first.version == 5


def test_g26c_d06_different_work_ids_yield_different_observation_uuids() -> None:
    """G26C-D06 distinct work identities never collide."""
    seen = {observation_uuid_for_resolution(uuid4()) for _ in range(100)}
    assert len(seen) == 100
