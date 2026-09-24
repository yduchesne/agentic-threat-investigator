# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 30E repository-owned fixture infrastructure tests (RPT-F01..F09).

Deterministic and offline: exact fixture lookup, fail-closed resolution, and
the run-scoped execution-identity contract are proven with in-memory
resolutions and the committed corpus. The source-inspection test proves the
production evaluation package never imports ``tests.support``. Database-backed
materializer behaviors (canonical Entity reuse, Assessment/Research
persistence, no destructive reset) are asserted by the PostgreSQL vertical
slice; this module covers the pure identity/lookup/source-contract parts.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from agentic_threat_investigator.evaluation.report_writer.fixtures import (
    report_scenario_resolution,
)
from agentic_threat_investigator.evaluation.report_writer.scenarios import (
    REPORT_WRITER_FIXTURES,
    report_writer_fixture,
)
from tests.support.report_writer_evaluation import (
    corpus_scenario,
    scenario_resolution,
)

S01 = "rpt-s01-clearly-malicious"


class TestFixtureLookup:
    """F01/F02: exact fixture lookup and fail-closed resolution."""

    def test_f01_known_fixture_returns_exact_fixture(self) -> None:
        """F01 a known fixture name resolves to the exact canonical fixture."""
        fixture = report_writer_fixture("report-malicious")
        assert fixture is REPORT_WRITER_FIXTURES["report-malicious"]
        assert fixture.root_entity == "target_domain"
        assert fixture.verdict.value == "malicious"

    def test_f02_unknown_fixture_fails_closed(self) -> None:
        """F02 an unknown fixture name fails closed with a typed KeyError."""
        with pytest.raises(KeyError):
            report_writer_fixture("no-such-fixture")


class TestExecutionIdentity:
    """F03/F04: deterministic and isolated execution-scoped identities."""

    def test_f03_same_execution_identity_is_deterministic(self) -> None:
        """F03 the same execution identity yields identical resolutions."""
        scenario = corpus_scenario(S01)
        execution_id = uuid4()
        first = scenario_resolution(scenario, execution_id=execution_id)
        second = scenario_resolution(scenario, execution_id=execution_id)
        assert first == second
        assert first.investigation_id == second.investigation_id
        assert first.research_claim_ids == second.research_claim_ids

    def test_f04_different_execution_identity_isolates_owned_ids(self) -> None:
        """F04 different executions isolate execution-owned IDs but reuse canonical ones."""
        scenario = corpus_scenario(S01)
        resolution_a = scenario_resolution(scenario, execution_id=uuid4())
        resolution_b = scenario_resolution(scenario, execution_id=uuid4())
        # Execution-owned worlds are isolated.
        assert resolution_a.investigation_id != resolution_b.investigation_id
        assert resolution_a.assessment_id != resolution_b.assessment_id
        assert set(resolution_a.evidence_ids.values()) != set(
            resolution_b.evidence_ids.values()
        )
        assert set(resolution_a.research_claim_ids.values()) != set(
            resolution_b.research_claim_ids.values()
        )
        # Canonical Entity/Relationship identities stay global.
        assert resolution_a.entity_ids == resolution_b.entity_ids
        assert resolution_a.relationship_ids == resolution_b.relationship_ids

    def test_f04b_default_identity_matches_pre_30e(self) -> None:
        """F04 the default (no execution id) keeps the deterministic pre-30E world."""
        scenario = corpus_scenario(S01)
        defaulted = scenario_resolution(scenario, execution_id=None)
        explicit = scenario_resolution(scenario)
        assert defaulted == explicit
        assert isinstance(defaulted.investigation_id, UUID)


class TestProductionBoundary:
    """F09: production evaluation code never imports tests.support."""

    def test_f09_evaluation_package_has_no_tests_support_import(self) -> None:
        """F09 the report-writer evaluation package never imports tests.support."""
        root = (
            Path(__file__).parents[3]
            / "src"
            / "agentic_threat_investigator"
            / "evaluation"
            / "report_writer"
        )
        for path in sorted(root.glob("*.py")):
            source = inspect.getsource(
                __import__(
                    f"agentic_threat_investigator.evaluation.report_writer.{path.stem}",
                    fromlist=["*"],
                )
            )
            assert "tests.support" not in source, path
            assert "tests/" not in source, path


def test_scenario_resolution_helpers_agree() -> None:
    """F04 the helper and direct builder agree on execution identities."""
    scenario = corpus_scenario(S01)
    execution_id = uuid4()
    from agentic_threat_investigator.evaluation.report_writer.scenarios import (
        report_writer_fixture,
    )

    fixture = report_writer_fixture(scenario.fixture)
    direct = report_scenario_resolution(scenario, fixture, execution_id=execution_id)
    assert direct == scenario_resolution(scenario, execution_id=execution_id)


@pytest.mark.parametrize("name", sorted(REPORT_WRITER_FIXTURES))
def test_f01_all_fixtures_resolve(name: str) -> None:
    """F01 every committed fixture name resolves to a nonempty fixture."""
    fixture = report_writer_fixture(name)
    assert fixture.entities
    assert fixture.root_entity
