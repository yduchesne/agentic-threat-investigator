# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Provider execution-policy and mandatory recursion-bound unit tests (PR 35-4)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from agentic_threat_investigator.app.orchestration.runner import (
    mandatory_recursion_allowance,
    recursion_limit_for_budget,
)
from agentic_threat_investigator.app.providers import (
    EvidenceProvider,
    ProviderExecutionPolicy,
)
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.investigation import (
    InvestigationBudget,
    InvestigationState,
    InvestigationStatus,
    InvestigationTriggerType,
)
from agentic_threat_investigator.infrastructure.fake_runtime.catalog import (
    FakeWorldCatalog,
)
from agentic_threat_investigator.infrastructure.fake_runtime.providers import (
    FakeWorldEvidenceProvider,
)
from agentic_threat_investigator.infrastructure.providers.dbip_city_lite import (
    CityLiteDatabase,
    DbIpCityLiteProvider,
)


def test_dbip_city_lite_is_mandatory_geoint() -> None:
    """M16: production DB-IP is classified mandatory GEOINT."""
    database = cast(CityLiteDatabase, object())
    provider = DbIpCityLiteProvider(database)
    assert provider.execution_policy is ProviderExecutionPolicy.MANDATORY_GEOINT


def test_fake_dbip_mirrors_production_policy() -> None:
    """M16: fake DB-IP carries the exact production policy, other fakes do not."""
    catalog = FakeWorldCatalog.load_packaged()
    fake_dbip = FakeWorldEvidenceProvider(SourceId.DBIP_CITY_LITE, catalog)
    fake_rdap = FakeWorldEvidenceProvider(SourceId.RDAP, catalog)
    assert fake_dbip.execution_policy is ProviderExecutionPolicy.MANDATORY_GEOINT
    assert fake_rdap.execution_policy is ProviderExecutionPolicy.INVESTIGATIVE


def test_default_provider_policy_is_investigative() -> None:
    """A provider that does not override the capability is investigative."""
    from uuid import UUID

    from agentic_threat_investigator.app.providers import ProviderResult
    from agentic_threat_investigator.domain.entities import Entity

    class _MinimalProvider(EvidenceProvider):
        @property
        def id(self) -> str:
            return SourceId.GOOGLE_PUBLIC_DNS.value

        def supports(self, entity: Entity) -> bool:
            return False

        async def investigate(
            self, investigation_id: UUID, entity: Entity
        ) -> ProviderResult:
            raise NotImplementedError

    assert _MinimalProvider().execution_policy is ProviderExecutionPolicy.INVESTIGATIVE


def _state(
    *, max_provider_calls: int = 40, provider_calls_used: int = 0
) -> InvestigationState:
    from uuid import UUID

    return InvestigationState(
        investigation_id=uuid4(),
        status=InvestigationStatus.RUNNING,
        trigger_type=InvestigationTriggerType.MANUAL,
        root_entity_ids=[UUID(int=1)],
        discovered_entity_ids=[UUID(int=2)],
        objective="recursion bound",
        budget=InvestigationBudget(
            max_depth=2,
            max_entities=10,
            max_provider_calls=max_provider_calls,
            max_replans=3,
            max_llm_calls=10,
            provider_calls_used=provider_calls_used,
        ),
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_recursion_limit_for_budget_is_unchanged_by_mandatory_work() -> None:
    """The base investigative recursion bound remains a pure budget function."""
    budget = InvestigationBudget(
        max_depth=2,
        max_entities=10,
        max_provider_calls=4,
        max_replans=3,
        max_llm_calls=5,
    )
    assert recursion_limit_for_budget(budget) > 0


def test_mandatory_recursion_allowance_is_zero_without_mandatory_providers() -> None:
    """No mandatory provider means no extra mandatory recursion headroom."""
    assert mandatory_recursion_allowance(_state(), mandatory_provider_count=0) == 0


def test_mandatory_recursion_allowance_is_finite_and_grows_with_providers() -> None:
    """The allowance is a finite positive bound that grows with providers."""
    one = mandatory_recursion_allowance(_state(), mandatory_provider_count=1)
    two = mandatory_recursion_allowance(_state(), mandatory_provider_count=2)
    assert 0 < one < two
    assert (
        mandatory_recursion_allowance(
            _state(max_provider_calls=0, provider_calls_used=0),
            mandatory_provider_count=1,
        )
        > 0
    )
