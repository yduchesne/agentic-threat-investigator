# SPDX-License-Identifier: AGPL-3.0-only
"""G26F-V / G26F-G matrices: deterministic geographic output validation.

Proves the validator operates only on the exact supplied observation/
Evidence pairs: unknown, substituted, cross-scope, structurally unsupported,
and containment-less references are rejected before persistence, while
descriptive shared-location, history, and location-change findings pass with
exact support. The independent-support gate rejects geography-only positive
verdicts and the approved vocabulary makes prohibited inferences impossible.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.app.evidence_analyst.geoint_validation import (
    GeographicFindingValidationError,
    GeointFindingValidator,
    map_geographic_findings,
)
from agentic_threat_investigator.domain.analyst import (
    AnalystEntityGeointContext,
    AnalystGeointContext,
    AnalystGeointLocation,
    EvidenceAnalystDecision,
    GeographicFinding,
    GeographicFindingKind,
    GeographicTemporalInterpretation,
)
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    Verdict,
)
from agentic_threat_investigator.domain.entities import EntityType
from agentic_threat_investigator.domain.geoint import LocationType
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from tests.support.geoint_fixtures import FIXED, analyst_observation, analyst_summary


class World:
    """One fixed observation world: E1 Seattle history, E2 Seattle, E1 Dallas.

    ``o1``/``o2`` observe E1 in Seattle (newer then older), ``o3`` observes
    E2 in Seattle, and ``o4`` observes E1 in Dallas at a later time.
    """

    def __init__(self) -> None:
        """Bind the fixed identities and observations.

        Every observation carries its own exact Evidence identity (one
        Evidence row backs exactly one resolved observation), so each
        observation/Evidence pair is globally unique like the persisted
        resolution path.
        """
        self.e1, self.e2 = uuid4(), uuid4()
        self.ev1 = uuid4()  # o1
        self.ev2 = uuid4()  # o2
        self.ev3 = uuid4()  # o3
        self.ev4 = uuid4()  # o4
        self.loc_sea = AnalystGeointLocation(
            location_id=uuid4(),
            location_type=LocationType.CITY,
            canonical_location_name="Seattle",
            country_code="US",
            admin1_code="WA",
        )
        self.loc_dal = AnalystGeointLocation(
            location_id=uuid4(),
            location_type=LocationType.CITY,
            canonical_location_name="Dallas",
            country_code="US",
            admin1_code="TX",
        )
        self.o1 = analyst_observation(
            observation_id=uuid4(),
            entity_id=self.e1,
            evidence_id=self.ev1,
            location=self.loc_sea,
        )
        self.o2 = analyst_observation(
            observation_id=uuid4(),
            entity_id=self.e1,
            evidence_id=self.ev2,
            location=self.loc_sea,
            observed_at=FIXED - timedelta(days=1),
        )
        self.o3 = analyst_observation(
            observation_id=uuid4(),
            entity_id=self.e2,
            evidence_id=self.ev3,
            location=self.loc_sea,
        )
        self.o4 = analyst_observation(
            observation_id=uuid4(),
            entity_id=self.e1,
            evidence_id=self.ev4,
            location=self.loc_dal,
            observed_at=FIXED + timedelta(days=1),
        )

    def context(
        self, *, contained_observation_ids: tuple[UUID, ...] = ()
    ) -> AnalystGeointContext:
        """Build the model-visible context over this world."""
        return AnalystGeointContext(
            summary=analyst_summary(
                observation_count=4,
                entity_count_with_location=2,
                location_count=2,
            ),
            entities=(
                AnalystEntityGeointContext(
                    entity_id=self.e1,
                    entity_type=EntityType.IP_ADDRESS,
                    entity_value="203.0.113.10",
                    current_observation=self.o4,
                    history=(self.o1, self.o2),
                ),
                AnalystEntityGeointContext(
                    entity_id=self.e2,
                    entity_type=EntityType.IP_ADDRESS,
                    entity_value="203.0.113.20",
                    current_observation=self.o3,
                    history=(),
                ),
            ),
            contained_observation_ids=contained_observation_ids,
        )

    def decision(
        self,
        *,
        finding: GeographicFinding,
        verdict: Verdict = Verdict.INCONCLUSIVE,
        findings: tuple[AnalyticalFinding, ...] = (),
        context: AnalystGeointContext | None = None,
    ) -> tuple[EvidenceAnalystDecision, AnalystGeointContext | None]:
        """Build a decision carrying one geographic finding over the context."""
        return (
            EvidenceAnalystDecision(
                verdict=verdict,
                confidence=AssessmentConfidence.LOW,
                summary="Geographic analysis.",
                disposition=AnalysisDisposition.EXHAUSTED,
                findings=findings,
                geographic_findings=(finding,),
            ),
            context if context is not None else self.context(),
        )


def shared_finding(
    world: World,
    *,
    observation_ids: tuple[UUID, ...] | None = None,
    evidence_ids: tuple[UUID, ...] | None = None,
    entity_ids: tuple[UUID, ...] | None = None,
    location_ids: tuple[UUID, ...] | None = None,
) -> GeographicFinding:
    """Build one shared-location finding over the world's exact identities."""
    return GeographicFinding(
        kind=GeographicFindingKind.SHARED_LOCATION,
        statement="Both entities were observed in Seattle.",
        temporal_interpretation=GeographicTemporalInterpretation.DIFFERENT_OBSERVATION_TIMES,
        observation_ids=observation_ids
        or (world.o1.observation_id, world.o3.observation_id),
        evidence_ids=evidence_ids or (world.o1.evidence_id, world.o3.evidence_id),
        entity_ids=entity_ids or (world.e1, world.e2),
        location_ids=location_ids or (world.loc_sea.location_id,),
    )


def test_g26f_v01_exact_observation_evidence_pair_accepted() -> None:
    """G26F-V01 an exact supplied observation/Evidence pair is accepted."""
    world = World()
    decision, context = world.decision(finding=shared_finding(world))
    GeointFindingValidator(context).validate(decision)  # no raise


def test_g26f_v01b_no_context_fails_closed() -> None:
    """G26F-V01b without supplied context every citation is rejected."""
    world = World()
    decision, _ = world.decision(finding=shared_finding(world))
    with pytest.raises(Exception) as holder:
        GeointFindingValidator(None).validate(decision)
    assert "unknown or omitted observation" in str(holder.value)


def test_g26f_v02_unknown_observation_rejected() -> None:
    """G26F-V02 an observation outside the supplied context is rejected."""
    world = World()
    finding = shared_finding(world, observation_ids=(uuid4(), world.o3.observation_id))
    decision, context = world.decision(finding=finding)
    with pytest.raises(Exception) as holder:
        GeointFindingValidator(context).validate(decision)
    assert "unknown or omitted observation" in str(holder.value)


def test_g26f_v03_substitute_evidence_rejected() -> None:
    """G26F-V03 substituting another observation's Evidence is rejected."""
    world = World()
    # Swapped evidence: each cited observation is real, but the Evidence at
    # each index is the OTHER observation's Evidence (a substitute).
    finding = shared_finding(
        world,
        observation_ids=(world.o1.observation_id, world.o3.observation_id),
        evidence_ids=(world.o3.evidence_id, world.o1.evidence_id),
    )
    decision, context = world.decision(finding=finding)
    with pytest.raises(Exception) as holder:
        GeointFindingValidator(context).validate(decision)
    assert "evidence does not match the cited observation" in str(holder.value)


def test_g26f_v04_wrong_entity_rejected() -> None:
    """G26F-V04 an Entity claim not matching the cited observations is rejected."""
    world = World()
    finding = shared_finding(world, entity_ids=(world.e1, uuid4()))
    decision, context = world.decision(finding=finding)
    with pytest.raises(Exception) as holder:
        GeointFindingValidator(context).validate(decision)
    assert "entity_ids" in str(holder.value)


def test_g26f_v05_wrong_location_rejected() -> None:
    """G26F-V05 a Location claim not matching the cited observations is rejected."""
    world = World()
    finding = shared_finding(world, location_ids=(world.loc_dal.location_id,))
    decision, context = world.decision(finding=finding)
    with pytest.raises(Exception) as holder:
        GeointFindingValidator(context).validate(decision)
    assert "location_ids" in str(holder.value)


def test_g26f_v06_shared_location_exact_support_accepted() -> None:
    """G26F-V06 a shared-location claim with exact support is accepted."""
    world = World()
    finding = shared_finding(world)
    decision, context = world.decision(finding=finding)
    GeointFindingValidator(context).validate(decision)


def test_g26f_v06b_single_observation_descriptive_context_accepted() -> None:
    """A single supplied observation supports a descriptive context finding."""
    world = World()
    finding = GeographicFinding(
        kind=GeographicFindingKind.SHARED_LOCATION,
        statement="The entity was observed in Seattle.",
        temporal_interpretation=GeographicTemporalInterpretation.NONE,
        observation_ids=(world.o1.observation_id,),
        evidence_ids=(world.o1.evidence_id,),
        entity_ids=(world.e1,),
        location_ids=(world.loc_sea.location_id,),
    )
    decision, context = world.decision(finding=finding)
    GeointFindingValidator(context).validate(decision)


def test_g26f_v07_different_locations_claimed_shared_rejected() -> None:
    """G26F-V07 observations in different Locations cannot be shared-location."""
    world = World()
    e3 = uuid4()
    ev5 = uuid4()
    o5 = analyst_observation(
        observation_id=uuid4(),
        entity_id=e3,
        evidence_id=ev5,
        location=world.loc_dal,
    )
    base = world.context()
    context = AnalystGeointContext(
        summary=base.summary,
        entities=base.entities
        + (
            AnalystEntityGeointContext(
                entity_id=e3,
                entity_type=EntityType.IP_ADDRESS,
                entity_value="203.0.113.30",
                current_observation=o5,
                history=(),
            ),
        ),
    )
    finding = shared_finding(
        world,
        observation_ids=(world.o1.observation_id, o5.observation_id),
        evidence_ids=(world.o1.evidence_id, ev5),
        entity_ids=(world.e1, e3),
        location_ids=(world.loc_sea.location_id, world.loc_dal.location_id),
    )
    decision, _ = world.decision(finding=finding, context=context)
    with pytest.raises(Exception) as holder:
        GeointFindingValidator(context).validate(decision)
    assert "share one canonical location" in str(holder.value)


def test_g26f_v08_history_across_entities_rejected() -> None:
    """G26F-V08 a location-history claim spanning Entities is rejected."""
    world = World()
    finding = GeographicFinding(
        kind=GeographicFindingKind.LOCATION_HISTORY,
        statement="Entity history.",
        temporal_interpretation=GeographicTemporalInterpretation.DIFFERENT_OBSERVATION_TIMES,
        observation_ids=(world.o1.observation_id, world.o3.observation_id),
        evidence_ids=(world.o1.evidence_id, world.o3.evidence_id),
        entity_ids=(world.e1, world.e2),
        location_ids=(world.loc_sea.location_id,),
    )
    decision, context = world.decision(finding=finding)
    with pytest.raises(Exception) as holder:
        GeointFindingValidator(context).validate(decision)
    assert "one entity" in str(holder.value)


def test_g26f_v09_location_change_accepted() -> None:
    """G26F-V09 same Entity, different Locations and times: change accepted."""
    world = World()
    finding = GeographicFinding(
        kind=GeographicFindingKind.LOCATION_CHANGE_OBSERVED,
        statement="The entity was observed in Seattle and later in Dallas.",
        temporal_interpretation=GeographicTemporalInterpretation.LOCATION_CHANGE_OBSERVED,
        observation_ids=(world.o1.observation_id, world.o4.observation_id),
        evidence_ids=(world.o1.evidence_id, world.o4.evidence_id),
        entity_ids=(world.e1,),
        location_ids=(world.loc_sea.location_id, world.loc_dal.location_id),
    )
    decision, context = world.decision(finding=finding)
    GeointFindingValidator(context).validate(decision)


def test_g26f_v10_same_location_repeated_is_not_change() -> None:
    """G26F-V10 repeated same Location observations are not a location change."""
    world = World()
    finding = GeographicFinding(
        kind=GeographicFindingKind.LOCATION_CHANGE_OBSERVED,
        statement="Location changed.",
        temporal_interpretation=GeographicTemporalInterpretation.LOCATION_CHANGE_OBSERVED,
        observation_ids=(world.o1.observation_id, world.o2.observation_id),
        evidence_ids=(world.o1.evidence_id, world.o2.evidence_id),
        entity_ids=(world.e1,),
        location_ids=(world.loc_sea.location_id,),
    )
    decision, context = world.decision(finding=finding)
    with pytest.raises(Exception) as holder:
        GeointFindingValidator(context).validate(decision)
    assert "different canonical locations" in str(holder.value)


def test_g26f_v10b_equal_effective_times_not_change() -> None:
    """Equal effective observation times cannot establish a location change."""
    world = World()
    first_evidence, second_evidence = uuid4(), uuid4()
    both_retrieved = analyst_observation(
        observation_id=uuid4(),
        entity_id=world.e1,
        evidence_id=first_evidence,
        location=world.loc_sea,
        observed_at=None,
        retrieved_at=FIXED,
    )
    both_retrieved_dal = analyst_observation(
        observation_id=uuid4(),
        entity_id=world.e1,
        evidence_id=second_evidence,
        location=world.loc_dal,
        observed_at=None,
        retrieved_at=FIXED,
    )
    context = AnalystGeointContext(
        summary=analyst_summary(
            observation_count=2, entity_count_with_location=1, location_count=2
        ),
        entities=(
            AnalystEntityGeointContext(
                entity_id=world.e1,
                entity_type=EntityType.IP_ADDRESS,
                entity_value="203.0.113.10",
                current_observation=both_retrieved_dal,
                history=(both_retrieved,),
            ),
        ),
    )
    finding = GeographicFinding(
        kind=GeographicFindingKind.LOCATION_CHANGE_OBSERVED,
        statement="Location changed.",
        temporal_interpretation=GeographicTemporalInterpretation.LOCATION_CHANGE_OBSERVED,
        observation_ids=(
            both_retrieved.observation_id,
            both_retrieved_dal.observation_id,
        ),
        evidence_ids=(first_evidence, second_evidence),
        entity_ids=(world.e1,),
        location_ids=(world.loc_sea.location_id, world.loc_dal.location_id),
    )
    decision, _ = world.decision(finding=finding, context=context)
    with pytest.raises(Exception) as holder:
        GeointFindingValidator(context).validate(decision)
    assert "distinct effective observation times" in str(holder.value)


def test_g26f_v11_containment_not_established_rejected() -> None:
    """G26F-V11 containment claims require an established containment selection."""
    world = World()
    finding = GeographicFinding(
        kind=GeographicFindingKind.CONTAINED_LOCATION_CONTEXT,
        statement="The country contains these observations.",
        temporal_interpretation=GeographicTemporalInterpretation.NONE,
        observation_ids=(world.o1.observation_id,),
        evidence_ids=(world.o1.evidence_id,),
        entity_ids=(world.e1,),
        location_ids=(world.loc_sea.location_id,),
    )
    decision, context = world.decision(finding=finding)
    with pytest.raises(Exception) as holder:
        GeointFindingValidator(context).validate(decision)
    assert "containment selection" in str(holder.value)

    # The same finding is accepted when the selection was containment-tagged.
    decision, context = world.decision(
        finding=finding,
        context=world.context(contained_observation_ids=(world.o1.observation_id,)),
    )
    GeointFindingValidator(context).validate(decision)


def test_g26f_v12_omitted_observation_rejected() -> None:
    """G26F-V12 an observation omitted from the supplied context is rejected."""
    world = World()
    observation = analyst_observation(
        observation_id=uuid4(), entity_id=world.e1, evidence_id=world.ev1
    )
    finding = shared_finding(
        world,
        observation_ids=(observation.observation_id, world.o3.observation_id),
        evidence_ids=(observation.evidence_id, world.o3.evidence_id),
        entity_ids=(world.e1, world.e2),
        location_ids=(world.loc_sea.location_id,),
    )
    decision, context = world.decision(finding=finding)
    with pytest.raises(Exception) as holder:
        GeointFindingValidator(context).validate(decision)
    assert "unknown or omitted observation" in str(holder.value)


def test_g26f_g01_same_city_coordination_impossible() -> None:
    """G26F-G01 no coordination kind exists: same-city stays descriptive."""
    with pytest.raises(ValidationError):
        GeographicFinding(
            kind="coordinated_activity",  # type: ignore[arg-type]
            statement="Both are coordinated because both are in Seattle.",
            observation_ids=(uuid4(), uuid4()),
            evidence_ids=(uuid4(), uuid4()),
            entity_ids=(uuid4(), uuid4()),
            location_ids=(uuid4(),),
        )


def test_g26f_g02_same_coordinate_ownership_impossible() -> None:
    """G26F-G02 no common-ownership kind exists."""
    with pytest.raises(ValidationError):
        GeographicFinding(
            kind="common_owner",  # type: ignore[arg-type]
            statement="Same coordinates imply common ownership.",
            observation_ids=(uuid4(), uuid4()),
            evidence_ids=(uuid4(), uuid4()),
            entity_ids=(uuid4(), uuid4()),
            location_ids=(uuid4(),),
        )


def test_g26f_g03_containment_campaign_impossible() -> None:
    """G26F-G03 no campaign kind exists: containment stays contextual."""
    with pytest.raises(ValidationError):
        GeographicFinding(
            kind="campaign_match",  # type: ignore[arg-type]
            statement="Country containment implies one campaign.",
            observation_ids=(uuid4(),),
            evidence_ids=(uuid4(),),
            entity_ids=(uuid4(),),
            location_ids=(uuid4(),),
        )


def test_g26f_g04_geoint_only_malicious_rejected() -> None:
    """G26F-G04 geography alone cannot support a MALICIOUS verdict."""
    world = World()
    decision, context = world.decision(
        finding=shared_finding(world), verdict=Verdict.MALICIOUS
    )
    with pytest.raises(Exception) as holder:
        GeointFindingValidator(context).validate(decision)
    assert "cannot support a non-INCONCLUSIVE verdict" in str(holder.value)


def test_g26f_g04b_geoint_only_suspicious_rejected() -> None:
    """G26F-G04b geography alone cannot support any positive verdict."""
    world = World()
    decision, context = world.decision(
        finding=shared_finding(world), verdict=Verdict.SUSPICIOUS
    )
    with pytest.raises(GeographicFindingValidationError):
        GeointFindingValidator(context).validate(decision)


def test_g26f_g05_independent_evidence_plus_geographic_context_allowed() -> None:
    """G26F-G05 independent non-geographic support allows descriptive GEOINT."""
    world = World()
    independent = AnalyticalFinding(
        category=FindingCategory.REPUTATION,
        disposition=FindingDisposition.SUPPORTING,
        statement="A block-list source reports the indicator.",
        confidence=AssessmentConfidence.MEDIUM,
        support=(EvidenceSupport(kind="evidence", evidence_id=uuid4()),),
    )
    decision, context = world.decision(
        finding=shared_finding(world),
        verdict=Verdict.MALICIOUS,
        findings=(independent,),
    )
    GeointFindingValidator(context).validate(decision)
    mapped = map_geographic_findings(decision)
    assert len(mapped) == 2
    assert mapped[0] is independent
    assert mapped[1].category is FindingCategory.GEOLOCATION
    assert [
        s.evidence_id for s in mapped[1].support if isinstance(s, EvidenceSupport)
    ] == [world.o1.evidence_id, world.o3.evidence_id]


def test_g26f_g06_two_locations_movement_impossible() -> None:
    """G26F-G06 no movement/travel kind exists: sequential Locations stay data."""
    with pytest.raises(ValidationError):
        GeographicFinding(
            kind="movement_route",  # type: ignore[arg-type]
            statement="The entity traveled between the locations.",
            observation_ids=(uuid4(), uuid4()),
            evidence_ids=(uuid4(), uuid4()),
            entity_ids=(uuid4(),),
            location_ids=(uuid4(), uuid4()),
        )


def test_g26f_g07_two_locations_change_allowed() -> None:
    """G26F-G07 descriptive location change remains representable."""
    world = World()
    finding = GeographicFinding(
        kind=GeographicFindingKind.LOCATION_CHANGE_OBSERVED,
        statement="Two supported observations identify different locations.",
        temporal_interpretation=GeographicTemporalInterpretation.LOCATION_CHANGE_OBSERVED,
        observation_ids=(world.o1.observation_id, world.o4.observation_id),
        evidence_ids=(world.o1.evidence_id, world.o4.evidence_id),
        entity_ids=(world.e1,),
        location_ids=(world.loc_sea.location_id, world.loc_dal.location_id),
    )
    decision, context = world.decision(finding=finding)
    GeointFindingValidator(context).validate(decision)


def test_g26f_g08_missing_observed_at_uses_retrieved_at() -> None:
    """G26F-G08 a missing observed_at never invents an observed time.

    The effective time defaults to ``retrieved_at`` (existing PR 26A
    semantics); the mapped durable finding carries no invented timestamp.
    """
    world = World()
    first_evidence, second_evidence = uuid4(), uuid4()
    first = analyst_observation(
        observation_id=uuid4(),
        entity_id=world.e1,
        evidence_id=first_evidence,
        location=world.loc_sea,
        observed_at=None,
        retrieved_at=FIXED,
    )
    second = analyst_observation(
        observation_id=uuid4(),
        entity_id=world.e1,
        evidence_id=second_evidence,
        location=world.loc_dal,
        observed_at=None,
        retrieved_at=FIXED + timedelta(days=2),
    )
    context = AnalystGeointContext(
        summary=analyst_summary(
            observation_count=2, entity_count_with_location=1, location_count=2
        ),
        entities=(
            AnalystEntityGeointContext(
                entity_id=world.e1,
                entity_type=EntityType.IP_ADDRESS,
                entity_value="203.0.113.10",
                current_observation=second,
                history=(first,),
            ),
        ),
    )
    finding = GeographicFinding(
        kind=GeographicFindingKind.LOCATION_CHANGE_OBSERVED,
        statement="The entity was observed at different locations at different times.",
        temporal_interpretation=GeographicTemporalInterpretation.LOCATION_CHANGE_OBSERVED,
        observation_ids=(first.observation_id, second.observation_id),
        evidence_ids=(first_evidence, second_evidence),
        entity_ids=(world.e1,),
        location_ids=(world.loc_sea.location_id, world.loc_dal.location_id),
    )
    decision, _ = world.decision(finding=finding, context=context)
    GeointFindingValidator(context).validate(decision)
    mapped = map_geographic_findings(decision)[0]
    assert mapped.statement == finding.statement
    assert "2026-01-02" not in mapped.statement


def test_mapping_without_geographic_findings_is_unchanged() -> None:
    """No geographic findings maps to the existing Findings unchanged."""
    decision = EvidenceAnalystDecision(
        verdict=Verdict.INCONCLUSIVE,
        confidence=AssessmentConfidence.LOW,
        summary="Summary.",
        disposition=AnalysisDisposition.EXHAUSTED,
    )
    assert map_geographic_findings(decision) == decision.findings == ()
