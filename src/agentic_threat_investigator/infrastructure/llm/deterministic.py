# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic offline LLM boundary for test/demo worker composition.

:class:`DeterministicLlmClient` implements the same ``LlmClient`` ABC as the
production LangChain adapter but never touches the network and never reads
configuration, environment variables, or secret values. It is selected
explicitly by ``ATI_LLM_DRIVER=deterministic`` and is used by the real-stack
fake-world browser E2E slice (PR 24B): the worker process runs the
production ``InvestigationRunner``, coordinator graph, providers,
persistence, Evidence Analyst, Research Agent, and Report Writer with this
scripted model boundary instead of a live LLM.

The client is deliberately coupled to the repository-owned deterministic
prompt renderings (``evidence_analyst/prompts.py``, ``research_agent/
prompts.py``, ``report_writer/prompts.py``): it reflects only exact stable
labels and identities already supplied in the prompt, so it can never invent
Evidence, RelationshipObservation, Assessment, or Research identities. A
future prompt-rendering change may require a matching update here; a unit
test pins the reflection behavior. Unknown operations and unparseable
inputs fail closed with a bounded ``LlmError`` exactly like a provider
schema failure — loose prose is never tolerated.
"""

from __future__ import annotations

import re as _re
from uuid import UUID

from agentic_threat_investigator.app.evidence_analyst.prompts import (
    OPERATION_EVIDENCE_ANALYSIS,
)
from agentic_threat_investigator.app.llm import (
    LlmClient,
    LlmError,
    LlmErrorCode,
    ResponseT,
)
from agentic_threat_investigator.app.report_writer.prompts import (
    OPERATION_REPORT_WRITING,
)
from agentic_threat_investigator.app.research_agent.prompts import (
    OPERATION_RESEARCH_SYNTHESIS,
)
from agentic_threat_investigator.domain.analyst import EvidenceAnalystDecision
from agentic_threat_investigator.domain.assessment import (
    AnalyticalFinding,
    AssessmentConfidence,
    EvidenceSupport,
    FindingCategory,
    FindingDisposition,
    RelationshipSupport,
    Verdict,
)
from agentic_threat_investigator.domain.investigation import AnalysisDisposition
from agentic_threat_investigator.domain.report import (
    AssessmentFindingRef,
    ReportNarrativeStatement,
    ReportWriterOutput,
)
from agentic_threat_investigator.domain.research_agent import ResearchAgentDecision

_UUID_PATTERN = _re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

_EVIDENCE_ID_LINE = _re.compile(
    r"evidence(?:_observation)?_id: (" + _UUID_PATTERN.pattern + r")"
)
_OBSERVATION_ID_LINE = _re.compile(
    r"relationship_observation_id: (" + _UUID_PATTERN.pattern + r")"
)
_ASSESSMENT_ID_LINE = _re.compile(r"assessment_id: (" + _UUID_PATTERN.pattern + r")")
_FINDING_ORDINAL_LINE = _re.compile(r"- AF-(\d+):")

# Deterministic analysis trajectory matching the canonical F02 fake-world
# slice: three bounded collection rounds, then a sufficient malicious
# conclusion over the corroborated evidence. Every path terminates; the
# exact round count is an observable, not a correctness requirement.
_NEEDS_MORE_ROUNDS = 3

_NEEDS_MORE_SUMMARY = (
    "The evidence collected so far is insufficient to conclude; another "
    "bounded collection round is justified."
)
_SUFFICIENT_SUMMARY = (
    "Correlated multi-source evidence is sufficient to conclude that the "
    "root indicator is part of malicious delivery infrastructure."
)
_LIMITATION = (
    "Deterministic scripted boundary: conclusions reflect the supplied "
    "synthetic-world evidence only."
)
_RECOMMENDED_STEP = (
    "Monitor the resolved delivery infrastructure for further pivot-worthy "
    "observations."
)

_EXECUTIVE_STATEMENT = (
    "The investigation concluded that the root indicator participates in "
    "malicious delivery infrastructure with high confidence."
)

_REPORT_TITLE = "ATI deterministic investigation report"


def _parse_uuids(lines: list[str]) -> list[str]:
    """Return the unique bounded UUID strings of one rendered label."""
    seen: list[str] = []
    for line in lines:
        if line not in seen:
            seen.append(line)
    return seen


class DeterministicLlmClient(LlmClient):
    """A scripted, offline, prompt-reflecting ``LlmClient`` implementation.

    The client keeps one process-local analysis round counter (the worker
    executes one Investigation at a time, starting from round one, so the
    canonical needs-more/ sufficient trajectory is deterministic across E2E
    runs). Research synthesis deterministically expresses no relevant
    context; report writing reflects the supplied Assessment finding
    ordinals. Every returned value is an instance of the exact requested
    response model.
    """

    def __init__(self) -> None:
        """Initialize the analysis round counter."""
        self._evidence_rounds = 0
        self.calls: list[tuple[str, str]] = []

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        operation_name: str,
    ) -> ResponseT:
        """Return an instance of ``response_model`` or raise ``LlmError``.

        Cancellation never applies (no I/O), so the bounded failure taxonomy
        covers unknown operations and unparseable prompt inputs; both raise
        a non-retryable ``INVALID_STRUCTURED_OUTPUT`` error with a safe,
        content-free message.
        """
        self.calls.append((operation_name, user_prompt))
        del system_prompt
        expected_model = {
            OPERATION_EVIDENCE_ANALYSIS: EvidenceAnalystDecision,
            OPERATION_RESEARCH_SYNTHESIS: ResearchAgentDecision,
            OPERATION_REPORT_WRITING: ReportWriterOutput,
        }.get(operation_name)
        if expected_model is None:
            raise LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False)
        if response_model is not expected_model:
            raise LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False)
        if operation_name == OPERATION_EVIDENCE_ANALYSIS:
            return self._evidence_decision(user_prompt)  # type: ignore[return-value]
        if operation_name == OPERATION_RESEARCH_SYNTHESIS:
            return self._research_decision(user_prompt)  # type: ignore[return-value]
        return self._report_output(user_prompt)  # type: ignore[return-value]

    def _evidence_decision(self, user_prompt: str) -> EvidenceAnalystDecision:
        """Author the next bounded Evidence Analyst decision.

        The first ``_NEEDS_MORE_ROUNDS`` calls request another collection
        round without findings; every later call concludes with a sufficient
        MALICIOUS/high Assessment whose Findings cite only Evidence and
        RelationshipObservation identities reflected from the prompt.
        """
        self._evidence_rounds += 1
        if self._evidence_rounds <= _NEEDS_MORE_ROUNDS:
            return EvidenceAnalystDecision(
                verdict=Verdict.SUSPICIOUS,
                confidence=AssessmentConfidence.MEDIUM,
                summary=_NEEDS_MORE_SUMMARY,
                disposition=AnalysisDisposition.NEEDS_MORE_EVIDENCE,
            )

        evidence_ids = _parse_uuids(_EVIDENCE_ID_LINE.findall(user_prompt))
        observation_ids = _parse_uuids(_OBSERVATION_ID_LINE.findall(user_prompt))
        findings: list[AnalyticalFinding] = []
        if evidence_ids:
            findings.append(
                AnalyticalFinding(
                    category=FindingCategory.REPUTATION,
                    disposition=FindingDisposition.SUPPORTING,
                    statement=(
                        "Threat-intelligence and reputation sources associate "
                        "the root indicator with known malicious delivery "
                        "infrastructure."
                    ),
                    confidence=AssessmentConfidence.HIGH,
                    support=(
                        EvidenceSupport(
                            kind="evidence", evidence_id=UUID(evidence_ids[0])
                        ),
                    ),
                )
            )
        if observation_ids:
            findings.append(
                AnalyticalFinding(
                    category=FindingCategory.NETWORK,
                    disposition=FindingDisposition.SUPPORTING,
                    statement=(
                        "Graph-backed observations connect the root indicator "
                        "to shared hosting and resolution infrastructure used "
                        "by the delivery campaign."
                    ),
                    confidence=AssessmentConfidence.HIGH,
                    support=(
                        RelationshipSupport(
                            kind="relationship_observation",
                            relationship_observation_id=UUID(observation_ids[0]),
                        ),
                    ),
                )
            )
        return EvidenceAnalystDecision(
            verdict=Verdict.MALICIOUS,
            confidence=AssessmentConfidence.HIGH,
            summary=_SUFFICIENT_SUMMARY,
            disposition=AnalysisDisposition.SUFFICIENT,
            findings=tuple(findings),
            limitations=(_LIMITATION,),
            unresolved_questions=(),
            recommended_next_steps=(_RECOMMENDED_STEP,),
        )

    def _research_decision(self, user_prompt: str) -> ResearchAgentDecision:
        """Deterministically express that no supplied context substantiates a claim.

        ``claims=()`` is a documented valid outcome (``research_agent.py``);
        the persisted result remains the empty-context first-class result
        with zero model-authored claims.
        """
        del user_prompt
        return ResearchAgentDecision(claims=())

    def _report_output(self, user_prompt: str) -> ReportWriterOutput:
        """Reflect the supplied Assessment into one bounded ReportWriterOutput.

        The executive summary statement supports exactly the first Assessment
        finding ordinal rendered as ``AF-<n>``; ``finding_order`` carries the
        same bounded ordinal. Verdict/confidence/limitations/questions/next
        steps are application-stamped and never authored here.
        """
        assessment_id_lines = _ASSESSMENT_ID_LINE.findall(user_prompt)
        if len(assessment_id_lines) != 1:
            raise LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False)
        ordinals = [
            int(ordinal) for ordinal in _FINDING_ORDINAL_LINE.findall(user_prompt)
        ]
        if not ordinals:
            raise LlmError(LlmErrorCode.INVALID_STRUCTURED_OUTPUT, retryable=False)
        first_ordinal = ordinals[0]
        return ReportWriterOutput(
            title=_REPORT_TITLE,
            executive_summary=(
                ReportNarrativeStatement(
                    text=_EXECUTIVE_STATEMENT,
                    support=(
                        AssessmentFindingRef(
                            kind="assessment_finding",
                            assessment_id=UUID(assessment_id_lines[0]),
                            finding_ordinal=first_ordinal,
                        ),
                    ),
                ),
            ),
            finding_order=(first_ordinal,),
            research_context=(),
        )
