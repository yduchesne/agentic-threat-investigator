# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic FakeLlmClient for unit and integration tests.

The fake implements the same ``LlmClient`` ABC as the production adapter and
is driven by explicitly configured typed Pydantic results or typed failures.
It records every call, optionally asserts the requested response model, and
never parses prose.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel

from agentic_threat_investigator.app.llm import LlmClient, ResponseT


@dataclass(frozen=True)
class FakeLlmCall:
    """One recorded fake invocation with its exact arguments."""

    system_prompt: str
    user_prompt: str
    response_model: type[BaseModel]
    operation_name: str


class FakeLlmClient(LlmClient):  # pylint: disable=too-few-public-methods
    """A scripted, deterministic structured-output fake.

    Outcomes are consumed FIFO; when the queue is empty a configured default
    result is returned. An outcome may be a Pydantic instance (returned after
    type verification) or an exception (raised unchanged, so
    ``LlmError``/``asyncio.CancelledError`` simulations behave exactly like
    the real boundary).
    """

    def __init__(self) -> None:
        """Initialize with an empty outcome queue and call log."""
        self._outcomes: list[BaseModel | BaseException] = []
        self._default: BaseModel | None = None
        self.calls: list[FakeLlmCall] = []
        self.expected_response_model: type[BaseModel] | None = None

    def enqueue(self, outcome: BaseModel | BaseException) -> None:
        """Append one typed result or typed failure to the outcome queue."""
        self._outcomes.append(outcome)

    def set_default(self, outcome: BaseModel) -> None:
        """Set the fixed result returned when the outcome queue is empty."""
        self._default = outcome

    def expect_response_model_type(self, response_model: type[BaseModel]) -> None:
        """Assert every invocation requests exactly this response model."""
        self.expected_response_model = response_model

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        operation_name: str,
    ) -> ResponseT:
        """Record the invocation and return/raise the next scripted outcome."""
        self.calls.append(
            FakeLlmCall(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                operation_name=operation_name,
            )
        )
        if self.expected_response_model is not None:
            if response_model is not self.expected_response_model:
                raise AssertionError(
                    f"FakeLlmClient received {response_model.__name__} but was "
                    f"configured for {self.expected_response_model.__name__}"
                )
        if self._outcomes:
            outcome = self._outcomes.pop(0)
        elif self._default is not None:
            outcome = self._default
        else:
            raise AssertionError("FakeLlmClient has no outcome configured")
        if isinstance(outcome, BaseException):
            raise outcome
        if not isinstance(outcome, response_model):
            raise AssertionError(
                f"fake outcome type {type(outcome).__name__} is not "
                f"{response_model.__name__}"
            )
        return outcome
