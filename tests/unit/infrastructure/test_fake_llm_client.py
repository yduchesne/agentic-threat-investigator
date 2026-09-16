# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the FakeLlmClient response-factory seam.

``set_response_factory`` lets evaluation tests script a response that
depends on the exact request the fake recorded for the current invocation
(for example, a citation drawn from the actual supplied retrieval) without
probing the production retriever independently. These tests pin the factory
precedence and type safety of that seam.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from tests.support.llm_fixtures import FakeLlmCall, FakeLlmClient


class Echo(BaseModel):
    """A minimal structured response model for factory tests."""

    text: str


@pytest.mark.asyncio
async def test_factory_receives_exact_recorded_call_and_returns_response() -> None:
    """The factory sees the recorded call and its result is type-verified."""
    fake = FakeLlmClient()

    def factory(call: FakeLlmCall) -> BaseModel:
        assert call.user_prompt == "prompt"
        assert call.response_model is Echo
        assert call.operation_name == "test"
        return Echo(text=call.user_prompt)

    fake.set_response_factory(factory)
    result = await fake.generate_structured(
        system_prompt="system",
        user_prompt="prompt",
        response_model=Echo,
        operation_name="test",
    )
    assert result == Echo(text="prompt")
    assert len(fake.calls) == 1


@pytest.mark.asyncio
async def test_queue_takes_precedence_over_factory() -> None:
    """Explicit FIFO outcomes still win over the factory derivation."""
    fake = FakeLlmClient()
    fake.enqueue(Echo(text="queued"))
    fake.set_response_factory(lambda call: Echo(text=f"factory-{call.user_prompt}"))
    first = await fake.generate_structured(
        system_prompt="", user_prompt="one", response_model=Echo, operation_name=""
    )
    second = await fake.generate_structured(
        system_prompt="", user_prompt="two", response_model=Echo, operation_name=""
    )
    assert first == Echo(text="queued")
    assert second == Echo(text="factory-two")


@pytest.mark.asyncio
async def test_factory_runs_before_default() -> None:
    """A configured factory shadows the fixed default."""
    fake = FakeLlmClient()
    fake.set_default(Echo(text="default"))
    fake.set_response_factory(lambda call: Echo(text=f"factory-{call.user_prompt}"))
    result = await fake.generate_structured(
        system_prompt="", user_prompt="actual", response_model=Echo, operation_name=""
    )
    assert result == Echo(text="factory-actual")


@pytest.mark.asyncio
async def test_factory_type_mismatch_is_rejected() -> None:
    """Factory responses are verified against the requested response model."""
    fake = FakeLlmClient()

    class Other(BaseModel):
        value: str

    fake.set_response_factory(lambda call: Other(value="wrong"))
    try:
        await fake.generate_structured(
            system_prompt="", user_prompt="p", response_model=Echo, operation_name=""
        )
    except AssertionError as error:
        assert "fake outcome type" in str(error)
    else:  # pragma: no cover - the mismatch must raise
        raise AssertionError("type-mismatched factory output was accepted")


@pytest.mark.asyncio
async def test_factory_exception_is_raised_unchanged() -> None:
    """Exceptions returned by the factory propagate like scripted failures."""
    fake = FakeLlmClient()
    error = LlmError(LlmErrorCode.PROVIDER_FAILURE, retryable=True)
    fake.set_response_factory(lambda call: error)
    raised = None
    try:
        await fake.generate_structured(
            system_prompt="", user_prompt="p", response_model=Echo, operation_name=""
        )
    except LlmError as caught:
        raised = caught
    assert raised is error


@pytest.mark.asyncio
async def test_clear_response_factory_restores_default_behavior() -> None:
    """Clearing the factory restores the fixed-default behavior."""
    fake = FakeLlmClient()
    fake.set_default(Echo(text="default"))
    fake.set_response_factory(lambda call: Echo(text="factory"))
    fake.clear_response_factory()
    result = await fake.generate_structured(
        system_prompt="", user_prompt="p", response_model=Echo, operation_name=""
    )
    assert result == Echo(text="default")


@pytest.mark.asyncio
async def test_missing_factory_prompt_has_no_outcome() -> None:
    """Without outcomes, factory, or default, the fake still fails closed."""
    fake = FakeLlmClient()
    try:
        await fake.generate_structured(
            system_prompt="", user_prompt="p", response_model=Echo, operation_name=""
        )
    except AssertionError as error:
        assert "no outcome configured" in str(error)
    else:  # pragma: no cover - the missing outcome must raise
        raise AssertionError("fake accepted an invocation without an outcome")
