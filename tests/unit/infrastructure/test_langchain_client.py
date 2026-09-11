# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the LangChain structured-output adapter.

The adapter is exercised through a deterministic fake ``BaseChatModel`` and a
fake structured-output runnable: no real external model or network is ever
involved. Coverage includes schema handoff, setup-time and invocation-time
failure mapping with safe causes, result typing, cancellation propagation,
tracing metadata provenance, and the suppression of automatic content-bearing
LangSmith tracing.
"""

import asyncio
from collections.abc import Sequence
from typing import Any

import pytest
from langchain_core.exceptions import (
    ModelAuthenticationError,
    ModelError,
    ModelInvalidRequestError,
    ModelPermissionDeniedError,
    ModelRateLimitError,
    ModelTimeoutError,
    OutputParserException,
)
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import RunnableLambda
from langsmith import utils as ls_utils
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentic_threat_investigator.app.llm import LlmError, LlmErrorCode
from agentic_threat_investigator.infrastructure.llm.langchain_client import (
    LangChainLlmClient,
)

_SYSTEM_PROMPT = "You are the Evidence Analyst."
_USER_PROMPT = "Analyze the supplied evidence."
_OPERATION = "urn:ati:llm:evidence_analysis"
_OTHER_OPERATION = "urn:ati:llm:research_synthesis"


class _Result(BaseModel):
    """A minimal typed output model for adapter tests."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    verdict: str


def _pydantic_validation_error() -> ValidationError:
    """Return a genuine Pydantic ValidationError for failure-mapping tests."""
    try:
        _Result(verdict="x", unexpected=True)  # type: ignore[call-arg]
    except ValidationError as exc:
        return exc
    raise AssertionError("expected a ValidationError")


class FakeStructuredRunnable:
    """A deterministic stand-in for the framework's structured-output runnable."""

    def __init__(self, schema: type[BaseModel]) -> None:
        """Record the requested schema and clear the script."""
        self.schema = schema
        self.calls: list[tuple[Sequence[BaseMessage], dict[str, Any] | None]] = []
        self.result: Any = None
        self.error: BaseException | None = None

    async def ainvoke(
        self,
        messages: Sequence[BaseMessage],
        config: dict[str, Any] | None = None,
    ) -> Any:
        """Record the invocation and return/raise the scripted outcome."""
        assert isinstance(messages, list)
        self.calls.append((list(messages), config))
        if self.error is not None:
            raise self.error
        return self.result


class FakeChatModel(BaseChatModel):
    """A chat model whose structured-output handoff is fully scripted."""

    structured_schemas: list[type[BaseModel]] = Field(default_factory=list)
    runnable: FakeStructuredRunnable = Field(
        default_factory=lambda: FakeStructuredRunnable(BaseModel)
    )
    #: Raised by ``with_structured_output`` when set, simulating a
    #: framework/provider failure during runnable construction.
    setup_error: BaseException | None = None

    @property
    def _llm_type(self) -> str:
        """Return the fake model type name."""
        return "fake-chat-model"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        """Unused by structured-output path; implemented for the ABC."""
        del messages, stop, run_manager, kwargs
        return ChatResult(generations=[])

    def with_structured_output(  # type: ignore[override]
        self,
        schema: type[BaseModel],
        *,
        include_raw: bool = False,
        **kwargs: Any,
    ) -> FakeStructuredRunnable:
        """Record the schema and hand back the shared scripted runnable."""
        del include_raw, kwargs
        if self.setup_error is not None:
            raise self.setup_error
        self.structured_schemas.append(schema)
        self.runnable.schema = schema
        return self.runnable


class RecordingChatModel(BaseChatModel):
    """A real-plumbing chat model that records installed callback handlers.

    ``_generate`` never touches the network; ``with_structured_output`` uses
    the real ``PydanticOutputParser`` so the full framework invocation runs.
    The recorded ``seen_handler_types`` shows whether LangChain installed a
    ``LangChainTracer`` for the invocation.
    """

    seen_handler_types: list[str] = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        """Return the recording model type name."""
        return "recording-chat-model"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        """Record installed handlers and return a canned structured message."""
        del messages, stop, kwargs
        self.seen_handler_types = (
            [type(handler).__name__ for handler in run_manager.handlers]
            if run_manager is not None
            else []
        )
        return ChatResult(
            generations=[
                ChatGeneration(message=AIMessage(content='{"verdict":"suspicious"}'))
            ]
        )

    def with_structured_output(  # type: ignore[override]
        self,
        schema: type[BaseModel],
        **kwargs: Any,
    ) -> Any:
        """Return a runnable invoking the model then parsing its JSON output."""
        del kwargs
        parser = PydanticOutputParser(pydantic_object=schema)

        def parse_json_message(json_message: object) -> BaseModel:
            """Parse the model's JSON content into the requested schema."""
            content = getattr(json_message, "content", json_message)
            return parser.parse(str(content))

        return self | RunnableLambda(parse_json_message)


@pytest.fixture
def fake_model() -> FakeChatModel:
    """Return a fresh fake chat model per test."""
    return FakeChatModel()


@pytest.fixture
def client(fake_model: FakeChatModel) -> LangChainLlmClient:
    """Return the adapter bound to the fake model."""
    return LangChainLlmClient(fake_model)


@pytest.mark.asyncio
async def test_structured_output_handoff_uses_exact_model(
    fake_model: FakeChatModel, client: LangChainLlmClient
) -> None:
    """The adapter requests structured output for the exact Pydantic model."""
    fake_model.runnable.result = _Result(verdict="suspicious")

    result = await client.generate_structured(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=_USER_PROMPT,
        response_model=_Result,
        operation_name=_OPERATION,
    )

    assert fake_model.structured_schemas == [_Result]
    assert isinstance(result, _Result)
    assert result.verdict == "suspicious"


@pytest.mark.asyncio
async def test_async_invocation_uses_the_exact_prompts(
    fake_model: FakeChatModel, client: LangChainLlmClient
) -> None:
    """The runnable receives the system/user prompts as chat messages."""
    fake_model.runnable.result = _Result(verdict="benign")

    await client.generate_structured(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=_USER_PROMPT,
        response_model=_Result,
        operation_name=_OPERATION,
    )

    assert len(fake_model.runnable.calls) == 1
    messages = fake_model.runnable.calls[0][0]
    assert isinstance(messages[0], SystemMessage)
    assert isinstance(messages[1], HumanMessage)
    assert messages[0].content == _SYSTEM_PROMPT
    assert messages[1].content == _USER_PROMPT


@pytest.mark.asyncio
async def test_unexpected_dict_becomes_invalid_structured_output(
    fake_model: FakeChatModel, client: LangChainLlmClient
) -> None:
    """A dict returned instead of the requested model is never trusted."""
    fake_model.runnable.result = {"verdict": "suspicious"}

    with pytest.raises(LlmError) as holder:
        await client.generate_structured(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=_USER_PROMPT,
            response_model=_Result,
            operation_name=_OPERATION,
        )

    assert holder.value.code is LlmErrorCode.INVALID_STRUCTURED_OUTPUT
    assert holder.value.retryable is True
    assert holder.value.__cause__ is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception",
    [
        OutputParserException("malformed model output"),
        _pydantic_validation_error(),
    ],
)
async def test_parse_and_validation_failures_map_safely(
    fake_model: FakeChatModel,
    client: LangChainLlmClient,
    exception: Exception,
) -> None:
    """Parse/validation failures become bounded INVALID_STRUCTURED_OUTPUT."""
    fake_model.runnable.error = exception

    with pytest.raises(LlmError) as holder:
        await client.generate_structured(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=_USER_PROMPT,
            response_model=_Result,
            operation_name=_OPERATION,
        )

    assert holder.value.code is LlmErrorCode.INVALID_STRUCTURED_OUTPUT
    assert "malformed" not in str(holder.value)
    assert holder.value.__cause__ is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception",
    [asyncio.TimeoutError("took too long"), ModelTimeoutError("model timeout")],
)
async def test_timeouts_map_safely(
    fake_model: FakeChatModel,
    client: LangChainLlmClient,
    exception: Exception,
) -> None:
    """Timeouts become the bounded TIMEOUT category without content."""
    fake_model.runnable.error = exception

    with pytest.raises(LlmError) as holder:
        await client.generate_structured(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=_USER_PROMPT,
            response_model=_Result,
            operation_name=_OPERATION,
        )

    assert holder.value.code is LlmErrorCode.TIMEOUT
    assert holder.value.retryable is False
    assert holder.value.__cause__ is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exception",
    [
        ModelRateLimitError("rate limited"),
        ModelError("provider exploded with api key sk-secret-abc"),
        RuntimeError("socket error: api key sk-super-secret"),
    ],
)
async def test_provider_failures_map_safely(
    fake_model: FakeChatModel,
    client: LangChainLlmClient,
    exception: Exception,
) -> None:
    """Provider/unknown failures map to PROVIDER_FAILURE with safe messages."""
    fake_model.runnable.error = exception

    with pytest.raises(LlmError) as holder:
        await client.generate_structured(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=_USER_PROMPT,
            response_model=_Result,
            operation_name=_OPERATION,
        )

    assert holder.value.code is LlmErrorCode.PROVIDER_FAILURE
    assert holder.value.retryable is False
    assert holder.value.__cause__ is None
    assert "sk-secret-abc" not in str(holder.value)
    assert "sk-super-secret" not in str(holder.value)


@pytest.mark.asyncio
async def test_authentication_failures_map_to_configuration(
    fake_model: FakeChatModel, client: LangChainLlmClient
) -> None:
    """Authentication/permission failures are never retried."""
    fake_model.runnable.error = ModelAuthenticationError("bad key")

    with pytest.raises(LlmError) as holder:
        await client.generate_structured(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=_USER_PROMPT,
            response_model=_Result,
            operation_name=_OPERATION,
        )

    assert holder.value.code is LlmErrorCode.CONFIGURATION_ERROR
    assert holder.value.retryable is False
    assert holder.value.__cause__ is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_exception",
    [
        ModelAuthenticationError("bad key"),
        ModelPermissionDeniedError("nope"),
        ModelInvalidRequestError("bad request"),
    ],
)
async def test_setup_authentication_failures_map_to_configuration(
    fake_model: FakeChatModel,
    client: LangChainLlmClient,
    setup_exception: Exception,
) -> None:
    """Runnable-construction auth/permission failures are never retried."""
    fake_model.setup_error = setup_exception

    with pytest.raises(LlmError) as holder:
        await client.generate_structured(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=_USER_PROMPT,
            response_model=_Result,
            operation_name=_OPERATION,
        )

    assert holder.value.code is LlmErrorCode.CONFIGURATION_ERROR
    assert holder.value.retryable is False
    assert holder.value.__cause__ is None
    assert fake_model.runnable.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_exception",
    [ModelError("provider exploded"), RuntimeError("framework broke")],
)
async def test_setup_provider_failures_map_safely(
    fake_model: FakeChatModel,
    client: LangChainLlmClient,
    setup_exception: Exception,
) -> None:
    """Runnable-construction provider failures map to PROVIDER_FAILURE."""
    fake_model.setup_error = setup_exception

    with pytest.raises(LlmError) as holder:
        await client.generate_structured(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=_USER_PROMPT,
            response_model=_Result,
            operation_name=_OPERATION,
        )

    assert holder.value.code is LlmErrorCode.PROVIDER_FAILURE
    assert holder.value.retryable is False
    assert holder.value.__cause__ is None
    assert "provider exploded" not in str(holder.value)
    assert "framework broke" not in str(holder.value)
    assert fake_model.runnable.calls == []


@pytest.mark.asyncio
async def test_setup_timeout_maps_safely(
    fake_model: FakeChatModel, client: LangChainLlmClient
) -> None:
    """Runnable-construction timeouts map to the TIMEOUT category."""
    fake_model.setup_error = ModelTimeoutError("slow")

    with pytest.raises(LlmError) as holder:
        await client.generate_structured(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=_USER_PROMPT,
            response_model=_Result,
            operation_name=_OPERATION,
        )

    assert holder.value.code is LlmErrorCode.TIMEOUT
    assert holder.value.__cause__ is None


@pytest.mark.asyncio
async def test_cancellation_propagates_unchanged(
    fake_model: FakeChatModel, client: LangChainLlmClient
) -> None:
    """Cooperative cancellation is never wrapped into an LlmError."""
    fake_model.runnable.error = asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await client.generate_structured(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=_USER_PROMPT,
            response_model=_Result,
            operation_name=_OPERATION,
        )


@pytest.mark.asyncio
async def test_setup_cancellation_propagates_unchanged(
    fake_model: FakeChatModel, client: LangChainLlmClient
) -> None:
    """Cancellation during runnable construction also propagates unchanged."""
    fake_model.setup_error = asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await client.generate_structured(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=_USER_PROMPT,
            response_model=_Result,
            operation_name=_OPERATION,
        )


@pytest.mark.asyncio
async def test_blank_operation_name_rejected_before_model_handoff(
    fake_model: FakeChatModel, client: LangChainLlmClient
) -> None:
    """Blank operation names fail before with_structured_output or ainvoke."""
    fake_model.runnable.result = _Result(verdict="suspicious")

    with pytest.raises(ValueError, match="operation_name"):
        await client.generate_structured(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=_USER_PROMPT,
            response_model=_Result,
            operation_name="   ",
        )

    assert fake_model.structured_schemas == []
    assert fake_model.runnable.calls == []


@pytest.mark.asyncio
async def test_operation_metadata_comes_from_method_argument(
    fake_model: FakeChatModel,
) -> None:
    """The per-call operation argument controls the metadata operation."""
    traced = LangChainLlmClient(
        fake_model,
        trace_tags=("evidence_analyst",),
        trace_metadata={"investigation_id": "inv-1"},
    )
    fake_model.runnable.result = _Result(verdict="suspicious")

    await traced.generate_structured(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=_USER_PROMPT,
        response_model=_Result,
        operation_name=_OPERATION,
    )
    _messages, config = fake_model.runnable.calls[0]
    assert config is not None
    assert config["metadata"]["operation"] == _OPERATION
    assert config["metadata"]["investigation_id"] == "inv-1"
    assert config["tags"] == ["evidence_analyst"]

    await traced.generate_structured(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=_USER_PROMPT,
        response_model=_Result,
        operation_name=_OTHER_OPERATION,
    )
    _messages, config = fake_model.runnable.calls[1]
    assert config is not None
    # The method argument, not stale constructor state, drives the field.
    assert config["metadata"]["operation"] == _OTHER_OPERATION


@pytest.mark.asyncio
async def test_only_operation_metadata_is_passed_by_default(
    fake_model: FakeChatModel, client: LangChainLlmClient
) -> None:
    """Without configured metadata, only the operation key is emitted."""
    fake_model.runnable.result = _Result(verdict="suspicious")

    await client.generate_structured(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=_USER_PROMPT,
        response_model=_Result,
        operation_name=_OPERATION,
    )

    _messages, config = fake_model.runnable.calls[0]
    assert config is not None
    assert config["metadata"] == {"operation": _OPERATION}


def test_unknown_trace_metadata_keys_are_rejected(
    fake_model: FakeChatModel,
) -> None:
    """Content-like metadata keys can never leak into the runnable config."""
    for banned in (
        {"prompt": _USER_PROMPT, "investigation_id": "inv-1"},
        {"operation": _OPERATION, "investigation_id": "inv-1"},
    ):
        with pytest.raises(ValueError, match="unexpected LLM trace metadata"):
            LangChainLlmClient(fake_model, trace_metadata=banned)


@pytest.mark.asyncio
async def test_no_prompt_or_provider_content_is_logged(
    fake_model: FakeChatModel,
    client: LangChainLlmClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No prompt, model output, or provider-exception text reaches logging.

    Exercise both the success and the mapped-failure path; the adapter must
    not log content in either case.
    """
    fake_model.runnable.result = _Result(verdict="suspicious")
    await client.generate_structured(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=_USER_PROMPT,
        response_model=_Result,
        operation_name=_OPERATION,
    )
    fake_model.runnable.error = RuntimeError(
        "provider failed with api key sk-top-secret"
    )
    with pytest.raises(LlmError):
        await client.generate_structured(
            system_prompt=_SYSTEM_PROMPT,
            user_prompt=_USER_PROMPT,
            response_model=_Result,
            operation_name=_OPERATION,
        )

    records = caplog.records
    for record in records:
        for forbidden in (_SYSTEM_PROMPT, _USER_PROMPT, "sk-top-secret"):
            assert forbidden not in record.getMessage()


class _RecordingClient:
    """A recording tracer client: captures every run posted by LangChain.

    Installed via ``get_client`` during the tracing tests so the real
    ``LangChainTracer`` plumbing runs against an in-memory seam instead of
    the hosted LangSmith API. Runs include the full input/output payloads,
    which is exactly the content PR 20B must not export.
    """

    def __init__(self) -> None:
        """Initialize the recorded runs list."""
        self.runs: list[dict[str, Any]] = []

    def create_run(self, *args: object, **kwargs: object) -> str:
        """Record a run and return a synthetic identity."""
        del args
        self.runs.append(dict(kwargs))
        return "test-run-id"

    def update_run(self, *args: object, **kwargs: object) -> str:
        """Record an update and return a synthetic identity."""
        del args
        self.runs.append(dict(kwargs))
        return "test-run-id"


def _enable_langsmith_tracing(
    monkeypatch: pytest.MonkeyPatch,
    recording_client: _RecordingClient,
) -> None:
    """Enable framework-level LangSmith tracing against a recording seam.

    The langsmith env lookup is cached, so the cache is cleared after the
    environment is mutated. No real credential and no network are used: the
    installed ``LangChainTracer`` posts to the in-memory recording client.
    """
    monkeypatch.setenv("LANGCHAIN_TRACING_V2", "true")

    ls_utils.get_env_var.cache_clear()  # type: ignore[attr-defined]  # type: ignore[attr-defined]
    monkeypatch.setattr(
        "langchain_core.tracers.langchain.get_client",
        lambda: recording_client,
    )


@pytest.mark.asyncio
async def test_automatic_tracing_is_suppressed_for_analyst_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With tracing enabled, the adapter installs no tracer and exports nothing.

    The control model proves the environment WOULD install a content-capturing
    ``LangChainTracer`` whose recording client receives the prompt text; the
    adapter's invocation installs no tracer and records nothing.
    """
    control_client = _RecordingClient()
    _enable_langsmith_tracing(monkeypatch, control_client)
    control = RecordingChatModel()
    control_runnable = control.with_structured_output(_Result)
    control_result = await control_runnable.ainvoke(
        [HumanMessage(content=_USER_PROMPT)]
    )
    assert type(control_result).__name__ == "_Result"
    assert "LangChainTracer" in control.seen_handler_types
    # The control run exported to the recording seam includes the prompt
    # content, demonstrating that un-suppressed tracing would capture it.
    assert control_client.runs
    captured = control_client.runs[0]["inputs"]
    assert _USER_PROMPT in str(captured)

    suppressed_client = _RecordingClient()
    monkeypatch.setattr(
        "langchain_core.tracers.langchain.get_client",
        lambda: suppressed_client,
    )
    recorded = RecordingChatModel()
    adapter = LangChainLlmClient(recorded)
    result = await adapter.generate_structured(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=_USER_PROMPT,
        response_model=_Result,
        operation_name=_OPERATION,
    )
    assert isinstance(result, _Result)
    # The framework callback manager received no content-capturing tracer,
    # so the recording seam received no run and no content was exported.
    assert recorded.seen_handler_types == []
    assert not suppressed_client.runs


@pytest.mark.asyncio
async def test_safe_metadata_does_not_reenable_tracing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Passing operation/investigation metadata keeps tracing suppressed."""
    recording_client = _RecordingClient()
    _enable_langsmith_tracing(monkeypatch, recording_client)
    recorded = RecordingChatModel()
    adapter = LangChainLlmClient(recorded, trace_metadata={"investigation_id": "inv-1"})

    result = await adapter.generate_structured(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=_USER_PROMPT,
        response_model=_Result,
        operation_name=_OPERATION,
    )

    assert isinstance(result, _Result)
    assert "LangChainTracer" not in recorded.seen_handler_types
    assert not recording_client.runs
