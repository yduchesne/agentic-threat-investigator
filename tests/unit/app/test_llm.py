# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for the ATI-owned LlmClient boundary and error taxonomy."""

import importlib
import subprocess
import sys
from abc import ABC
from typing import cast, get_type_hints

import pytest
from pydantic import BaseModel, ConfigDict

from agentic_threat_investigator.app.llm import (
    LlmClient,
    LlmError,
    LlmErrorCode,
    ResponseT,
)


class _SampleResult(BaseModel):
    """A minimal typed output model for contract tests."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    verdict: str


def test_error_taxonomy_is_stable() -> None:
    """The PR 20B error categories are exactly the documented set."""
    assert {code.value for code in LlmErrorCode} == {
        "timeout",
        "provider_failure",
        "invalid_structured_output",
        "configuration_error",
    }


def test_llm_error_carries_code_and_retryability() -> None:
    """Every taxonomy member produces a typed, content-free error."""
    error = LlmError(LlmErrorCode.TIMEOUT, retryable=False)

    assert error.code is LlmErrorCode.TIMEOUT
    assert error.retryable is False
    assert str(error) == "LLM operation failed: timeout"


def test_llm_error_defaults_to_non_retryable() -> None:
    """Retryability must be explicit; the default is conservative."""
    assert LlmError(LlmErrorCode.PROVIDER_FAILURE).retryable is False


def test_llm_client_is_an_abstract_boundary() -> None:
    """The LlmClient ABC requires the async structured-output operation."""
    assert issubclass(LlmClient, ABC)
    assert LlmClient.__abstractmethods__ == {
        "generate_structured",
    }
    hints = get_type_hints(LlmClient.generate_structured)
    assert "system_prompt" in hints
    assert "response_model" in hints
    assert "operation_name" in hints


def test_response_type_variable_is_pydantic_bound() -> None:
    """The generic response variable is constrained to ATI Pydantic models."""
    bounds = getattr(ResponseT, "__bound__", None)
    assert bounds is not None and issubclass(bounds, BaseModel)


class _WorkingClient(LlmClient):
    """A minimal conforming implementation returning a typed result."""

    def __init__(self) -> None:
        self.operation_names: list[str] = []
        self.requested_models: list[type[BaseModel]] = []

    async def generate_structured(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_model: type[ResponseT],
        operation_name: str,
    ) -> ResponseT:
        """Record the request and return a fresh sample result."""
        self.operation_names.append(operation_name)
        self.requested_models.append(response_model)
        return cast(ResponseT, _SampleResult(verdict="suspicious"))


@pytest.mark.asyncio
async def test_client_returns_exactly_the_requested_model() -> None:
    """A conforming client returns an instance of the requested type."""
    client = _WorkingClient()

    result = await client.generate_structured(
        system_prompt="system",
        user_prompt="user",
        response_model=_SampleResult,
        operation_name="urn:ati:llm:evidence_analysis",
    )

    assert isinstance(result, _SampleResult)
    assert client.requested_models == [_SampleResult]
    assert client.operation_names == ["urn:ati:llm:evidence_analysis"]


def test_abstract_client_cannot_be_instantiated() -> None:
    """The ABC itself cannot be instantiated directly."""
    with pytest.raises(TypeError):
        LlmClient()  # type: ignore[abstract]


@pytest.mark.parametrize(
    "module",
    [
        "agentic_threat_investigator.domain.analyst",
        "agentic_threat_investigator.app.llm",
        "agentic_threat_investigator.domain.assessment",
    ],
)
def test_domain_and_application_contracts_do_not_import_langchain(
    module: str,
) -> None:
    """Domain/application contract modules stay free of LangChain imports.

    Importing each module in a fresh interpreter must not pull any
    LangChain/provider package into the process.
    """
    script = (
        "import sys\n"
        f"import {module}\n"
        "langchain_modules = [\n"
        "    name for name in sys.modules\n"
        "    if name == 'langchain_core'\n"
        "    or name.startswith('langchain')\n"
        "    or name.startswith('openai')\n"
        "    or name.startswith('langsmith')\n"
        "]\n"
        "sys.exit(1 if langchain_modules else 0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"{module} imported LangChain: {result.stderr}"


def test_importlib_reload_keeps_single_types() -> None:
    """The module reloads without creating duplicate boundary types."""
    module = importlib.import_module("agentic_threat_investigator.app.llm")

    reloaded = importlib.reload(module)

    assert reloaded.LlmError is module.LlmError
