# SPDX-License-Identifier: AGPL-3.0-only
"""Authenticated runtime-mode metadata route (PR 23D).

``GET /api/v1/runtime`` reports the selected operating mode so PR 24 can
display a persistent ``FAKE DATA`` indicator. It is read-only and
authenticated; no request may switch the operating mode.
"""

from __future__ import annotations

from typing import cast

from fastapi import APIRouter, Request

from agentic_threat_investigator.api.dependencies import AnalystUser
from agentic_threat_investigator.api.dto.runtime import RuntimeInfoResponse
from agentic_threat_investigator.api.errors import ApiError, ApiErrorCode
from agentic_threat_investigator.config import Settings

router = APIRouter(prefix="/api/v1/runtime", tags=["runtime"])


@router.get(
    "",
    response_model=RuntimeInfoResponse,
    operation_id="get_runtime_info",
)
async def get_runtime_info(
    request: Request,
    _user: AnalystUser,
) -> RuntimeInfoResponse:
    """Return the selected intelligence-source composition mode.

    Only the lowercase ``fake``/``production`` operating mode is exposed;
    no credential, secret reference, LLM provider, or configuration value is
    included.
    """
    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        raise ApiError(
            ApiErrorCode.DEPENDENCY_UNAVAILABLE,
            "Application settings are unavailable.",
            503,
        )
    composed = cast(Settings, settings)
    return RuntimeInfoResponse.from_operating_mode(composed.operating_mode.value)
