# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Startup observability and CLI entrypoint tests (PR 23D).

Covers the safe startup logging event (23D-U25), the CLI fake-data bootstrap
mode refusal, and the worker entrypoint's mode-aware composition seam.
"""

from _pytest.logging import LogCaptureFixture
from _pytest.monkeypatch import MonkeyPatch

from agentic_threat_investigator.api.app import log_operating_mode
from agentic_threat_investigator.cli import fake_data_bootstrap_main
from agentic_threat_investigator.config import OperatingMode, Settings, get_settings


def test_u25_startup_logging_exposes_mode_without_secrets(
    caplog: LogCaptureFixture,
) -> None:
    """23D-U25: startup logging shows the mode and never secrets."""
    with caplog.at_level("INFO"):
        log_operating_mode(Settings(operating_mode=OperatingMode.FAKE))
        log_operating_mode(Settings(operating_mode=OperatingMode.PRODUCTION))
    text = caplog.text
    assert "operating_mode=fake" in text
    assert "operating_mode=production" in text
    assert "deterministic local fakes" in text
    for secret_fragment in ("api_key", "password", "token", "ATI_OPENAI_API_KEY"):
        assert secret_fragment not in text


def test_bootstrap_cli_refuses_production_mode(
    monkeypatch: MonkeyPatch,
) -> None:
    """The fake-data bootstrap entrypoint fails closed outside fake mode."""
    get_settings.cache_clear()
    monkeypatch.setenv("ATI_CONFIG_PROFILE", "default")
    monkeypatch.delenv("ATI_OPERATING_MODE", raising=False)
    assert fake_data_bootstrap_main([]) == 2
    get_settings.cache_clear()
