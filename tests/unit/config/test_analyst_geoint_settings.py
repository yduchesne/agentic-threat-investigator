# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26F analyst GEOINT context-bound settings tests.

The deterministic context bounds have safe defaults, hard constructor-style
validation at the ``Settings`` boundary, appear in the default profile, and
can never be configured as \"unbounded\".
"""

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.config import load_config, settings_from_config


class TestAnalystGeointSettings:
    """Analyst GEOINT context-bound defaults and validation."""

    def test_defaults(self) -> None:
        """Default GEOINT context bounds are accepted and bounded."""
        settings = settings_from_config({})
        assert settings.analyst_geoint_max_entities == 10
        assert settings.analyst_geoint_max_observations_per_entity == 5
        assert settings.analyst_geoint_max_total_observations == 50
        assert settings.analyst_geoint_max_context_bytes == 262_144

    def test_profile_defaults_include_geoint_keys(self) -> None:
        """The default profile declares the non-secret GEOINT bounds."""
        config = load_config()
        assert config["analyst_geoint_max_entities"] == 10
        assert config["analyst_geoint_max_observations_per_entity"] == 5
        assert config["analyst_geoint_max_total_observations"] == 50
        assert config["analyst_geoint_max_context_bytes"] == 262_144

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("analyst_geoint_max_entities", 0),
            ("analyst_geoint_max_entities", 201),
            ("analyst_geoint_max_entities", True),
            ("analyst_geoint_max_observations_per_entity", 0),
            ("analyst_geoint_max_observations_per_entity", 201),
            ("analyst_geoint_max_observations_per_entity", 2.5),
            ("analyst_geoint_max_total_observations", 0),
            ("analyst_geoint_max_total_observations", 1001),
            ("analyst_geoint_max_context_bytes", 999),
            ("analyst_geoint_max_context_bytes", 1_000_001),
        ],
    )
    def test_bounded_integer_settings_reject_invalid_values(
        self, field: str, value: object
    ) -> None:
        """GEOINT context bounds reject out-of-range and non-integer values."""
        with pytest.raises(ValidationError):
            settings_from_config({field: value})

    @pytest.mark.parametrize(
        "field",
        [
            "analyst_geoint_max_entities",
            "analyst_geoint_max_observations_per_entity",
            "analyst_geoint_max_total_observations",
            "analyst_geoint_max_context_bytes",
        ],
    )
    def test_negative_values_rejected(self, field: str) -> None:
        """Negative bounds are rejected; \"unbounded\" is impossible."""
        with pytest.raises(ValidationError):
            settings_from_config({field: -1})

    def test_no_unbounded_sentinel(self) -> None:
        """No GEOINT bound may ever be configured as unbounded/None/infinite."""
        settings = settings_from_config({})
        for field_name in (
            "analyst_geoint_max_entities",
            "analyst_geoint_max_observations_per_entity",
            "analyst_geoint_max_total_observations",
            "analyst_geoint_max_context_bytes",
        ):
            value = getattr(settings, field_name)
            assert isinstance(value, int)
            assert value >= 1
