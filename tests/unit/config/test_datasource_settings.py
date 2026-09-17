# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 27A datasource configuration contract tests.

Covers the typed ``Settings.datasources`` collection: default representative
definitions, profile-provided definitions, unique datasource IDs
(D27A-10), shared providers across instances, fail-closed unknown values,
and preservation of provider-specific operational settings.
"""

import pytest
from pydantic import ValidationError

from agentic_threat_investigator.config.settings import Settings, settings_from_config
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)


def _threatfox_definition(datasource_id: str) -> dict[str, object]:
    """Build one documented ThreatFox-shaped definition as profile JSON."""
    return {
        "datasource_id": datasource_id,
        "source_id": SourceId.THREATFOX,
        "protocol": DatasourceProtocol.HTTPS,
        "serialization_format": SerializationFormat.JSON,
        "semantic_format": SemanticFormatId.THREATFOX,
    }


def test_default_settings_expose_representative_definitions() -> None:
    """Settings defaults carry the two documented representative definitions."""
    settings = Settings()
    assert len(settings.datasources) == 2
    by_id = {d.datasource_id.value: d for d in settings.datasources}
    assert by_id["threatfox-live"].source_id is SourceId.THREATFOX
    assert by_id["threatfox-live"].protocol is DatasourceProtocol.HTTPS
    assert by_id["threatfox-live"].semantic_format is SemanticFormatId.THREATFOX
    assert by_id["mitre-attack-enterprise"].source_id is SourceId.MITRE_ATTACK
    assert by_id["mitre-attack-enterprise"].protocol is DatasourceProtocol.FILE
    assert by_id["mitre-attack-enterprise"].semantic_format is SemanticFormatId.STIX_21
    for definition in settings.datasources:
        assert isinstance(definition, DatasourceDefinition)
        assert definition.serialization_format is SerializationFormat.JSON


def test_profile_provided_definitions_parse_to_typed_models() -> None:
    """Profile values are validated into the canonical typed definition."""
    settings = settings_from_config(
        {
            "datasources": [
                _threatfox_definition("threatfox-live"),
                {
                    "datasource_id": "mitre-attack-enterprise",
                    "source_id": SourceId.MITRE_ATTACK,
                    "protocol": "file",
                    "serialization_format": "json",
                    "semantic_format": "urn:ati:datasource:semanticformat:stix21",
                },
            ]
        }
    )
    assert len(settings.datasources) == 2
    assert settings.datasources[0].datasource_id.value == "threatfox-live"
    assert settings.datasources[1].semantic_format is SemanticFormatId.STIX_21


def test_d27a_10_duplicate_datasource_ids_are_rejected() -> None:
    """D27A-10: a Settings collection rejects duplicate datasource IDs."""
    duplicate = [
        _threatfox_definition("threatfox-live"),
        _threatfox_definition("threatfox-live"),
    ]
    with pytest.raises(ValidationError, match="unique datasource IDs"):
        Settings(datasources=duplicate)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="unique datasource IDs"):
        settings_from_config({"datasources": duplicate})


def test_shared_source_id_with_distinct_datasource_ids_is_accepted() -> None:
    """Two datasource instances may share one ``SourceId`` at Settings level."""
    settings = settings_from_config(
        {
            "datasources": [
                _threatfox_definition("threatfox-live"),
                _threatfox_definition("threatfox-replay"),
            ]
        }
    )
    assert len(settings.datasources) == 2
    assert {d.datasource_id.value for d in settings.datasources} == {
        "threatfox-live",
        "threatfox-replay",
    }
    assert all(d.source_id is SourceId.THREATFOX for d in settings.datasources)


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("protocol", "gopher"),
        ("serialization_format", "xml"),
        ("semantic_format", "urn:ati:datasource:semanticformat:misp"),
        ("source_id", "urn:ati:source:unknown"),
    ],
)
def test_unknown_typed_values_fail_closed_in_profiles(field: str, invalid: str) -> None:
    """Unknown typed dimension values are rejected at the settings boundary."""
    definition = _threatfox_definition("threatfox-live")
    definition[field] = invalid
    with pytest.raises(ValidationError):
        settings_from_config({"datasources": [definition]})


def test_provider_operational_settings_remain_in_place() -> None:
    """PR 27A does not migrate provider-specific operational settings."""
    settings = settings_from_config({})
    assert settings.threatfox_auth_key_secret == "ATI_THREATFOX_AUTH_KEY"
    assert settings.threatfox_max_concurrency == 10
    assert settings.abuseipdb_api_key_secret == "ATI_ABUSEIPDB_API_KEY"
    assert settings.provider_timeout_seconds == 15.0
