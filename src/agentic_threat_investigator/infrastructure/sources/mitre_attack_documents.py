# SPDX-License-Identifier: AGPL-3.0-only
"""Narrative document builder for normalized MITRE ATT&CK records."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from agentic_threat_investigator.app.document_indexing import (
    CHUNKING_VERSION,
    DocumentBuilder,
)
from agentic_threat_investigator.domain.documents import Document
from agentic_threat_investigator.domain.identifiers import SourceId
from agentic_threat_investigator.domain.immutable_json import thaw_json
from agentic_threat_investigator.domain.source import SourceRecord


class MitreAttackDocumentBuilder(DocumentBuilder):
    """Render bounded normalized ATT&CK fields, never raw STIX JSON."""

    source_id = SourceId.MITRE_ATTACK.value
    document_record_types = frozenset(
        {"attack_technique", "attack_software", "attack_group"}
    )

    @staticmethod
    def _render_value(value: Any) -> str:
        """Render normalized JSON values deterministically."""
        if isinstance(value, (Mapping, list, tuple, bool)):
            return json.dumps(
                thaw_json(value),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        return str(value)

    @staticmethod
    def _section(name: str, lines: list[str]) -> str | None:
        """Render a non-empty structural section."""
        if not lines:
            return None
        return f"## {name}\n" + "\n".join(lines)

    def _sections(self, record: SourceRecord) -> list[str]:
        """Build ordered sections from the MITRE normalization vocabulary."""
        payload = record.canonical_payload
        name = payload.get("name")
        overview = [f"type: {record.record_type}"]
        if isinstance(name, str) and name.strip():
            overview.insert(0, f"name: {name}")

        details: list[str] = []
        description = payload.get("description")
        if isinstance(description, str) and description.strip():
            normalized_description = description.strip()
            overview.append("description: " + normalized_description.partition(". ")[0])
            details.append(normalized_description)

        detection: list[str] = []
        guidance = payload.get("detection") or payload.get("detection_guidance")
        if isinstance(guidance, str) and guidance.strip():
            detection.append(guidance)

        context = [
            f"{key}: {self._render_value(payload[key])}"
            for key in (
                "platforms",
                "tactics",
                "aliases",
                "software_kind",
                "is_subtechnique",
                "revoked",
                "deprecated",
            )
            if key in payload and payload[key] not in (None, "", (), [])
        ]

        references: list[str] = []
        source_url = payload.get("url")
        if isinstance(source_url, str) and source_url.strip():
            references.append(source_url)
        external_references = payload.get("external_references")
        if isinstance(external_references, (list, tuple)):
            references.extend(
                self._render_value(value) for value in external_references
            )

        rendered = [
            self._section("Overview", overview),
            self._section("Details", details),
            self._section("Detection", detection),
            self._section("Context", context),
            self._section("References", references),
        ]
        return [section for section in rendered if section is not None]

    def build(self, record: SourceRecord) -> Document:
        """Render one supported normalized record into stable narrative sections."""
        if record.source_id != self.source_id:
            raise ValueError("MITRE document builder received a different source")
        if record.record_type not in self.document_record_types:
            raise ValueError(
                "MITRE document builder received an unsupported record type"
            )

        sections = self._sections(record)
        content = "\n\n".join(sections)
        if not content.strip():
            raise ValueError("MITRE ATT&CK record produced empty document")

        payload = record.canonical_payload
        title_value = payload.get("name")
        title = title_value if isinstance(title_value, str) else None
        url_value = payload.get("url")
        source_url = url_value if isinstance(url_value, str) else None
        metadata: dict[str, Any] = {"record_type": record.record_type}
        attack_id = payload.get("attack_id")
        if isinstance(attack_id, str) and attack_id:
            metadata["attack_id"] = attack_id

        return Document(
            source_id=record.source_id,
            source_record_id=record.source_record_id,
            document_type=record.record_type,
            title=title,
            source_url=source_url,
            published_at=record.published_at,
            retrieved_at=record.retrieved_at,
            content=content,
            normalization_version=record.normalization_version,
            chunking_version=CHUNKING_VERSION,
            metadata=metadata,
        )
