# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""LangSmith evaluation adapter (PR 30B).

Provides a deterministic, fail-closed projection of ATI-owned PR 30
datasets and evaluation results onto LangSmith:

- ``mapping`` — deterministic dataset names, stable example identity,
  projection metadata, canonical JSON serialization and semantic digests;
- ``client`` — a narrow injectable client boundary plus the real SDK
  wrapper (bounded errors, no credential logging, cancellation preserved);
- ``datasets`` — idempotent ``sync`` and read-only ``verify``;
- ``results`` — categorical PASS/FAIL/ERROR feedback publication and
  experiment metadata building.

LangSmith is a projection/visualization backend, never the source of ATI
evaluation truth; no common evaluation model is modified to fit it.
"""

from agentic_threat_investigator.evaluation.backends.langsmith.client import (
    LangSmithBackendError,
    LangSmithEvaluationClient,
    LangSmithSdkEvaluationClient,
)
from agentic_threat_investigator.evaluation.backends.langsmith.datasets import (
    LangSmithSyncError,
    synchronize_dataset,
    verify_dataset,
)
from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
    DEFAULT_NAMESPACE,
    PROJECTION_SCHEMA_VERSION,
    LangSmithProjectionError,
    canonical_json,
    project_dataset_name,
    semantic_digest,
)
from agentic_threat_investigator.evaluation.backends.langsmith.models import (
    LangSmithDatasetRef,
    LangSmithEvaluationPublication,
    LangSmithExampleMetadata,
    LangSmithExampleProjection,
    LangSmithExampleRef,
    LangSmithPublicationFeedback,
    LangSmithSyncReceipt,
    LangSmithVerifyReport,
)
from agentic_threat_investigator.evaluation.backends.langsmith.results import (
    build_experiment_metadata,
    build_publication,
    categorical_status,
)

__all__ = [
    "DEFAULT_NAMESPACE",
    "LangSmithBackendError",
    "LangSmithDatasetRef",
    "LangSmithEvaluationClient",
    "LangSmithEvaluationPublication",
    "LangSmithExampleMetadata",
    "LangSmithExampleProjection",
    "LangSmithExampleRef",
    "LangSmithProjectionError",
    "LangSmithPublicationFeedback",
    "LangSmithSdkEvaluationClient",
    "LangSmithSyncError",
    "LangSmithSyncReceipt",
    "LangSmithVerifyReport",
    "PROJECTION_SCHEMA_VERSION",
    "build_experiment_metadata",
    "build_publication",
    "canonical_json",
    "categorical_status",
    "project_dataset_name",
    "semantic_digest",
    "synchronize_dataset",
    "verify_dataset",
]
