# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Repository-owned deterministic GEOINT evaluation baseline (PR 26G).

PR 26G closes the PR 26 series: it evaluates the delivered PR 26A--F
runtime contracts with deterministic fixtures, structured evaluators, real
production paths, and a source-level audit. This package contains the
scenario contracts (:mod:`models`), strict corpus loading
(:mod:`loader`), deterministic fixture materialization (:mod:`materializer`),
an evaluation-only query tracing seam (:mod:`tracing`), and the pure
deterministic evaluator (:mod:`evaluator`).

PR 26G adds evaluation and closure only; it changes no production GEOINT
runtime semantics and absorbs none of PR 27's generic evaluator-platform
scope.
"""

from agentic_threat_investigator.evaluation.geoint.evaluator import (
    GeointDeterministicEvaluator,
)
from agentic_threat_investigator.evaluation.geoint.loader import (
    GeointScenarioLoadError,
    load_geoint_scenarios_directory,
)
from agentic_threat_investigator.evaluation.geoint.materializer import (
    GeointScenarioMaterializer,
)
from agentic_threat_investigator.evaluation.geoint.models import (
    GeointScenario,
    GeointScenarioResolution,
)

__all__ = [
    "GeointDeterministicEvaluator",
    "GeointScenario",
    "GeointScenarioLoadError",
    "GeointScenarioMaterializer",
    "GeointScenarioResolution",
    "load_geoint_scenarios_directory",
]
