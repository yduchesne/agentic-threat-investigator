# SPDX-License-Identifier: AGPL-3.0-only
"""PR 34 isolated observability integration-harness package.

Modules here are test infrastructure owned by
``scripts/observability-integration.sh``: the pure convergence state machine,
bounded backend HTTP contact points, the run-scoped verifier, the status CLI,
and the authoritative ``-m observability`` pytest gate. Normal
``./build.sh --intg`` never runs them.
"""
