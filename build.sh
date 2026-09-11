#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage: ./build.sh [OPTION]

Run an ATI build operation.

Options:
  --chk     Run the static quality checks and unit tests: Ruff lint, strict
            Mypy, and the unit test suites (Python and frontend).
  --fmt     Apply Ruff lint-safe fixes (including import sorting) and then
            format Python sources with the Ruff formatter.
  --qa      Check Ruff formatting, then run the same operations as --chk,
            plus the frontend lint.
  --unit    Run the unit test suites only (Python and frontend).
  --intg    Run the PostgreSQL integration tests (via ./integration-test.sh)
            and the frontend unit tests.
  --sec     Run the Python security scans: Bandit static analysis, Semgrep
            static analysis, Safety and pip-audit dependency vulnerability
            audits.
  -h, --help  Show this help message and exit.
USAGE
}

run_python_static_checks() {
  echo '== Python: static checks =='
  uv run ruff check src tests
  uv run mypy src tests
}

run_python_unit_tests() {
  uv run pytest tests/unit --cov=agentic_threat_investigator --cov-report=term-missing --cov-fail-under=85
}

ensure_frontend_deps() {
  command -v npm >/dev/null || { echo 'npm is required for frontend checks; run ./install.sh' >&2; exit 1; }
  if [[ ! -d frontend/node_modules ]]; then (cd frontend && npm ci) >/dev/null; fi
}

run_frontend_unit_tests() {
  ensure_frontend_deps
  (cd frontend && npm test)
}

run_frontend_lint() {
  ensure_frontend_deps
  (cd frontend && npm run lint)
}

run_security_checks() {
  # Security scans are not part of the local --qa gate; they run as a
  # dedicated, parallel CI gate (build.sh --sec) that must pass before a
  # PR can be merged.
  echo '== Security: static analysis (Bandit) =='
  # Scans production code only (src); tests intentionally carry synthetic
  # credentials and asserts. B101 skips are justified in pyproject.toml.
  uv run bandit -q -r src -c pyproject.toml
  echo '== Security: static analysis (Semgrep) =='
  # p/ci rules are fetched from the Semgrep registry (network required).
  uv run semgrep scan --config p/ci --metrics=off --error src
  echo '== Security: dependency vulnerabilities (Safety) =='
  uv run safety check
  echo '== Security: dependency vulnerabilities (pip-audit) =='
  # PYSEC-2026-3740 (nltk, no fixed release on PyPI) is a transitive,
  # test-only dependency of the Safety scanner itself; ATI production code
  # never imports nltk. Re-evaluate when Safety ships a fixed nltk bound.
  uv run pip-audit --ignore-vuln PYSEC-2026-3740
}

run_quality_checks() {
  run_python_static_checks
  echo '== Python: unit tests and coverage =='
  run_python_unit_tests
  echo '== Frontend: unit tests =='
  run_frontend_unit_tests
}

cd "$(dirname "${BASH_SOURCE[0]}")"
command -v uv >/dev/null || { echo 'uv is required; run ./install.sh' >&2; exit 1; }

case "${1:-}" in
  --chk)
    run_quality_checks
    ;;
  --fmt)
    echo '== Python: lint-safe fixes and formatting =='
    uv run ruff check src tests --fix
    uv run ruff format src tests
    ;;
  --qa)
    echo '== Python: formatting check =='
    uv run ruff format --check src tests
    run_quality_checks
    echo '== Frontend: lint =='
    run_frontend_lint
    ;;
  --unit)
    echo '== Python: unit tests and coverage =='
    run_python_unit_tests
    echo '== Frontend: unit tests =='
    run_frontend_unit_tests
    ;;
  --intg)
    echo '== Integration: PostgreSQL via podman =='
    ./integration-test.sh
    echo '== Frontend: unit tests =='
    run_frontend_unit_tests
    ;;
  --sec)
    run_security_checks
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  "")
    echo 'Error: no option provided; exactly one option is required.' >&2
    usage >&2
    exit 2
    ;;
  *)
    echo "Unknown option: $1" >&2
    usage >&2
    exit 2
    ;;
esac

echo 'Build operation completed successfully.'
