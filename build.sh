#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage: ./build.sh [OPTION]

Run an ATI build operation.

Options:
  --check     Run all quality controls and build validation.
  --qa        Format Python code with Black, then run --check.
  -h, --help  Show this help message and exit.

Quality controls are opt-in and do not run when ./build.sh is invoked without
an option. The --check operation includes Python formatting, import ordering,
linting, strict type checking, tests with coverage, and frontend linting,
tests, and production build validation. The --qa operation formats Python
sources with Black before running the same controls.
USAGE
}

case "${1:-}" in
  "") usage; exit 0 ;;
  -h|--help) usage; exit 0 ;;
  --check|--qa) ;;
  *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
esac
if [[ $# -gt 1 ]]; then
  echo "build.sh accepts only one option." >&2
  usage >&2
  exit 2
fi

cd "$(dirname "${BASH_SOURCE[0]}")"

command -v uv >/dev/null || { echo "uv is required; run ./install.sh" >&2; exit 1; }

if [[ $1 == "--qa" ]]; then
  echo '== Python: formatting sources =='
  uv run black src tests
fi

echo '== Python: formatting =='
uv run black --check src tests
uv run isort --check-only src tests
echo '== Python: static checks =='
uv run pylint src tests
uv run mypy src tests
echo '== Python: tests and coverage =='
uv run pytest tests/unit --cov=agentic_threat_investigator --cov-report=term-missing --cov-fail-under=85

if [[ -f frontend/package-lock.json ]]; then
  echo '== Frontend =='
  (cd frontend && npm ci && npm run lint && npm test && npm run build)
fi

echo 'Build and quality checks passed.'
