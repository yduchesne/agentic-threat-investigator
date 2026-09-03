# Agentic Threat Investigator

ATI is an open-source threat-investigation analyst workbench, licensed under
[AGPL-3.0-only](LICENSE). If you run a modified ATI service for users over a
network, AGPLv3 requires offering those users the corresponding source; see the
full license for details.

## Bootstrap

On a supported Linux distribution, run:

```bash
./install.sh
```

This installs missing development prerequisites, `uv`, Python dependencies,
frontend dependencies, and the pre-commit hook. Run the deterministic quality
suite (formatting check, Pylint, strict Mypy, unit tests, and frontend lint)
with:

```bash
./build.sh --qa
```

To format Python sources with Black:

```bash
./build.sh --fmt
```

Unit tests are kept under `tests/unit/` and integration tests under
`tests/integration/`. The integration tests provision an isolated PostgreSQL
container via Podman and therefore require `podman` and `podman-compose`
(installed by `./install.sh`); after the integration tests succeed, the
frontend production bundle is built (`tsc` type-check plus `vite build`).
Other build operations include `--chk` (quality checks and unit tests without
the formatting check), `--unit` (unit tests only), and `--intg` (integration
tests plus frontend tests). To run only the PostgreSQL integration suite and
frontend build by itself:

```bash
./integration-test.sh
```

The local runtime is Podman Compose-based. Configure `ATI_DATA_DIR` and the
other values in `.env.example` in a local `.env` before using Compose.

ATI is early-stage software; domain, persistence, provider, and agent features
are delivered incrementally according to `docs/PR_PLAN.md`.
