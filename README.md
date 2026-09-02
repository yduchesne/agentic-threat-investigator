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
and test suite with:

```bash
./build.sh --check
```

To format Python sources with Black before running the same checks:

```bash
./build.sh --qa
```

Unit tests are kept under `tests/unit/` and integration tests under
`tests/integration/`. Run integration tests separately with:

```bash
./integration-test.sh
```

The local runtime is Docker Compose-based. Configure `ATI_DATA_DIR` and the
other values in `.env.example` in a local `.env` before using Compose.

ATI is early-stage software; domain, persistence, provider, and agent features
are delivered incrementally according to `docs/PR_PLAN.md`.
