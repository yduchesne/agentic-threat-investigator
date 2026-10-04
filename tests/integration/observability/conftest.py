# SPDX-License-Identifier: AGPL-3.0-only
"""PR 34 observability-harness conftest.

``tests/integration/conftest.py`` (the PostgreSQL repository suite) registers
an ``autouse`` ``reset_application_data`` fixture that requires an isolated
``DATABASE_URL``. The PR 34 harness runs **no** PostgreSQL and must not
instantiate the repository fixtures, so this closer conftest shadows exactly
that one autouse fixture with a no-op. No other parent fixture is referenced
and the observability tests stay deterministic without a database/network
from the developer side.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest_asyncio


@pytest_asyncio.fixture(autouse=True)
async def reset_application_data() -> AsyncIterator[None]:
    """No-op shadow of the PostgreSQL-suite autouse data reset.

    PR 34 proves telemetry *delivery*; there is no application database in
    the harness topology and nothing to reset. Shadowing by name prevents
    the repository suite's ``DATABASE_URL`` requirement from leaking into
    these tests.
    """
    yield
