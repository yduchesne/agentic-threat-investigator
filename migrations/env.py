# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Configure Alembic migration execution for the ATI database."""

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

config = context.config
url = os.environ.get("DATABASE_URL")
if url:
    config.set_main_option(
        "sqlalchemy.url", url.replace("%", "%%").replace("+async", "")
    )


def run_migrations_offline() -> None:
    """Run migrations without creating a database connection."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        literal_binds=True,
        include_schemas=True,
        version_table_schema="ati",
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations using a connection created from Alembic settings."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        # The schema and search path must be prepared before Alembic starts, and
        # Alembic must then begin its own transaction: if a transaction is still
        # open when Alembic runs, it joins the existing one without owning it and
        # the entire upgrade is rolled back when the connection is released.
        connection.exec_driver_sql("CREATE SCHEMA IF NOT EXISTS ati")
        connection.exec_driver_sql("SET search_path TO ati, public")
        connection.commit()
        context.configure(
            connection=connection, include_schemas=True, version_table_schema="ati"
        )
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
