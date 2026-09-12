# SPDX-License-Identifier: AGPL-3.0-only
"""PostgreSQL implementations of the PR 23A application query contracts.

Each service executes one bounded keyset query over static predicates and
returns validated domain/read models only — never raw SQLAlchemy rows or
unvalidated dictionaries.
"""
