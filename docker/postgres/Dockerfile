# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
# Project-owned PostgreSQL 18 runtime containing BOTH pgvector and PostGIS.
#
# The pgvector image is built on the official postgres:18-bookworm image,
# which already configures the PostgreSQL Apt Repository (PGDG) with the
# signed `/etc/apt/sources.list.d/pgdg.list` source. Installing
# `postgresql-18-postgis-3` from that same PGDG repository therefore adds the
# matching PostgreSQL 18 PostGIS package (SQL scripts under
# /usr/share/postgresql/18/extension) without re-adding repository keys.
#
# Neither the pgvector extension nor the retained `vector` column is touched;
# the image only adds the PostGIS capability on top of the existing baseline.
FROM docker.io/pgvector/pgvector:0.8.1-pg18

RUN set -ex; \
    apt-get update; \
    apt-get install -y --no-install-recommends postgresql-18-postgis-3; \
    rm -rf /var/lib/apt/lists/*

# Keep the official entrypoint and default CMD; only the extension set
# differs from the pgvector baseline.