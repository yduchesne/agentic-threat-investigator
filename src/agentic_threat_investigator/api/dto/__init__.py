# SPDX-License-Identifier: AGPL-3.0-only
"""Public API request/response DTOs.

DTOs are explicit allowlists separate from domain and persistence models;
unknown request fields are rejected and responses are never produced from
unrestricted internal serialization.
"""
