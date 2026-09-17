# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Format-specific semantic parsing for datasource acquisitions (PR 27C).

Each module in this package interprets one source semantic format into
validated source-native typed objects after transport and serialization
decoding. Semantic modules never construct ATI Evidence, never perform
network/DB/persistence I/O, and never log full source objects.
"""
