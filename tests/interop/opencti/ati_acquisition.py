#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""ATI-side real acquisition driver of the OpenCTI interoperability harness.

Runs the **production** TAXII/STIX/Evidence path against a real OpenCTI
TAXII 2.1 collection, real Redpanda, and real PostgreSQL:

```text
real OpenCTI TAXII 2.1 collection
 -> real ProviderHttpClient (bounded network HTTP)
 -> real Taxii21Datasource (durable checkpoint reader over PostgreSQL)
 -> real parse_stix21_object / Stix21ToEvidenceConverter
 -> CollectionDatasourceEvidenceProducer (post-publication checkpoint commit)
 -> KafkaEvidencePublisher -> real Redpanda
 -> KafkaEvidenceConsumer -> EvidencePersistenceConsumer -> real PostgreSQL
```

Environment:

  DATABASE_URL                       ATI PostgreSQL (guarded test URL)
  ATI_EVIDENCE_KAFKA_BOOTSTRAP       Redpanda broker host:port
  OPENCTI_TAXII_URL                  HTTPS TAXII collection objects URL
  OPENCTI_TAXII_TOKEN                bearer token (authorization only)
  DATASOURCE_ID                      datasource instance id (default opencti-collection)
  RUN_STATE_FILE                     JSON state file the driver updates

No OpenCTI-specific production code exists: this driver only composes
existing production seams. The driver never prints tokens, payloads, or
logs; output is a single bounded JSON state object.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)

from agentic_threat_investigator.app.datasource_evidence_producer import (
    CollectionDatasourceEvidenceProducer,
    DatasourceProducerOutcome,
)
from agentic_threat_investigator.app.evidence_batch_persistence import (
    EvidenceBatchPersistenceService,
)
from agentic_threat_investigator.app.evidence_consumer import (
    EvidencePersistenceConsumer,
)
from agentic_threat_investigator.app.evidence_log import EvidenceConsumerId
from agentic_threat_investigator.app.persistence.repositories import (
    DatasourceCheckpoint,
)
from agentic_threat_investigator.config.settings import Settings
from agentic_threat_investigator.infrastructure.datasources.stix21_evidence import (
    build_stix21_conversion_registry,
)
from agentic_threat_investigator.infrastructure.datasources.taxii21 import (
    TAXII_CHECKPOINT_KIND,
    Taxii21Datasource,
)
from agentic_threat_investigator.infrastructure.kafka.evidence_log import (
    build_kafka_consumer,
    build_kafka_publisher,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.providers.composition import (
    build_taxii_checkpoint_committer,
    resolve_taxii_datasource_definition,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    BoundedLimiter,
    ProviderHttpClient,
    ProviderHttpPolicy,
    RateLimiterSettings,
)


def _require(env: str) -> str:
    value = os.environ.get(env, "")
    if not value:
        raise SystemExit(f"{env} is required")
    return value


def _read_state(state_file: Path) -> dict[str, Any]:
    if state_file.exists():
        loaded = json.loads(state_file.read_text())
        return loaded if isinstance(loaded, dict) else {}
    return {}


def _write_state(state_file: Path, state: dict[str, int | str | bool | None]) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state, indent=2, default=str))


def _make_checkpoint_reader(
    uow_factory: Callable[[], PostgresUnitOfWork], datasource_id: str
) -> Callable[[], Any]:
    """Return the real durable-checkpoint reader over one short committed UoW."""

    async def _read() -> DatasourceCheckpoint | None:
        async with uow_factory() as uow:
            return await uow.datasource_checkpoints.get(
                datasource_id=datasource_id, checkpoint_kind=TAXII_CHECKPOINT_KIND
            )

    return _read


class _RequestCounter:
    """Bounded request-counting hook for the pagination provenance proof."""

    def __init__(self, state: dict[str, Any]) -> None:
        """Bind the counter to the run-state dict it updates."""
        self._state = state
        self._count = 0
        # Preserve per-run counts: the second (incremental) acquisition would
        # otherwise overwrite the first run's pagination proof.
        self._seen_previous = isinstance(state.get("requests_count"), int)
        self._previous = state.get("requests_count") if self._seen_previous else None

    async def on_request(self, request: object) -> None:
        """Increment the bounded request counter (metadata only)."""
        self._count += 1
        if self._seen_previous and self._previous is not None:
            self._state.setdefault("requests_count_first", self._previous)
            self._state["requests_count_second"] = self._count
        self._state["requests_count"] = self._count

    def requests_count(self) -> int:
        """Return the number of TAXII requests issued so far."""
        return self._count


async def _run_consumer_until_drained(
    bootstrap: str, topic: str, uow_factory: Callable[[], PostgresUnitOfWork]
) -> int:
    """Consume published Evidence until one full empty poll, returning the count."""
    consumer = build_kafka_consumer(
        bootstrap_servers=tuple(bootstrap.split(",")),
        topic=topic,
        consumer_id=EvidenceConsumerId("opencti-interop-consumer"),
        client_id="ati-interop-consumer",
        poll_timeout_ms=3000,
    )
    await consumer.start()
    service = EvidenceBatchPersistenceService(uow_factory)
    persistence = EvidencePersistenceConsumer(consumer=consumer, persistence=service)
    persisted = 0
    try:
        for _ in range(200):
            run = await persistence.process_next_batch()
            persisted += run.persisted_count
            if run.polled_count == 0:
                break
    finally:
        await consumer.stop()
    return persisted


def _derive_endpoint(taxii_url: str) -> tuple[str, str]:
    """Split the collection-objects URL into its API root and collection ID."""
    marker = "/collections/"
    if marker not in taxii_url:
        raise SystemExit("OPENCTI_TAXII_URL must contain /collections/")
    api_root, tail = taxii_url.split(marker, 1)
    collection_id = tail.split("/", 1)[0]
    if not api_root or not collection_id:
        raise SystemExit(
            "OPENCTI_TAXII_URL must be <api_root>/collections/<id>/objects/"
        )
    return api_root, collection_id


async def _main() -> int:
    settings = Settings()
    database_url = _require("DATABASE_URL")
    if (
        "ati-test" not in database_url
        and "ati-interop" not in database_url
        and "ati_interop" not in database_url
    ):
        raise SystemExit("refusing interop against a non-isolated database URL")
    bootstrap = _require("ATI_EVIDENCE_KAFKA_BOOTSTRAP")
    taxii_url = _require("OPENCTI_TAXII_URL")
    token = os.environ.get("OPENCTI_TAXII_TOKEN")
    datasource_id = os.environ.get("DATASOURCE_ID", "opencti-collection")
    state_file = Path(_require("RUN_STATE_FILE"))
    state = _read_state(state_file)

    engine = create_async_engine(
        database_url.replace("postgresql+psycopg://", "postgresql+psycopg_async://", 1)
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    def uow_factory() -> PostgresUnitOfWork:
        return PostgresUnitOfWork(session_factory)

    definition = resolve_taxii_datasource_definition(settings)
    if definition is None or definition.datasource_id.value != datasource_id:
        await engine.dispose()
        raise SystemExit(f"no TAXII datasource definition for {datasource_id}")

    publisher = build_kafka_publisher(
        bootstrap_servers=tuple(bootstrap.split(",")),
        topic=settings.evidence_kafka.topic,
        client_id="ati-interop-publisher",
    )
    await publisher.start()
    try:
        import httpx

        counter = _RequestCounter(state)
        counting_client = httpx.AsyncClient(
            timeout=settings.provider_timeout_seconds,
            follow_redirects=False,
            verify=os.environ.get("ATI_OPENCTI_CA_CERT") or True,
            event_hooks={"request": [counter.on_request]},
        )
        http_client = ProviderHttpClient(
            client=counting_client,
            policy=ProviderHttpPolicy(
                timeout_seconds=settings.provider_timeout_seconds,
                max_retries=settings.provider_max_retries,
                base_delay_seconds=settings.provider_retry_base_delay_seconds,
                max_delay_seconds=settings.provider_retry_max_delay_seconds,
                jitter_ratio=settings.provider_retry_jitter_ratio,
                max_response_bytes=settings.provider_max_response_bytes,
            ),
            limiter=BoundedLimiter(
                RateLimiterSettings(
                    max_concurrency=settings.taxii_max_concurrency,
                    requests_per_second=settings.taxii_requests_per_second,
                )
            ),
        )
        api_root, collection_id = _derive_endpoint(taxii_url)
        datasource = Taxii21Datasource(
            http_client,
            api_root_url=api_root,
            collection_id=collection_id,
            bearer_token=token,
            page_size=settings.taxii_page_size,
            max_pages=settings.taxii_max_pages,
            initial_added_after=settings.taxii_initial_added_after or None,
            checkpoint_reader=_make_checkpoint_reader(uow_factory, datasource_id),
            clock=lambda: datetime.now(UTC),
        )
        committer = build_taxii_checkpoint_committer(
            uow_factory, checkpoint_kind=TAXII_CHECKPOINT_KIND
        )
        producer = CollectionDatasourceEvidenceProducer(
            definition=definition,
            acquirer=datasource,
            registry=build_stix21_conversion_registry(),
            publisher=publisher,
            uow_factory=uow_factory,
            progress_committer=committer,
        )
        result = await producer.produce()
        state["execution_id"] = (
            str(result.execution_id) if result.execution_id else None
        )
        state["outcome"] = result.outcome.value
        state["published_count"] = result.published_count
        state["error_code"] = result.error_code
        _write_state(state_file, state)
        if result.outcome is not DatasourceProducerOutcome.COMPLETED:
            return 3
        persisted = await _run_consumer_until_drained(
            bootstrap, settings.evidence_kafka.topic, uow_factory
        )
        state["persisted_count"] = persisted
        state["acquisition_completed"] = True
        _write_state(state_file, state)
        return 0
    finally:
        await publisher.stop()
        await engine.dispose()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
