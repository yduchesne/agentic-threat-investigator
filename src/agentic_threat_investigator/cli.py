# SPDX-License-Identifier: AGPL-3.0-only
"""Narrow CLI entrypoints (PR 23D, extended PR 26B/26B-2/26C).

Explicit, repository-owned entrypoints follow the current bootstrap
convention (plain modules invoked by deployment; no general-purpose CLI
framework):

- ``ati-fake-data-bootstrap``: one-shot idempotent fake batch-data bootstrap;
- ``ati-worker``: the durable investigation job worker loop;
- ``ati-geography-import``: canonical reference geography corpus import;
- ``ati-geography-build``: deterministic ATI Geography Corpus derivation
  from the documented GeoNames/Natural Earth local source artifacts;
- ``ati-geo-resolver``: the bounded asynchronous geographic-resolution
  worker loop (PR 26C).

All load the cached typed settings once and never read environment
variables themselves, and none ever download upstream data. The worker
composes the selected intelligence-source registry through the
operating-mode boundary and the configured real LLM; operating mode never
selects the LLM implementation.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from collections.abc import Callable
from uuid import UUID, uuid4

from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from agentic_threat_investigator.app.assessment_persistence import (
    AssessmentPersistenceService,
)
from agentic_threat_investigator.app.embeddings import EmbeddingClient
from agentic_threat_investigator.app.evidence_analyst.accounting import (
    LlmAccountingService,
)
from agentic_threat_investigator.app.evidence_analyst.analyst import EvidenceAnalyst
from agentic_threat_investigator.app.evidence_analyst.loader import (
    EvidenceAnalystInputLoader,
)
from agentic_threat_investigator.app.geoint.analysis_context import (
    GeointAnalysisContextPolicy,
    GeointAnalystContextLoader,
)
from agentic_threat_investigator.app.geoint.analysis_tools import GeointAnalysisTools
from agentic_threat_investigator.app.geoint.resolution import LocationResolver
from agentic_threat_investigator.app.geoint.worker import (
    GeoResolutionWorker,
    GeoResolutionWorkerConfig,
)
from agentic_threat_investigator.app.investigation_worker import (
    InvestigationJobWorker,
)
from agentic_threat_investigator.app.llm import LlmClient
from agentic_threat_investigator.app.orchestration.research import (
    ResearchAgentResearchExecutor,
)
from agentic_threat_investigator.app.orchestration.runner import (
    LocalInvestigationRunner,
)
from agentic_threat_investigator.app.orchestration.services import (
    EvidenceAnalystAnalysisExecutor,
)
from agentic_threat_investigator.app.query.models import QueryLimits
from agentic_threat_investigator.app.report_writer.writer import ReportWriter
from agentic_threat_investigator.app.secrets import EnvVarSecretsResolver
from agentic_threat_investigator.config import get_settings
from agentic_threat_investigator.config.settings import (
    LlmDriver,
    OperatingMode,
    Settings,
)
from agentic_threat_investigator.domain.geoint import (
    CanonicalLocationResolution,
    GeographicClaim,
)
from agentic_threat_investigator.infrastructure.embeddings import (
    HashingEmbeddingClient,
    build_openai_embedding_client,
)
from agentic_threat_investigator.infrastructure.intelligence_composition import (
    IntelligenceSourceComposition,
    build_intelligence_sources,
)
from agentic_threat_investigator.infrastructure.llm.composition import (
    build_observed_llm_client,
    build_openai_chat_model,
)
from agentic_threat_investigator.infrastructure.llm.deterministic import (
    DeterministicLlmClient,
)
from agentic_threat_investigator.infrastructure.llm.langchain_client import (
    LangChainLlmClient,
)
from agentic_threat_investigator.infrastructure.observability.composition import (
    build_llm_observability,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.canonical_geography_resolver import (
    PostgresCanonicalGeographyResolver,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.composites import (
    register_batch_composites,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.persistence.query.geoint import (
    PostgresGeointQueryService,
)
from agentic_threat_investigator.infrastructure.report_writer_composition import (
    build_report_writer,
)
from agentic_threat_investigator.infrastructure.research_agent_composition import (
    build_research_agent,
)
from agentic_threat_investigator.telemetry.logging import TraceCorrelationFilter

LOGGER = logging.getLogger(__name__)


def _configure_logging() -> None:
    """Configure bounded structured logging with trace/span correlation.

    Installs the PR 29A :class:`TraceCorrelationFilter` on the root handler so
    every structured log record carries ``otel_trace_id`` / ``otel_span_id``
    when a valid OTel span is current. The filter is additive and idempotent:
    existing attributes are never overwritten and log semantics are
    unchanged (``docs/OBSERVABILITY.md``).
    """
    logging.basicConfig(level=logging.INFO)
    for handler in logging.getLogger().handlers:
        if not any(
            isinstance(installed, TraceCorrelationFilter)
            for installed in handler.filters
        ):
            handler.addFilter(TraceCorrelationFilter())


def _make_engine(settings: Settings) -> AsyncEngine:
    """Create the async engine and register the batch composite types."""
    url = settings.database_url.replace(
        "postgresql+psycopg://", "postgresql+psycopg_async://", 1
    )
    engine = create_async_engine(
        url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
    )

    @sqlalchemy_event.listens_for(engine.sync_engine, "connect")
    def _register_composites(dbapi_connection: object, _record: object) -> None:
        """Register custom types before a pooled connection is used."""
        run_async = getattr(dbapi_connection, "run_async", None)
        if run_async is not None:
            run_async(register_batch_composites)

    return engine


def _session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create the session factory for the process engine."""
    return async_sessionmaker(engine, expire_on_commit=False)


def _uow_factory(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> Callable[[], PostgresUnitOfWork]:
    """Create the short-transaction UnitOfWork factory for the process."""
    return lambda: PostgresUnitOfWork(
        session_factory, batch_size=settings.db_batch_size
    )


def _compose_llm(settings: Settings) -> LlmClient:
    """Compose the configured LLM client for the worker process.

    ``ATI_LLM_DRIVER=deterministic`` selects the repository-owned offline
    scripted boundary (PR 24B offline real-stack browser tests); the default
    ``openai`` driver resolves the API key through the secret-reference
    bootstrap contract and builds the real chat model. Operating mode never
    selects the LLM implementation. PR 29B wraps the concrete delegate with
    the single ATI-owned observing client bound to the selected
    LLM-observability backend, so every agent/report model attempt is
    observable without content capture.
    """
    resolver = EnvVarSecretsResolver()
    if settings.llm_driver is LlmDriver.DETERMINISTIC:
        delegate: LlmClient = DeterministicLlmClient()
    else:
        chat_model = build_openai_chat_model(settings, resolver)
        delegate = LangChainLlmClient(chat_model)
    observability = build_llm_observability(settings, resolver)
    return build_observed_llm_client(
        delegate=delegate, observability=observability, settings=settings
    )


def _compose_embedding(settings: Settings) -> EmbeddingClient:
    """Compose the configured embedding client (deterministic by default)."""
    embedding_settings = settings.embedding
    if embedding_settings.provider == "hashing":
        return HashingEmbeddingClient(embedding_settings.dimension)
    if embedding_settings.provider != "openai":
        raise ValueError("unsupported worker embedding provider")
    api_key = EnvVarSecretsResolver().require(embedding_settings.api_key_secret)
    return build_openai_embedding_client(
        model=embedding_settings.model,
        model_version=embedding_settings.model_version,
        dimension=embedding_settings.dimension,
        api_key=api_key,
        timeout_seconds=embedding_settings.timeout_seconds,
    )


def _compose_runner(
    *,
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
    uow_factory: Callable[[], PostgresUnitOfWork],
    sources: IntelligenceSourceComposition,
    llm: LlmClient,
) -> LocalInvestigationRunner:
    """Compose the production InvestigationRunner for the worker process.

    The provider registry comes from the operating-mode intelligence-source
    composition; the LLM is the injected configured runtime implementation in
    every driver mode (automated tests inject ``FakeLlmClient``
    independently of ``worker_main``). The recursion bound mirrors the
    measured production trajectory (40) at normal runtime; the deterministic
    offline driver uses the generous bound measured by the canonical
    multi-hop fake-world slices (120), since the optional deterministic
    boundary is only ever composed for test/demo stacks.
    """
    recursion_limit = 120 if settings.llm_driver is LlmDriver.DETERMINISTIC else 40
    geoint_context_loader = _compose_geoint_context_loader(settings, session_factory)
    analyst = EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(
            uow_factory,
            max_evidence_items=settings.llm_max_evidence_items,
            max_relationship_observations=settings.llm_max_relationship_observations,
            max_normalized_facts_bytes=settings.llm_max_normalized_facts_bytes,
            max_input_bytes=settings.llm_max_input_bytes,
            geoint_context_loader=geoint_context_loader,
        ),
        llm_client=llm,
        assessment_persistence=AssessmentPersistenceService(
            uow_factory, batch_size=settings.db_batch_size
        ),
        llm_accounting=LlmAccountingService(uow_factory),
        max_structured_output_attempts=settings.llm_max_structured_output_attempts,
    )
    research_agent = build_research_agent(
        uow_factory=uow_factory,
        session_factory=session_factory,
        embedding_client=_compose_embedding(settings),
        llm_client=llm,
        max_structured_output_attempts=settings.llm_max_structured_output_attempts,
    )
    return LocalInvestigationRunner(
        uow_factory=uow_factory,
        provider_registry=sources.provider_registry,
        analysis_executor_factory=lambda bound: EvidenceAnalystAnalysisExecutor(
            analyst, bound_investigation_id=bound
        ),
        research_executor_factory=lambda bound: ResearchAgentResearchExecutor(
            research_agent, bound_investigation_id=bound
        ),
        recursion_limit=recursion_limit,
    )


def _compose_geoint_context_loader(
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
) -> GeointAnalystContextLoader:
    """Compose the bounded GEOINT context loader for the worker analyst.

    Each analysis invocation opens one short-lived read session through the
    existing per-request session factory, runs the deterministic context
    policy over the real PR 26D ``PostgresGeointQueryService``, and closes
    the session before any LLM accounting or model I/O. No second engine,
    session factory, or GEOINT repository is created.
    """
    limits = QueryLimits(
        default_page_size=settings.query_default_page_size,
        max_page_size=settings.query_max_page_size,
    )

    def tools_factory() -> GeointAnalysisTools:
        """Build one bounded tools facade over a fresh read session."""
        session = session_factory()
        service = PostgresGeointQueryService(
            session,
            limits,
            summary_top_locations=settings.api_max_geoint_summary_top_locations,
        )

        async def close() -> None:
            """Close the short-lived read session owned by this invocation."""
            await session.close()

        return GeointAnalysisTools(
            service,
            max_observations_per_entity=(
                settings.analyst_geoint_max_observations_per_entity
            ),
            on_close=close,
        )

    return GeointAnalystContextLoader(
        tools_factory=tools_factory,
        policy=GeointAnalysisContextPolicy(
            max_entities=settings.analyst_geoint_max_entities,
            max_observations_per_entity=(
                settings.analyst_geoint_max_observations_per_entity
            ),
            max_total_observations=settings.analyst_geoint_max_total_observations,
            max_context_bytes=settings.analyst_geoint_max_context_bytes,
        ),
    )


def geography_import_main(argv: list[str] | None = None) -> int:
    """Import canonical reference geography from local corpus artifacts.

    Reads the documented ATI Geography Corpus NDJSON format from the supplied
    files/directories, validates the complete batch, and persists it through
    the canonical reference ingestion service in one transaction. Reference
    data is loaded separately from schema migration: ``alembic upgrade``
    never downloads or imports reference geography.
    """
    from pathlib import Path

    from agentic_threat_investigator.app.geoint.reference_ingestion import (
        ReferenceIngestionService,
    )
    from agentic_threat_investigator.infrastructure.sources.geography import (
        JsonlGeographyCorpus,
        ReferenceCorpusError,
    )

    parser = argparse.ArgumentParser(prog="ati-geography-import")
    parser.add_argument(
        "sources",
        nargs="+",
        help="reference corpus artifacts or directories (ATI Geography Corpus NDJSON)",
    )
    args = parser.parse_args(argv)
    _configure_logging()
    settings = get_settings()

    paths: list[Path] = []
    for source in args.sources:
        path = Path(source)
        if path.is_dir():
            paths.extend(sorted(path.glob("*.jsonl")))
        else:
            paths.append(path)
    if not paths:
        LOGGER.error("geography import refused: no corpus artifacts found")
        return 2
    try:
        records = JsonlGeographyCorpus().read_paths(paths)
    except ReferenceCorpusError:
        LOGGER.exception("reference corpus parse failed")
        return 1
    if not records:
        LOGGER.error("geography import refused: corpus is empty")
        return 2

    engine = _make_engine(settings)
    factory = _session_factory(engine)
    uow_factory = _uow_factory(factory, settings)

    async def run() -> int:
        try:
            stats = await ReferenceIngestionService(uow_factory).ingest(records)
        except Exception:
            LOGGER.exception(
                "reference import failed; the batch transaction rolled back "
                "and no partial hierarchy was committed"
            )
            return 1
        finally:
            await engine.dispose()
        LOGGER.info(
            "reference import complete created=%d enriched=%d unchanged=%d "
            "conflicts=%d rejected=%d",
            stats.created,
            stats.enriched,
            stats.unchanged,
            stats.conflicts,
            stats.rejected,
        )
        return 0

    return asyncio.run(run())


def geography_build_main(argv: list[str] | None = None) -> int:
    """Derive the ATI Geography Corpus from supported upstream source files.

    Parses the documented supported GeoNames artifacts (``countryInfo.txt``,
    ``admin1CodesASCII.txt``, and a supported cities file such as
    ``cities1000.txt``) and Natural Earth GeoJSON collections (10m admin-0
    countries and admin-1 states/provinces) into the deterministic ATI
    Geography Corpus NDJSON consumed by ``ati-geography-import``. Only
    local operator-supplied files are ever read; the command never
    downloads upstream data. ``--validate-only`` parses and validates the
    complete build without writing an artifact.
    """
    from pathlib import Path

    from agentic_threat_investigator.app.persistence.repositories import (
        InvalidReferenceGeometryError,
    )
    from agentic_threat_investigator.infrastructure.geoint.geography_corpus_builder import (
        CorpusBuildError,
        GeographyCorpusBuilder,
        serialize_corpus,
    )
    from agentic_threat_investigator.infrastructure.geoint.geonames import (
        GeoNamesReferenceSource,
        GeonamesSourceError,
    )
    from agentic_threat_investigator.infrastructure.geoint.natural_earth import (
        NaturalEarthReferenceSource,
        NaturalEarthSourceError,
    )

    parser = argparse.ArgumentParser(prog="ati-geography-build")
    parser.add_argument(
        "--geonames-country-info",
        type=Path,
        required=True,
        help="GeoNames countryInfo.txt artifact",
    )
    parser.add_argument(
        "--geonames-admin1",
        type=Path,
        required=True,
        help="GeoNames admin1CodesASCII.txt artifact",
    )
    parser.add_argument(
        "--geonames-cities",
        type=Path,
        required=True,
        help="supported GeoNames cities file (cities1000.txt layout)",
    )
    parser.add_argument(
        "--natural-earth-countries",
        type=Path,
        help="Natural Earth 10m admin-0 countries GeoJSON (optional)",
    )
    parser.add_argument(
        "--natural-earth-admin1",
        type=Path,
        help="Natural Earth 10m admin-1 states/provinces GeoJSON (optional)",
    )
    parser.add_argument(
        "--output", type=Path, help="write the corpus NDJSON artifact here"
    )
    parser.add_argument(
        "--min-population",
        type=int,
        help="drop cities below this population (optional)",
    )
    parser.add_argument(
        "--countries",
        nargs="+",
        help="build only these two-letter country codes (optional)",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="parse and validate without writing an artifact",
    )
    args = parser.parse_args(argv)
    _configure_logging()

    if args.validate_only and args.output is not None:
        LOGGER.error(
            "geography build refused: --validate-only and --output are "
            "mutually exclusive"
        )
        return 2
    if not args.validate_only and args.output is None:
        LOGGER.error(
            "geography build refused: --output is required unless "
            "--validate-only is set"
        )
        return 2
    if args.min_population is not None and args.min_population < 0:
        LOGGER.error("geography build refused: --min-population must not be negative")
        return 2
    country_codes: frozenset[str] = frozenset()
    if args.countries:
        normalized_codes = [code.strip().upper() for code in args.countries]
        if any(len(code) != 2 or not code.isalpha() for code in normalized_codes):
            LOGGER.error(
                "geography build refused: --countries values must be "
                "two-letter country codes"
            )
            return 2
        country_codes = frozenset(normalized_codes)

    try:
        geonames = GeoNamesReferenceSource()
        countries = geonames.parse_countries(args.geonames_country_info)
        admin1 = geonames.parse_admin1(args.geonames_admin1)
        cities = geonames.parse_cities(args.geonames_cities)
        natural_earth = NaturalEarthReferenceSource()
        ne_countries = (
            natural_earth.parse_countries(args.natural_earth_countries)
            if args.natural_earth_countries
            else ()
        )
        ne_admin1 = (
            natural_earth.parse_admin1(args.natural_earth_admin1)
            if args.natural_earth_admin1
            else ()
        )
        result = GeographyCorpusBuilder().build(
            countries=countries,
            admin1=admin1,
            cities=cities,
            natural_earth_countries=ne_countries,
            natural_earth_admin1=ne_admin1,
            min_population=args.min_population,
            country_filter=country_codes,
        )
    except (
        GeonamesSourceError,
        NaturalEarthSourceError,
        CorpusBuildError,
        InvalidReferenceGeometryError,
    ) as error:
        LOGGER.error("geography corpus build failed: %s", error)
        return 1

    if args.output is not None:
        try:
            args.output.write_text(serialize_corpus(result.records), encoding="utf-8")
        except OSError as error:
            LOGGER.error("geography corpus write failed: %s", error)
            return 1

    report = result.report
    LOGGER.info(
        "geography corpus build complete countries=%d administrative_areas=%d "
        "cities=%d polygon_geometries=%d records_without_geometry=%d "
        "unmatched=%d rejected_cities=%d ambiguous=%d",
        report.countries,
        report.administrative_areas,
        report.cities,
        report.polygon_geometries,
        report.records_without_geometry,
        len(report.unmatched),
        len(report.rejected_cities),
        len(report.ambiguous),
    )
    for entry in report.unmatched:
        LOGGER.warning(
            "geography corpus unmatched object source=%s kind=%s identifier=%s "
            "reason=%s",
            entry.source,
            entry.kind,
            entry.identifier,
            entry.reason,
        )
    for rejection in report.rejected_cities:
        LOGGER.warning(
            "geography corpus rejected city name=%s country=%s admin1=%s reason=%s",
            rejection.name,
            rejection.country_code,
            rejection.admin1_code,
            rejection.reason,
        )
    for ambiguity in report.ambiguous:
        LOGGER.warning(
            "geography corpus ambiguous match kind=%s identifier=%s reason=%s",
            ambiguity.kind,
            ambiguity.identifier,
            ambiguity.reason,
        )
    if args.validate_only:
        LOGGER.info("geography corpus validation passed: no artifact written")
    return 0


def fake_data_bootstrap_main(argv: list[str] | None = None) -> int:
    """Run the one-shot fake-data bootstrap and exit with its status code."""
    parser = argparse.ArgumentParser(prog="ati-fake-data-bootstrap")
    parser.parse_args(argv)
    _configure_logging()
    settings = get_settings()
    _log_operating_mode(settings)
    if settings.operating_mode is not OperatingMode.FAKE:
        LOGGER.error(
            "fake-data bootstrap refused: ATI_OPERATING_MODE must be fake (got %s)",
            settings.operating_mode.value,
        )
        return 2

    from agentic_threat_investigator.infrastructure.bootstrap import (
        FakeDataBootstrap,
    )

    engine = _make_engine(settings)
    factory = _session_factory(engine)
    uow_factory = _uow_factory(factory, settings)

    async def run() -> int:
        try:
            summary = await FakeDataBootstrap(
                settings=settings, uow_factory=uow_factory
            ).run()
        except Exception:
            LOGGER.exception("fake-data bootstrap failed")
            return 1
        finally:
            await engine.dispose()
        for fixture in summary.fixtures:
            LOGGER.info(
                "fake-data bootstrap fixture source=%s inserted=%d updated=%d "
                "unchanged=%d complete=%s documents_indexed=%d",
                fixture.source_id,
                fixture.inserted,
                fixture.updated,
                fixture.unchanged,
                fixture.complete,
                fixture.documents_indexed,
            )
        return 0

    return asyncio.run(run())


def worker_main(argv: list[str] | None = None) -> int:
    """Run the durable investigation worker loop until interrupted."""
    parser = argparse.ArgumentParser(prog="ati-worker")
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=1.0,
        help="sleep between empty claim rounds (default 1.0)",
    )
    args = parser.parse_args(argv)
    _configure_logging()
    settings = get_settings()
    _log_operating_mode(settings)
    engine = _make_engine(settings)
    factory = _session_factory(engine)
    uow_factory = _uow_factory(factory, settings)

    async def run() -> int:
        try:
            sources = await build_intelligence_sources(
                settings, uow_factory=uow_factory
            )
            llm = _compose_llm(settings)
            runner = _compose_runner(
                settings=settings,
                session_factory=factory,
                uow_factory=uow_factory,
                sources=sources,
                llm=llm,
            )
            report_writer = build_report_writer(
                uow_factory=uow_factory,
                llm_client=llm,
                batch_size=settings.db_batch_size,
                max_findings=settings.report_writer_max_findings,
                max_evidence=settings.report_writer_max_evidence,
                max_relationship_observations=(
                    settings.report_writer_max_relationship_observations
                ),
                max_research_results=settings.report_writer_max_research_results,
                max_research_claims=settings.report_writer_max_research_claims,
                max_input_bytes=settings.report_writer_max_input_bytes,
                max_structured_output_attempts=settings.llm_max_structured_output_attempts,
            )
            worker = InvestigationJobWorker(uow_factory=uow_factory, runner=runner)
            while True:
                executed = await worker.claim_and_run_once()
                if executed is None:
                    await asyncio.sleep(max(0.0, args.poll_seconds))
                    continue
                await _write_missing_current_report(
                    executed, uow_factory, report_writer
                )
        except KeyboardInterrupt:
            LOGGER.info("worker interrupted")
            return 0
        finally:
            await engine.dispose()
        return 0

    return asyncio.run(run())


class _SessionBoundLocationResolver(LocationResolver):
    """Production :class:`LocationResolver` with one short read session per call.

    Each resolve opens a fresh SQLAlchemy session (the canonical geography
    resolver's own bounded read boundary) and closes it on return, so the
    worker never holds a work transaction or row lock while resolving.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        """Bind the read-session factory."""
        self._session_factory = session_factory

    async def resolve(self, claim: GeographicClaim) -> CanonicalLocationResolution:
        """Resolve one bounded claim through the PR 26B canonical resolver."""
        async with self._session_factory() as session:
            return await PostgresCanonicalGeographyResolver(session).resolve(claim)


def _compose_geo_worker(
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
    uow_factory: Callable[[], PostgresUnitOfWork],
) -> GeoResolutionWorker:
    """Compose the production Geo Resolution worker (PR 26C)."""
    worker_id = settings.geo_resolver_worker_id or (
        f"geo-resolver-{os.getpid()}-{uuid4().hex[:8]}"
    )
    config = GeoResolutionWorkerConfig(
        enabled=settings.geo_resolver_enabled,
        worker_id=worker_id,
        batch_size=settings.geo_resolver_batch_size,
        lease_seconds=settings.geo_resolver_lease_seconds,
        poll_interval_seconds=settings.geo_resolver_poll_interval_seconds,
        max_attempts=settings.geo_resolver_max_attempts,
        retry_base_seconds=settings.geo_resolver_retry_base_seconds,
        retry_max_seconds=settings.geo_resolver_retry_max_seconds,
    )
    return GeoResolutionWorker(
        uow_factory=uow_factory,
        resolver=_SessionBoundLocationResolver(session_factory),
        config=config,
    )


def geo_resolver_main(argv: list[str] | None = None) -> int:
    """Run the bounded async geographic-resolution worker loop (PR 26C).

    ``--once`` runs a single claim/resolve/complete iteration and exits,
    which tests exercise instead of the endless daemon. The durable loop
    claims bounded work in short committed transactions, resolves outside
    any database transaction, persists outcomes through the versioned SQL
    API v0024, and sleeps the configured poll interval when no work is due.
    Cancellation (``KeyboardInterrupt``/``CancelledError``) exits cleanly:
    committed leases recover by expiry.
    """
    parser = argparse.ArgumentParser(prog="ati-geo-resolver")
    parser.add_argument(
        "--once",
        action="store_true",
        help="run a single claim/resolve/complete iteration and exit",
    )
    args = parser.parse_args(argv)
    _configure_logging()
    settings = get_settings()
    _log_operating_mode(settings)
    if not settings.geo_resolver_enabled:
        LOGGER.info("geo resolver disabled by configuration; exiting")
        return 0
    engine = _make_engine(settings)
    factory = _session_factory(engine)
    uow_factory = _uow_factory(factory, settings)
    worker = _compose_geo_worker(settings, factory, uow_factory)

    async def run() -> int:
        try:
            while True:
                processed = await worker.run_once()
                if processed == 0:
                    if args.once:
                        return 0
                    await asyncio.sleep(
                        max(0.0, settings.geo_resolver_poll_interval_seconds)
                    )
        except KeyboardInterrupt:
            LOGGER.info("geo resolver interrupted")
            return 0
        finally:
            await engine.dispose()
        return 0

    return asyncio.run(run())


async def _write_missing_current_report(
    investigation_id: UUID,
    uow_factory: Callable[[], PostgresUnitOfWork],
    report_writer: ReportWriter,
) -> None:
    """Write the current Report for one executed terminal Investigation.

    PR 23B deliberately keeps Report generation out of the coordinator graph;
    the worker uploads the persisted Report after a terminal Investigation
    that owns a current Assessment but no current Report. Report failure
    (for example an exhausted LLM budget) never flips the already-terminal
    Investigation; the bounded error is logged and the legitimate
    Assessment-only state remains visible to analysts.
    """
    from agentic_threat_investigator.app.investigation_worker import (
        _bounded_error_code,
    )
    from agentic_threat_investigator.domain.investigation import (
        is_terminal_status,
    )

    async with uow_factory() as uow:
        state = await uow.investigations.get_by_id(investigation_id)
    if state is None or not is_terminal_status(state.status):
        return
    if state.assessment_id is None or state.report_id is not None:
        return
    LOGGER.info("worker writing current report investigation_id=%s", investigation_id)
    try:
        await report_writer.write(investigation_id)
    except BaseException as error:  # noqa: BLE001 - bounded worker-side marker; the terminal Investigation is never flipped
        LOGGER.warning(
            "worker report generation failed investigation_id=%s error_code=%s",
            investigation_id,
            _bounded_error_code(type(error).__name__),
        )


def _log_operating_mode(settings: Settings) -> None:
    """Emit the safe startup observability event (PR 23D Step 8).

    The event exposes the selected operating mode and the intelligence-source
    mode label only; it never logs resolved secrets or configuration values.
    """
    LOGGER.info(
        "operating_mode=%s intelligence_source_mode=%s",
        settings.operating_mode.value,
        settings.operating_mode.value,
    )
    if settings.operating_mode is OperatingMode.FAKE:
        LOGGER.info(
            "ATI operating mode: FAKE; external threat-intelligence sources: "
            "deterministic local fakes; LLM: configured runtime implementation "
            "(not selected by operating mode)"
        )
