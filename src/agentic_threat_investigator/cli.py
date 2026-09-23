# SPDX-License-Identifier: AGPL-3.0-only
"""Narrow CLI entrypoints (PR 23D, extended PR 26B/26B-2/26C/30C).

Explicit, repository-owned entrypoints follow the current bootstrap
convention (plain modules invoked by deployment; no general-purpose CLI
framework):

- ``ati-fake-data-bootstrap``: one-shot idempotent fake batch-data bootstrap;
- ``ati-worker``: the durable investigation job worker loop;
- ``ati-geography-import``: canonical reference geography corpus import;
- ``ati-geography-build``: deterministic ATI Geography Corpus derivation
  from the documented GeoNames/Natural Earth local source artifacts;
- ``ati-geo-resolver``: the bounded asynchronous geographic-resolution
  worker loop (PR 26C);
- ``ati-eval``: the PR 30 evaluation CLI (validate; langsmith sync/verify;
  PR 30C adds run evidence-analyst/v1 [--langsmith]).

All load the cached typed settings once and never read environment
variables themselves, and none ever download upstream data. The worker
composes the selected intelligence-source registry through the
operating-mode boundary and the configured real LLM; operating mode never
selects the LLM implementation. PR 30C reuses the worker's LLM/analyst
composition for the optional real benchmark run.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

if TYPE_CHECKING:
    from agentic_threat_investigator.evaluation.backends.langsmith.client import (
        LangSmithEvaluationClient,
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
from agentic_threat_investigator.evaluation.common import (
    DatasetLoadError,
    EvaluationDatasetId,
    EvaluationExecutionStatus,
    EvaluationRunResult,
    EvaluationTarget,
    EvaluationVerdict,
    render_human_report,
)
from agentic_threat_investigator.evaluation.common.models import ScenarioLike
from agentic_threat_investigator.evaluation.datasets import (
    load_evaluation_dataset,
    validate_dataset_directory,
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
from agentic_threat_investigator.telemetry.setup import (
    ServiceNames,
    configure_telemetry,
    shutdown_telemetry,
)

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


def _compose_evaluation_analyst(
    *,
    settings: Settings,
    session_factory: async_sessionmaker[AsyncSession],
    uow_factory: Callable[[], PostgresUnitOfWork],
    llm: LlmClient,
) -> EvidenceAnalyst:
    """Compose the production Evidence Analyst for a benchmark process.

    Reuses exactly the same loader, persistence seam, accounting, GEOINT
    context loader, and structured-output policy as the worker composition;
    PR 30C never builds a parallel evaluation-only analyst.
    """
    geoint_context_loader = _compose_geoint_context_loader(settings, session_factory)
    return EvidenceAnalyst(
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
    analyst = _compose_evaluation_analyst(
        settings=settings,
        session_factory=session_factory,
        uow_factory=uow_factory,
        llm=llm,
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
    """Run the durable investigation worker loop until interrupted.

    PR 29C wires the process telemetry composition (service identity
    ``ati-worker``) while observability is enabled so the PR 29B
    instrumentation is active in the deployed worker. Providers start before
    any instrumented service executes and are shut down in a ``finally``
    block after the process-owned engine is disposed, so worker outcomes are
    never replaced by telemetry teardown behavior.
    """
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
    configure_telemetry(
        enabled=settings.observability_enabled,
        service_name=ServiceNames.WORKER,
    )
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
            shutdown_telemetry()
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

    PR 29C wires the process telemetry composition (service identity
    ``ati-geo-resolver``) after the configuration gate so an observability-
    disabled or resolver-disabled process never starts a provider pipeline,
    and shuts telemetry down after the process-owned engine is disposed.
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
    configure_telemetry(
        enabled=settings.observability_enabled,
        service_name=ServiceNames.GEO_RESOLVER,
    )
    engine = _make_engine(settings)
    factory = _session_factory(engine)
    uow_factory = _uow_factory(factory, settings)

    async def run() -> int:
        try:
            worker = _compose_geo_worker(settings, factory, uow_factory)
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
            shutdown_telemetry()
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


def _resolve_and_validate(dataset_or_path: str) -> tuple[EvaluationDatasetId, int]:
    """Resolve one dataset-or-path argument and strictly validate it.

    A canonical dataset identity such as ``evidence-analyst/v1`` loads the
    registered corpus; any other argument is treated as a scenario directory
    whose target is inferred from its files. Raises
    :class:`DatasetLoadError`/``ValueError`` on any failure.
    """
    try:
        dataset_id = EvaluationDatasetId.from_canonical(dataset_or_path)
    except ValueError:
        dataset_id = validate_dataset_directory(Path(dataset_or_path))
        return dataset_id, len(load_evaluation_dataset(dataset_id))
    cases = load_evaluation_dataset(dataset_id)
    return dataset_id, len(cases)


def evaluation_main(argv: list[str] | None = None) -> int:
    """Run the PR 30 evaluation CLI (``ati-eval``).

    PR 30A exposes local validation, PR 30B adds explicit LangSmith dataset
    operations, and PR 30C adds the first real-model run:

    .. code-block:: text

        ati-eval validate <dataset-or-path>
        ati-eval langsmith sync|verify <dataset-id> [--namespace NAMESPACE]
        ati-eval run evidence-analyst/v1 [--langsmith] [--namespace NAMESPACE]

    ``validate`` strictly loads a canonical dataset identity (for example
    ``evidence-analyst/v1``) or one scenario directory, enforces the
    scenario-quality and dataset-identity contracts, and exits 0 on success
    or nonzero on failure. The command is fully offline: no LangSmith, no
    LLM, and no network.

    ``langsmith sync`` validates the local dataset first, then creates the
    missing remote mirror (dataset and examples) idempotently and fails
    closed on drift/extras/duplicates; ``langsmith verify`` performs the
    same comparisons read-only. Both require ``LANGSMITH_API_KEY``
    credentials and report a bounded nonzero exit otherwise.

    ``run`` executes the configured real Evidence Analyst benchmark through
    the production analyst path (``evidence-analyst/v1`` only in PR 30C).
    Without ``--langsmith`` no LangSmith client is constructed; with
    ``--langsmith`` the exact remote mirror is verified before any model
    work and the categorical result is published and confirmed as one
    experiment afterwards. The run requires the configured model-provider
    credential (``ATI_OPENAI_API_KEY`` by default) and refuses the
    deterministic driver. Exit semantics: ``0`` COMPLETED/PASS with requested
    publication succeeded; ``1`` COMPLETED/FAIL; ``2``
    ERROR/config/backend/publication failure.
    """
    parser = argparse.ArgumentParser(prog="ati-eval")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser(
        "validate",
        help="strictly validate a canonical dataset or one scenario directory",
    )
    validate_parser.add_argument(
        "dataset_or_path",
        help="canonical dataset identity such as evidence-analyst/v1 or a "
        "scenario directory path",
    )
    langsmith_parser = subparsers.add_parser(
        "langsmith",
        help="explicit LangSmith dataset operations (sync/verify; needs "
        "LANGSMITH_API_KEY credentials)",
    )
    langsmith_subparsers = langsmith_parser.add_subparsers(
        dest="langsmith_operation", required=True
    )
    for operation in ("sync", "verify"):
        operation_parser = langsmith_subparsers.add_parser(
            operation,
            help=(
                "idempotently create the missing remote mirror (sync) or "
                "read-only check (verify); both fail closed on drift"
            ),
        )
        operation_parser.add_argument(
            "dataset_id",
            help="canonical dataset identity such as evidence-analyst/v1",
        )
        operation_parser.add_argument(
            "--namespace",
            default="ati",
            help="optional remote dataset name prefix (default: ati)",
        )
    run_parser = subparsers.add_parser(
        "run",
        help="execute the configured real Evidence Analyst benchmark "
        "(evidence-analyst/v1; needs the configured model-provider key; "
        "--langsmith also needs LANGSMITH_API_KEY)",
    )
    run_parser.add_argument(
        "dataset_id",
        help="canonical dataset identity such as evidence-analyst/v1",
    )
    run_parser.add_argument(
        "--langsmith",
        action="store_true",
        help="verify the exact remote mirror before any model work, then publish "
        "and confirm the categorical experiment",
    )
    run_parser.add_argument(
        "--namespace",
        default="ati",
        help="optional remote dataset/experiment name prefix (default: ati)",
    )
    args = parser.parse_args(argv)
    _configure_logging()
    if args.command == "validate":
        return _evaluation_validate_main(args)
    if args.command == "langsmith":
        return _evaluation_langsmith_main(args)
    if args.command == "run":
        return _evaluation_run_main(args)
    parser.error(f"unknown evaluation command: {args.command}")
    return 2  # pragma: no cover - argparse exits before this line


def _evaluation_validate_main(args: argparse.Namespace) -> int:
    """Run one PR 30A offline validation command and return its exit code."""
    try:
        dataset_id, case_count = _resolve_and_validate(args.dataset_or_path)
    except (ValueError, OSError, DatasetLoadError) as exc:
        LOGGER.error("evaluation validation failed: %s", exc)
        return 1
    LOGGER.info(
        "evaluation validation passed: %s (%d cases)",
        dataset_id.canonical,
        case_count,
    )
    return 0


def _build_langsmith_evaluation_client() -> LangSmithEvaluationClient:
    """Construct the real LangSmith SDK client for explicit evaluation commands.

    Credentials come from the standard ``LANGSMITH_API_KEY`` environment
    contract; missing credentials surface as a bounded backend failure on
    the first remote call, never as an environment dump.
    """
    from agentic_threat_investigator.evaluation.backends.langsmith.client import (
        LangSmithSdkEvaluationClient,
    )

    return LangSmithSdkEvaluationClient()


def _evaluation_langsmith_main(args: argparse.Namespace) -> int:
    """Run one explicit LangSmith operator command (sync/verify).

    The local dataset is strictly loaded and validated before any remote
    operation; a malformed local dataset means no LangSmith mutation
    attempt at all. Credential/network/API failures and all fail-closed
    drift conditions exit nonzero with a bounded message.
    """
    from agentic_threat_investigator.evaluation.backends.langsmith.client import (
        LangSmithBackendError,
    )
    from agentic_threat_investigator.evaluation.backends.langsmith.datasets import (
        LangSmithSyncError,
        synchronize_dataset,
        verify_dataset,
    )
    from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
        LangSmithProjectionError,
    )
    from agentic_threat_investigator.evaluation.datasets import (
        load_evaluation_scenarios,
    )

    try:
        dataset_id = EvaluationDatasetId.from_canonical(args.dataset_id)
    except ValueError as exc:
        LOGGER.error(
            "evaluation langsmith refused: dataset argument must be a canonical "
            "dataset identity such as evidence-analyst/v1: %s",
            exc,
        )
        return 1
    try:
        scenarios = load_evaluation_scenarios(dataset_id)
    except (ValueError, OSError, DatasetLoadError) as exc:
        LOGGER.error(
            "evaluation langsmith %s failed before any remote operation: %s",
            args.langsmith_operation,
            exc,
        )
        return 1
    client = _build_langsmith_evaluation_client()
    namespace = args.namespace

    async def run() -> int:
        if args.langsmith_operation == "sync":
            receipt = await synchronize_dataset(
                dataset_id=dataset_id,
                client=client,
                scenarios=scenarios,
                namespace=namespace,
            )
            LOGGER.info(
                "evaluation langsmith sync complete dataset=%s local_cases=%d "
                "created=%d unchanged=%d status=%s",
                receipt.dataset,
                receipt.local_cases,
                receipt.created,
                receipt.unchanged,
                receipt.status,
            )
            return 0
        report = await verify_dataset(
            dataset_id=dataset_id,
            client=client,
            scenarios=scenarios,
            namespace=namespace,
        )
        LOGGER.info(
            "evaluation langsmith verify complete dataset=%s local_cases=%d "
            "remote_examples=%d status=%s",
            report.dataset,
            report.local_cases,
            report.remote_examples,
            report.status,
        )
        return 0

    try:
        return asyncio.run(run())
    except (LangSmithBackendError, LangSmithSyncError, LangSmithProjectionError) as exc:
        LOGGER.error(
            "evaluation langsmith %s failed: %s",
            args.langsmith_operation,
            exc,
        )
        return 1


def _current_commit_sha() -> str | None:
    """Return the bounded ATI git SHA of the running checkout, if available.

    Reads the repository's own ``.git`` files only (no subprocess and no
    environment access): a detached HEAD resolves directly, a symbolic ref
    resolves through ``<gitdir>/refs/...``, and a worktree ``gitdir:``
    pointer is followed. Any missing/malformed state returns ``None`` and the
    metadata field is omitted. The value is validated as exactly 40 lowercase
    hex characters and never treated as a credential.
    """
    git_dir = _repo_git_dir()
    if git_dir is None:
        return None
    head = git_dir / "HEAD"
    try:
        ref = head.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if ref.startswith("ref:"):
        ref_path = git_dir / ref[4:].strip()
        try:
            ref = ref_path.read_text(encoding="utf-8").strip()
        except OSError:
            return None
    if len(ref) != 40 or any(character not in "0123456789abcdef" for character in ref):
        return None
    return ref


def _repo_git_dir() -> Path | None:
    """Return the repository's ``.git`` directory, following worktree pointers."""
    git = Path(".git")
    if git.is_dir():
        return git
    if git.is_file():
        try:
            pointer = git.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if pointer.startswith("gitdir:"):
            candidate = Path(pointer[len("gitdir:") :].strip())
            return candidate if candidate.is_dir() else None
    return None


async def _execute_evidence_analyst_benchmark(
    *,
    dataset_id: EvaluationDatasetId,
    scenarios: Sequence[ScenarioLike],
) -> EvaluationRunResult:
    """Execute the configured real Evidence Analyst benchmark (PR 30C).

    Composes the production analyst over the configured real LLM and the
    process database, then runs the common PR 30 runner through the
    evidence-analyst run service. This is the CLI's injectable benchmark seam
    (unit tests replace it with a deterministic double); it never composes
    LangSmith.
    """
    from agentic_threat_investigator.evaluation.analyst.models import (
        AnalystScenario,
    )
    from agentic_threat_investigator.evaluation.analyst.run import (
        run_evidence_analyst_evaluation,
    )

    settings = get_settings()
    engine = _make_engine(settings)
    factory = _session_factory(engine)
    uow_factory = _uow_factory(factory, settings)
    try:
        llm = _compose_llm(settings)
        analyst = _compose_evaluation_analyst(
            settings=settings,
            session_factory=factory,
            uow_factory=uow_factory,
            llm=llm,
        )
        typed = tuple(item for item in scenarios if isinstance(item, AnalystScenario))
        return await run_evidence_analyst_evaluation(
            dataset_id=dataset_id,
            analyst=analyst,
            uow_factory=uow_factory,
            scenarios=typed,
        )
    finally:
        await engine.dispose()


def _evaluation_run_main(args: argparse.Namespace) -> int:
    """Run the configured real Evidence Analyst benchmark (PR 30C).

    ``ati-eval run evidence-analyst/v1`` executes every repository case
    through the real production Evidence Analyst path with the configured
    real model, then reports the canonical local result. With ``--langsmith``
    the exact remote mirror is verified **before** any model work and the
    categorical result is published as one experiment afterwards.

    Exit semantics: ``0`` COMPLETED/PASS with requested publication
    succeeded; ``1`` COMPLETED/FAIL (publication never converts FAIL to
    success); ``2`` ERROR/config/backend/publication failure.
    """
    from agentic_threat_investigator.app.secrets import SecretNotFoundError
    from agentic_threat_investigator.evaluation.backends.langsmith.client import (
        LangSmithBackendError,
    )
    from agentic_threat_investigator.evaluation.backends.langsmith.datasets import (
        LangSmithSyncError,
        verify_dataset,
    )
    from agentic_threat_investigator.evaluation.backends.langsmith.experiments import (
        LangSmithExperimentError,
        publish_experiment,
    )
    from agentic_threat_investigator.evaluation.backends.langsmith.mapping import (
        PROJECTION_SCHEMA_VERSION,
        LangSmithProjectionError,
    )
    from agentic_threat_investigator.evaluation.backends.langsmith.results import (
        build_experiment_metadata,
    )
    from agentic_threat_investigator.evaluation.datasets import (
        load_evaluation_scenarios,
    )

    try:
        dataset_id = EvaluationDatasetId.from_canonical(args.dataset_id)
    except ValueError as exc:
        LOGGER.error(
            "evaluation run refused: dataset argument must be a canonical dataset "
            "identity such as evidence-analyst/v1: %s",
            exc,
        )
        return 2
    if dataset_id.target is not EvaluationTarget.EVIDENCE_ANALYST:
        LOGGER.error(
            "evaluation run refused: PR 30C executes only evidence-analyst/v1 (got %s)",
            dataset_id.canonical,
        )
        return 2
    try:
        scenarios = load_evaluation_scenarios(dataset_id)
    except (ValueError, OSError, DatasetLoadError) as exc:
        LOGGER.error(
            "evaluation run failed before any model work: %s",
            exc,
        )
        return 2

    settings = get_settings()
    if settings.llm_driver is LlmDriver.DETERMINISTIC:
        LOGGER.error(
            "evaluation run refused: ATI_LLM_DRIVER=deterministic selects the "
            "offline scripted boundary, not a real benchmark model"
        )
        return 2

    client: LangSmithEvaluationClient | None = None
    if args.langsmith:
        try:
            client = _build_langsmith_evaluation_client()
            report = asyncio.run(
                verify_dataset(
                    dataset_id=dataset_id,
                    client=client,
                    scenarios=scenarios,
                    namespace=args.namespace,
                )
            )
        except (
            LangSmithBackendError,
            LangSmithSyncError,
            LangSmithProjectionError,
        ) as exc:
            LOGGER.error(
                "evaluation run refused before any model work: remote dataset "
                "verification failed: %s",
                exc,
            )
            return 2
        LOGGER.info(
            "evaluation run remote verification passed dataset=%s local_cases=%d "
            "remote_examples=%d",
            report.dataset,
            report.local_cases,
            report.remote_examples,
        )

    async def run() -> int:
        try:
            run_result = await _execute_evidence_analyst_benchmark(
                dataset_id=dataset_id, scenarios=scenarios
            )
        except (SecretNotFoundError, ValueError, DatasetLoadError, OSError) as exc:
            LOGGER.error("evaluation run failed: %s", exc)
            return 2
        except Exception:
            LOGGER.exception("evaluation run failed")
            return 2
        LOGGER.info(
            "evaluation run complete:%s", "\n" + render_human_report(run_result)
        )
        if client is not None:
            commit_sha = _current_commit_sha()
            bounded_parameters: dict[str, str | float | int | bool | None] = {
                "temperature": settings.llm_temperature
            }
            if settings.llm_max_tokens is not None:
                bounded_parameters["max_tokens"] = settings.llm_max_tokens
            try:
                confirmation = await publish_experiment(
                    dataset_id=dataset_id,
                    run=run_result,
                    client=client,
                    execution_id=uuid4().hex,
                    namespace=args.namespace,
                    commit_sha=commit_sha,
                    metadata=build_experiment_metadata(
                        commit_sha=commit_sha,
                        dataset_id=dataset_id.canonical,
                        projection_schema_version=PROJECTION_SCHEMA_VERSION,
                        model_provider=settings.llm_driver.value,
                        model_name=settings.llm_model,
                        model_parameters=dict(bounded_parameters),
                    ),
                )
            except (
                LangSmithBackendError,
                LangSmithSyncError,
                LangSmithExperimentError,
            ) as exc:
                LOGGER.error(
                    "evaluation run completed but LangSmith publication failed: %s",
                    exc,
                )
                return 2
            LOGGER.info(
                "evaluation experiment confirmed run_id=%s experiment=%s "
                "feedback_count=%d",
                confirmation.run_id,
                confirmation.experiment_name,
                confirmation.feedback_count,
            )
        if run_result.execution_status is EvaluationExecutionStatus.ERROR:
            return 2
        if run_result.verdict is EvaluationVerdict.FAIL:
            return 1
        return 0

    return asyncio.run(run())
