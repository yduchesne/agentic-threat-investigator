# SPDX-License-Identifier: AGPL-3.0-only
"""Narrow CLI entrypoints (PR 23D).

Two explicit, repository-owned entrypoints follow the current bootstrap
convention (plain modules invoked by deployment; no general-purpose CLI
framework):

- ``ati-fake-data-bootstrap``: one-shot idempotent fake batch-data bootstrap;
- ``ati-worker``: the durable investigation job worker loop.

Both load the cached typed settings once and never read environment
variables themselves. The worker composes the selected intelligence-source
registry through the operating-mode boundary and the configured real LLM;
operating mode never selects the LLM implementation.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Callable
from uuid import UUID

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
from agentic_threat_investigator.app.investigation_worker import (
    InvestigationJobWorker,
)
from agentic_threat_investigator.app.orchestration.research import (
    ResearchAgentResearchExecutor,
)
from agentic_threat_investigator.app.orchestration.runner import (
    LocalInvestigationRunner,
)
from agentic_threat_investigator.app.orchestration.services import (
    EvidenceAnalystAnalysisExecutor,
)
from agentic_threat_investigator.app.report_writer.writer import ReportWriter
from agentic_threat_investigator.app.secrets import EnvVarSecretsResolver
from agentic_threat_investigator.config import get_settings
from agentic_threat_investigator.config.settings import (
    LlmDriver,
    OperatingMode,
    Settings,
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
    build_openai_chat_model,
)
from agentic_threat_investigator.infrastructure.llm.deterministic import (
    DeterministicLlmClient,
)
from agentic_threat_investigator.infrastructure.llm.langchain_client import (
    LangChainLlmClient,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.composites import (
    register_batch_composites,
)
from agentic_threat_investigator.infrastructure.persistence.postgresql.database import (
    PostgresUnitOfWork,
)
from agentic_threat_investigator.infrastructure.report_writer_composition import (
    build_report_writer,
)
from agentic_threat_investigator.infrastructure.research_agent_composition import (
    build_research_agent,
)

LOGGER = logging.getLogger(__name__)


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


def _compose_llm(settings: Settings) -> LangChainLlmClient | DeterministicLlmClient:
    """Compose the configured LLM client for the worker process.

    ``ATI_LLM_DRIVER=deterministic`` selects the repository-owned offline
    scripted boundary (PR 24B offline real-stack browser tests); the default
    ``openai`` driver resolves the API key through the secret-reference
    bootstrap contract and builds the real chat model. Operating mode never
    selects the LLM implementation.
    """
    if settings.llm_driver is LlmDriver.DETERMINISTIC:
        return DeterministicLlmClient()
    resolver = EnvVarSecretsResolver()
    chat_model = build_openai_chat_model(settings, resolver)
    return LangChainLlmClient(chat_model)


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
    llm: LangChainLlmClient | DeterministicLlmClient,
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
    analyst = EvidenceAnalyst(
        input_loader=EvidenceAnalystInputLoader(uow_factory),
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
    logging.basicConfig(level=logging.INFO)
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


def fake_data_bootstrap_main(argv: list[str] | None = None) -> int:
    """Run the one-shot fake-data bootstrap and exit with its status code."""
    parser = argparse.ArgumentParser(prog="ati-fake-data-bootstrap")
    parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
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
    logging.basicConfig(level=logging.INFO)
    settings = get_settings()
    _log_operating_mode(settings)
    engine = _make_engine(settings)
    factory = _session_factory(engine)
    uow_factory = _uow_factory(factory, settings)

    async def run() -> int:
        try:
            sources = await build_intelligence_sources(settings)
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
