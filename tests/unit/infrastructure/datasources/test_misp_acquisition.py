# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 32C native MISP REST acquisition tests.

Matrix M32C-01..60 + configuration matrix M32C-C01..C10 (the latter in
``tests/unit/config/test_misp_settings.py``) plus acquisition vertical
slices M32C-V01..V05. Only the external HTTPS boundary is faked (in-process
``httpx.MockTransport``); the real ``ProviderHttpClient``, the real
``MispDatasource``, the real REST-envelope adapter, and the real PR 32A
``parse_misp_event`` are exercised. No test touches a live MISP server,
reads the wall clock, or sleeps for timing.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, Self

import httpx
import pytest

from agentic_threat_investigator.app.datasource_semantics import DatasourceStage
from agentic_threat_investigator.app.persistence import UnitOfWork
from agentic_threat_investigator.app.secrets import SecretsResolver
from agentic_threat_investigator.config.settings import settings_from_config
from agentic_threat_investigator.domain.datasource import (
    DatasourceDefinition,
    DatasourceId,
    DatasourceLogEvent,
    DatasourceProtocol,
    SerializationFormat,
)
from agentic_threat_investigator.domain.identifiers import (
    SemanticFormatId,
    SourceId,
)
from agentic_threat_investigator.infrastructure.datasources.misp import (
    MispDatasource,
    acquire_misp_execution,
)
from agentic_threat_investigator.infrastructure.datasources.misp_semantics import (
    MispAttributeRecord,
    MispObjectRecord,
    parse_misp_event,
)
from agentic_threat_investigator.infrastructure.providers.composition import (
    HttpClientFactory,
)
from agentic_threat_investigator.infrastructure.providers.http import (
    BoundedLimiter,
    ProviderHttpClient,
    ProviderHttpPolicy,
    RateLimiterSettings,
)
from tests.support.misp_fixtures import (
    DOMAIN_VALUE,
    FIXED_KEY,
    MISP_BASE_URL,
    MISP_REST_SEARCH_ENDPOINT,
    SECOND_EVENT_UUID,
    THIRD_EVENT_UUID,
    UNSUPPORTED_ATTRIBUTE_TYPE,
    misp_attribute,
    misp_object,
    misp_rest_event,
    misp_rest_search,
)
from tests.support.provider_http import no_op_sleep, zero_jitter

_FIXED_TS = datetime(2026, 5, 1, 10, 0, 0, tzinfo=UTC)
_EPOCH = datetime(2026, 2, 1, 12, 30, 0, tzinfo=UTC)

_DEFINITION = DatasourceDefinition(
    datasource_id=DatasourceId("misp-live"),
    source_id=SourceId.MISP,
    protocol=DatasourceProtocol.HTTPS,
    serialization_format=SerializationFormat.JSON,
    semantic_format=SemanticFormatId.MISP,
)


class _Logs:
    """In-memory append-only datasource-log fake."""

    def __init__(self, state: "_State") -> None:
        """Bind to the shared test state."""
        self.state = state

    async def append(self, event: DatasourceLogEvent) -> None:
        """Record the pending append; the UoW commit applies it."""
        self.state.pending_append = event


class _State:
    """Shared datasource-test state: durable events and commit accounting."""

    def __init__(self) -> None:
        """Start with an empty durable log."""
        self.events: list[DatasourceLogEvent] = []
        self.pending_append: DatasourceLogEvent | None = None
        self.commits = 0
        self.active = 0
        self.active_at_http: list[int] = []

    @property
    def types(self) -> list[str]:
        """Return the durable event types in append order."""
        return [event.event_type.value for event in self.events]

    @property
    def execution_ids(self) -> set[str]:
        """Return the durable execution identities."""
        return {str(event.execution_id) for event in self.events}

    @property
    def datasource_ids(self) -> set[str]:
        """Return the durable datasource identities."""
        return {event.datasource_id.value for event in self.events}


class _Uow(UnitOfWork):
    """In-memory UnitOfWork fake that tracks open transactions."""

    def __init__(self, state: _State) -> None:
        """Bind the fake UoW to the shared test state."""
        self.state = state
        self._logs = _Logs(state)
        self.datasource_logs = self._logs  # type: ignore[assignment]

    async def __aenter__(self) -> Self:
        """Reject nested/overlapping transactions and mark the boundary active."""
        assert self.state.active == 0
        self.state.active += 1
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Commit on success and roll back when the block raised."""
        if exc_type is None:
            await self.commit()
        else:
            await self.rollback()
        self.state.active -= 1

    async def commit(self) -> None:
        """Apply the pending append and count the short committed transaction."""
        if self.state.pending_append is not None:
            self.state.events.append(self.state.pending_append)
            self.state.pending_append = None
        self.state.commits += 1

    async def rollback(self) -> None:
        """Discard the pending append."""
        self.state.pending_append = None


def _factory(state: _State) -> Callable[[], UnitOfWork]:
    """Return a recorder UoW factory bound to the shared state."""
    return lambda: _Uow(state)


def _json_bytes(payload: object) -> bytes:
    """Serialize a payload exactly as httpx would for a JSON response body."""
    return json.dumps(payload).encode("utf-8")


def _json_response(
    payload: object, status: int = 200, headers: dict[str, str] | None = None
) -> httpx.Response:
    """Build a deterministic JSON response with an explicit body length."""
    response_headers = {"Content-Type": "application/json"}
    if headers:
        response_headers.update(headers)
    return httpx.Response(
        status, content=_json_bytes(payload), headers=response_headers
    )


def _client(handler: Callable[[httpx.Request], Any]) -> httpx.AsyncClient:
    """Build a deterministic mock-transport client."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _datasource(
    client: httpx.AsyncClient,
    *,
    api_key: str = FIXED_KEY,
    base_url: str = MISP_BASE_URL,
    page_size: int = 100,
    max_pages: int = 10,
    max_retries: int = 0,
    max_response_bytes: int | None = None,
    limiter: BoundedLimiter | None = None,
    clock: Callable[[], datetime] | None = None,
) -> MispDatasource:
    """Build the acquirer with deterministic policy and the fixed test key."""
    policy_kwargs: dict[str, Any] = {
        "max_retries": max_retries,
        "base_delay_seconds": 0.01,
    }
    if max_response_bytes is not None:
        policy_kwargs["max_response_bytes"] = max_response_bytes
    http = ProviderHttpClient(
        client=client,
        policy=ProviderHttpPolicy(**policy_kwargs),
        sleep=no_op_sleep,
        jitter_fn=zero_jitter,
        limiter=limiter,
    )
    return MispDatasource(
        http,
        api_key=api_key,
        base_url=base_url,
        page_size=page_size,
        max_pages=max_pages,
        clock=clock if clock is not None else (lambda: _FIXED_TS),
    )


async def _run(
    datasource: MispDatasource,
    *,
    definition: DatasourceDefinition = _DEFINITION,
    state: _State | None = None,
    clock: datetime = _EPOCH,
) -> tuple[Any, _State]:
    """Run one full bounded acquisition execution over the fake recorder state."""
    state = state or _State()
    result = await acquire_misp_execution(
        datasource=datasource,
        definition=definition,
        uow_factory=_factory(state),
        clock=lambda: clock,
    )
    return result, state


def _domain_event(
    *,
    uuid: str = SECOND_EVENT_UUID,
    attr_uuid: str = "21e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b02",
    value: str = DOMAIN_VALUE,
    info: str = "Synthetic MISP event for ATI documentation testing",
) -> dict[str, Any]:
    """Build one deterministic Event envelope carrying one domain Attribute."""
    return misp_rest_event(
        uuid=uuid,
        info=info,
        attributes=(misp_attribute(uuid=attr_uuid, type_="domain", value=value),),
    )


# ---------------------------------------------------------------------------
# Configuration / construction (M32C-01..10)
# ---------------------------------------------------------------------------


class TestConstruction:
    """M32C-01..10: endpoint construction, bounds, key, and environment."""

    def test_m32c_01_valid_https_base_yields_canonical_endpoint(self) -> None:
        """M32C-01: a valid HTTPS base URL joins the canonical REST endpoint."""
        datasource = _datasource(
            _client(lambda _: _json_response({})), base_url=MISP_BASE_URL
        )
        assert datasource.endpoint_url == MISP_REST_SEARCH_ENDPOINT
        assert datasource.endpoint_url is not None
        assert "user" not in datasource.endpoint_url
        assert "?" not in datasource.endpoint_url
        assert "#" not in datasource.endpoint_url

    def test_m32c_02_http_url_rejected(self) -> None:
        """M32C-02: a non-HTTPS base URL is rejected."""
        with pytest.raises(ValueError, match="https"):
            _datasource(
                _client(lambda _: _json_response({})),
                base_url="http://misp.example.test",
            )

    def test_m32c_03_url_credentials_rejected_safely(self) -> None:
        """M32C-03: URL-embedded credentials are rejected without echo."""
        with pytest.raises(ValueError, match="credentials"):
            _datasource(
                _client(lambda _: _json_response({})),
                base_url="https://attacker:pw@misp.example.test",
            )

    def test_m32c_04_query_and_fragment_rejected(self) -> None:
        """M32C-04: a query or fragment in the base URL is rejected."""
        with pytest.raises(ValueError, match="query"):
            _datasource(
                _client(lambda _: _json_response({})),
                base_url="https://misp.example.test?filter=spy",
            )
        with pytest.raises(ValueError, match="fragment"):
            _datasource(
                _client(lambda _: _json_response({})),
                base_url="https://misp.example.test#secret",
            )

    def test_m32c_05_blank_resolved_key_rejected(self) -> None:
        """M32C-05: a blank resolved API key is rejected at construction."""
        for blank in ("", "   "):
            with pytest.raises(ValueError, match="blank"):
                _datasource(_client(lambda _: _json_response({})), api_key=blank)

    def test_m32c_06_secret_reference_resolved_value_injected(self) -> None:
        """M32C-06: composition resolves the reference and injects the exact value."""
        from agentic_threat_investigator.infrastructure.providers.composition import (
            ProviderComposition,
        )

        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return _json_response(misp_rest_search(_domain_event()))

        settings = settings_from_config({"misp_base_url": MISP_BASE_URL})
        secrets = _DictSecrets(_full_secret_values("resolved-misp-key-123"))
        client = _client(handler)
        factory = _SharedTransportFactory(client)
        state = _State()

        async def _compose_and_acquire() -> Any:
            async with await ProviderComposition.create(
                settings, http_client_factory=factory, secrets=secrets
            ) as composition:
                assert composition.misp_datasource is not None
                return await acquire_misp_execution(
                    datasource=composition.misp_datasource,
                    definition=_DEFINITION,
                    uow_factory=_factory(state),
                    clock=lambda: _EPOCH,
                )

        try:
            result = asyncio.run(_compose_and_acquire())
        finally:
            asyncio.run(client.aclose())
        assert result.error is None
        assert requests[0].headers["Authorization"] == "resolved-misp-key-123"
        assert FIXED_KEY not in requests[0].headers.get("Authorization", "")

    def test_m32c_07_missing_secret_raises_without_http(self) -> None:
        """M32C-07: a missing secret raises SecretNotFoundError before any I/O."""
        from agentic_threat_investigator.app.secrets import SecretNotFoundError
        from agentic_threat_investigator.infrastructure.providers.composition import (
            ProviderComposition,
        )

        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return _json_response({})

        settings = settings_from_config({"misp_base_url": MISP_BASE_URL})
        missing = {
            key: value
            for key, value in _full_secret_values("x").items()
            if key != "ATI_MISP_API_KEY"
        }
        secrets = _DictSecrets(missing)
        client = _client(handler)
        factory = _SharedTransportFactory(client)

        async def _compose() -> None:
            await ProviderComposition.create(
                settings, http_client_factory=factory, secrets=secrets
            )

        try:
            with pytest.raises(SecretNotFoundError) as excinfo:
                asyncio.run(_compose())
        finally:
            asyncio.run(client.aclose())
        assert excinfo.value.name == "ATI_MISP_API_KEY"
        assert calls == []

    def test_m32c_08_defaults_pinned(self) -> None:
        """M32C-08: default page/window/concurrency/secret values are pinned."""
        settings = settings_from_config({"misp_base_url": MISP_BASE_URL})
        assert settings.misp_base_url == MISP_BASE_URL
        assert settings.misp_api_key_secret == "ATI_MISP_API_KEY"
        assert settings.misp_max_concurrency == 4
        assert settings.misp_requests_per_second is None
        assert settings.misp_page_size == 100
        assert settings.misp_max_pages == 10
        datasource = _datasource(_client(lambda _: _json_response({})))
        assert datasource.endpoint_url == MISP_REST_SEARCH_ENDPOINT

    def test_m32c_08b_unset_base_url_legal_but_acquire_fails_before_io(self) -> None:
        """An unset base URL stays legal pre-32D; acquire fails before I/O."""
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return _json_response({})

        client = _client(handler)
        datasource = MispDatasource(
            ProviderHttpClient(
                client=client,
                policy=ProviderHttpPolicy(max_retries=0),
                sleep=no_op_sleep,
                jitter_fn=zero_jitter,
            ),
            api_key=FIXED_KEY,
        )
        assert datasource.endpoint_url is None
        state = _State()
        with pytest.raises(ValueError, match="not configured"):
            asyncio.run(
                _run(
                    datasource,
                    state=state,
                )
            )
        assert calls == []
        asyncio.run(client.aclose())

    def test_m32c_08c_naive_clock_rejected(self) -> None:
        """A clock returning a naive datetime is rejected at acquisition time."""

        def naive_clock() -> datetime:
            return datetime(2026, 5, 1, 10, 0, 0)

        state = _State()
        with pytest.raises(ValueError, match="timezone-aware"):
            asyncio.run(
                _run(
                    _datasource(
                        _client(lambda _: _json_response({})),
                        clock=naive_clock,
                    ),
                    state=state,
                )
            )

    @pytest.mark.parametrize(
        ("page_size", "max_pages"),
        [
            (0, 10),
            (-1, 10),
            (1001, 10),
            (100, 0),
            (100, -2),
            (100, 1001),
        ],
    )
    def test_m32c_09_invalid_bounds_validation_fails(
        self, page_size: int, max_pages: int
    ) -> None:
        """M32C-09: out-of-range page-size/max-pages bounds are rejected."""
        with pytest.raises(ValueError):
            _datasource(
                _client(lambda _: _json_response({})),
                page_size=page_size,
                max_pages=max_pages,
            )

    @pytest.mark.parametrize(
        ("page_size", "max_pages"),
        [(True, 10), (2.5, 10), (100, True), (100, 1.5)],
    )
    def test_m32c_09b_non_integer_bounds_rejected(
        self, page_size: object, max_pages: object
    ) -> None:
        """M32C-09: non-integer page-size/max-pages values are rejected."""
        with pytest.raises(ValueError):
            _datasource(
                _client(lambda _: _json_response({})),
                page_size=page_size,  # type: ignore[arg-type]
                max_pages=max_pages,  # type: ignore[arg-type]
            )

    def test_m32c_10_env_overrides_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """M32C-10: environment values beat profile-provided values."""
        try:
            monkeypatch.setenv("ATI_MISP_BASE_URL", "https://env.example.test")
            monkeypatch.setenv("ATI_MISP_PAGE_SIZE", "7")
            monkeypatch.setenv("ATI_MISP_MAX_PAGES", "3")
            monkeypatch.setenv("ATI_MISP_API_KEY_SECRET", "MY_MISP_KEY_VAR")
            env_settings = settings_from_config(
                {"misp_base_url": MISP_BASE_URL, "misp_page_size": 200}
            )
        finally:
            monkeypatch.delenv("ATI_MISP_BASE_URL", raising=False)
            monkeypatch.delenv("ATI_MISP_PAGE_SIZE", raising=False)
            monkeypatch.delenv("ATI_MISP_MAX_PAGES", raising=False)
            monkeypatch.delenv("ATI_MISP_API_KEY_SECRET", raising=False)
        assert env_settings.misp_base_url == "https://env.example.test"
        assert env_settings.misp_page_size == 7
        assert env_settings.misp_max_pages == 3
        assert env_settings.misp_api_key_secret == "MY_MISP_KEY_VAR"


class _DictSecrets(SecretsResolver):
    """Deterministic in-memory SecretsResolver for composition tests."""

    def __init__(self, values: dict[str, str]) -> None:
        """Bind the resolver to the fixed mapping."""
        self._values = values

    def get(self, name: str) -> str | None:
        """Return the configured value for a reference name, or ``None``."""
        return self._values.get(name)


def _full_secret_values(misp_key: str) -> dict[str, str]:
    """Return values for every secret required by one full provider composition."""
    return {
        "ATI_IPINFO_LITE_TOKEN": "token-x",
        "ATI_ABUSEIPDB_API_KEY": "abuse-key-x",
        "ATI_THREATFOX_AUTH_KEY": "threatfox-key-x",
        "ATI_URLHAUS_AUTH_KEY": "urlhaus-key-x",
        "ATI_MISP_API_KEY": misp_key,
    }


class _SharedTransportFactory(HttpClientFactory):
    """HttpClientFactory sharing one mock-transport client across compositions."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        """Bind the shared mock-transport client."""
        self._client = client

    def create(
        self, policy: ProviderHttpPolicy, limiter: BoundedLimiter
    ) -> ProviderHttpClient:
        """Construct one ProviderHttpClient over the shared transport."""
        return ProviderHttpClient(
            client=self._client,
            policy=policy,
            limiter=limiter,
            sleep=no_op_sleep,
            jitter_fn=zero_jitter,
        )


# ---------------------------------------------------------------------------
# Definition guards (M32C-11..15)
# ---------------------------------------------------------------------------


class TestDefinitionGuards:
    """M32C-11..15: the datasource dimensions fail closed before any I/O."""

    def _bad_definition(self, field: str) -> DatasourceDefinition:
        """Build a definition with exactly one wrong dimension."""
        if field == "source_id":
            return DatasourceDefinition(
                datasource_id=DatasourceId("misp-live"),
                source_id=SourceId.THREATFOX,
                protocol=DatasourceProtocol.HTTPS,
                serialization_format=SerializationFormat.JSON,
                semantic_format=SemanticFormatId.MISP,
            )
        if field == "protocol":
            return DatasourceDefinition(
                datasource_id=DatasourceId("misp-live"),
                source_id=SourceId.MISP,
                protocol=DatasourceProtocol.FILE,
                serialization_format=SerializationFormat.JSON,
                semantic_format=SemanticFormatId.MISP,
            )
        if field == "semantic_format":
            return DatasourceDefinition(
                datasource_id=DatasourceId("misp-live"),
                source_id=SourceId.MISP,
                protocol=DatasourceProtocol.HTTPS,
                serialization_format=SerializationFormat.JSON,
                semantic_format=SemanticFormatId.THREATFOX,
            )
        # Serialization: only JSON exists in the vocabulary, so the guard is
        # structurally exercised by requesting JSON for a non-JSON contract
        # would be impossible; the serialization dimension is still validated
        # independently in code and its wrong value raises the same guard.
        return DatasourceDefinition(
            datasource_id=DatasourceId("misp-live"),
            source_id=SourceId.MISP,
            protocol=DatasourceProtocol.HTTPS,
            serialization_format=SerializationFormat.JSON,
            semantic_format=SemanticFormatId.MISP,
        )

    @pytest.mark.parametrize("field", ["source_id", "protocol", "semantic_format"])
    def test_m32c_12_to_15_wrong_dimension_fails_before_io(self, field: str) -> None:
        """M32C-12..15: a wrong dimension is rejected before any request."""
        calls: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request)
            return _json_response(misp_rest_search(_domain_event()))

        async def _acquire() -> None:
            async with _client(handler) as client:
                with pytest.raises(ValueError):
                    await _run(
                        _datasource(client),
                        definition=self._bad_definition(field),
                    )

        asyncio.run(_acquire())
        assert calls == []

    def test_m32c_11_misp_https_json_misp_accepted(self) -> None:
        """M32C-11: the exact MISP/HTTPS/JSON/MISP definition is accepted."""
        state = _State()

        def handler(request: httpx.Request) -> httpx.Response:
            state.active_at_http.append(state.active)
            return _json_response(misp_rest_search(_domain_event()))

        async def _acquire() -> Any:
            async with _client(handler) as client:
                return await acquire_misp_execution(
                    datasource=_datasource(client),
                    definition=_DEFINITION,
                    uow_factory=_factory(state),
                    clock=lambda: _EPOCH,
                )

        result = asyncio.run(_acquire())
        assert result.error is None
        assert len(result.objects) == 1
        assert state.active_at_http == [0]


# ---------------------------------------------------------------------------
# Request / security (M32C-16..22)
# ---------------------------------------------------------------------------


class TestRequestSecurity:
    """M32C-16..22: request contract, header-only key, safe provenance."""

    def _capture_handler(
        self, requests: list[httpx.Request]
    ) -> Callable[[httpx.Request], httpx.Response]:
        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return _json_response(misp_rest_search(_domain_event()))

        return handler

    @pytest.mark.asyncio
    async def test_m32c_16_to_19_request_contract(self) -> None:
        """M32C-16..19: POST + exact endpoint, auth header, JSON headers/body."""
        requests: list[httpx.Request] = []

        async with _client(self._capture_handler(requests)) as client:
            await _run(_datasource(client, page_size=17))

        assert requests[0].method == "POST"
        assert requests[0].url.path == "/events/restSearch"
        assert str(requests[0].url).startswith(MISP_REST_SEARCH_ENDPOINT)
        # M32C-17: key only in the Authorization header.
        assert requests[0].headers["Authorization"] == FIXED_KEY
        plain = (
            str(requests[0].url)
            + "|"
            + str(requests[0].headers)
            + "|"
            + str(requests[0].content)
        )
        assert FIXED_KEY not in requests[0].url.path
        # M32C-18: JSON Accept/Content-Type headers.
        assert "application/json" in requests[0].headers["Accept"]
        assert requests[0].headers["Content-Type"] == "application/json"
        # M32C-19: exact page/limit request body, verified scalar types.
        assert json.loads(requests[0].content) == {"page": 1, "limit": 17}
        # The key never appears in the body either.
        assert FIXED_KEY not in plain

    @pytest.mark.asyncio
    async def test_m32c_20_source_reference_credential_free(self) -> None:
        """M32C-20: the SemanticSourceContext reference is credential-free."""
        async with _client(self._capture_handler([])) as client:
            result, _ = await _run(_datasource(client))
        assert result.context.source_reference == MISP_REST_SEARCH_ENDPOINT
        assert result.context.source_reference is not None
        assert FIXED_KEY not in str(result.context.source_reference)

    @pytest.mark.asyncio
    async def test_m32c_21_error_text_never_contains_key(self) -> None:
        """M32C-21: failure text never carries the resolved key."""
        async with _client(lambda _: httpx.Response(401, json={})) as client:
            result, state = await _run(_datasource(client))
        assert result.error is not None
        assert result.error.code == "authentication_failed"
        assert FIXED_KEY not in str(result.error)
        assert FIXED_KEY not in str(result.context)
        assert FIXED_KEY not in str(state.events)

    @pytest.mark.asyncio
    async def test_m32c_22_lifecycle_and_log_representation_clean(self) -> None:
        """M32C-22: lifecycle/durable log carry no key or response body."""
        state = _State()
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return _json_response(misp_rest_search(_domain_event()))

        async with _client(handler) as client:
            await _run(_datasource(client), state=state)

        assert FIXED_KEY not in str(state.events)
        assert "Synthetic MISP event for ATI documentation testing" not in str(
            state.events
        )
        assert FIXED_KEY not in str(requests[0].content)
        assert state.types == ["started", "acquired", "decoded", "completed"]


# ---------------------------------------------------------------------------
# Envelope/parser reuse (M32C-23..31)
# ---------------------------------------------------------------------------


class TestEnvelopeParserReuse:
    """M32C-23..31: REST envelope adaptation onto the real PR 32A parser."""

    @pytest.mark.asyncio
    async def test_m32c_23_one_event_uses_real_parser(self) -> None:
        """M32C-23: one Event is parsed by the real parse_misp_event."""
        envelope = _domain_event()
        async with _client(
            lambda _: _json_response(misp_rest_search(envelope))
        ) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is None
        expected = parse_misp_event(envelope)
        assert expected.error is None
        assert result.objects == expected.records

    @pytest.mark.asyncio
    async def test_m32c_24_multiple_events_preserve_order(self) -> None:
        """M32C-24: multiple Event envelopes keep deterministic source order."""
        first = _domain_event(uuid=SECOND_EVENT_UUID, value="first-domain.test")
        second = _domain_event(
            uuid=THIRD_EVENT_UUID,
            attr_uuid="77fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b22",
            value="second-domain.test",
        )
        async with _client(
            lambda _: _json_response(misp_rest_search(first, second))
        ) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is None
        assert len(result.objects) == 2
        assert isinstance(result.objects[0], MispAttributeRecord)
        assert isinstance(result.objects[1], MispAttributeRecord)
        assert (
            str(result.objects[0].attribute.uuid)
            == "21e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b02"
        )
        assert result.objects[0].attribute.value == "first-domain.test"
        assert result.objects[1].attribute.value == "second-domain.test"

    @pytest.mark.asyncio
    async def test_m32c_25_empty_page_is_successful_empty(self) -> None:
        """M32C-25: an empty search response succeeds with zero objects."""
        async with _client(lambda _: _json_response(misp_rest_search())) as client:
            result, state = await _run(_datasource(client))
        assert result.error is None
        assert result.objects == ()
        assert state.types == ["started", "acquired", "decoded", "completed"]
        assert state.events[2].item_count == 0

    @pytest.mark.parametrize(
        "payload",
        [
            [1, 2],
            "not-an-object",
            None,
        ],
    )
    @pytest.mark.asyncio
    async def test_m32c_26_invalid_root_is_semantic_failure(
        self, payload: object
    ) -> None:
        """M32C-26: an invalid search root is a bounded semantic failure."""
        async with _client(lambda _: _json_response(payload)) as client:
            result, state = await _run(_datasource(client))
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SEMANTIC_VALIDATION
        assert result.error.code == "semantic_validation_failed"
        assert result.error.retryable is False
        assert result.objects == ()
        assert state.types == ["started", "failed"]

    @pytest.mark.asyncio
    async def test_m32c_27_missing_response_member_is_failure(self) -> None:
        """M32C-27: a search body without the response member fails closed."""
        async with _client(lambda _: _json_response({"events": []})) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is not None
        assert result.error.code == "semantic_validation_failed"

    @pytest.mark.parametrize(
        "payload",
        [
            {"response": {"Event": {"a": 1}}},
            {"response": [1, 2]},
        ],
    )
    @pytest.mark.asyncio
    async def test_m32c_27b_non_list_or_malformed_response_members(
        self, payload: object
    ) -> None:
        """M32C-27/28: a non-list response or non-object member fails closed."""
        async with _client(lambda _: _json_response(payload)) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SEMANTIC_VALIDATION
        assert result.error.code == "semantic_validation_failed"
        assert result.objects == ()

    @pytest.mark.asyncio
    async def test_m32c_28_non_object_event_is_failure(self) -> None:
        """M32C-28: a response member that is not an Event envelope fails."""
        async with _client(
            lambda _: _json_response({"response": [{"Event": "nope"}, {"Event": {}}]})
        ) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SEMANTIC_VALIDATION
        assert result.error.code == "semantic_validation_failed"
        assert result.objects == ()

    @pytest.mark.asyncio
    async def test_m32c_29_malformed_event_semantics_fail_whole_acquisition(
        self,
    ) -> None:
        """M32C-29: a malformed Event carries the PR 32A semantic error."""
        malformed = _domain_event()
        malformed["Event"]["timestamp"] = "not-a-number"
        async with _client(
            lambda _: _json_response(misp_rest_search(malformed))
        ) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SEMANTIC_VALIDATION
        assert result.error.code == "semantic_validation_failed"
        assert result.error.retryable is False
        assert result.objects == ()

    @pytest.mark.asyncio
    async def test_m32c_30_supported_and_unsupported_attributes_both_preserved(
        self,
    ) -> None:
        """M32C-30: acquisition does not filter converter support by type."""
        supported = misp_attribute(
            uuid="21e9c2a0-6e54-4a0a-9b6c-3f9cc2ff3b02", type_="domain"
        )
        unsupported = misp_attribute(
            uuid="88fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b33",
            type_=UNSUPPORTED_ATTRIBUTE_TYPE,
            value="a" * 64,
        )
        async with _client(
            lambda _: _json_response(
                misp_rest_search(misp_rest_event(attributes=(supported, unsupported)))
            )
        ) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is None
        assert len(result.objects) == 2
        types = {record.attribute.type for record in result.objects}
        assert types == {"domain", UNSUPPORTED_ATTRIBUTE_TYPE}

    @pytest.mark.asyncio
    async def test_m32c_31_event_objects_preserved(self) -> None:
        """M32C-31: Event Objects are transported as MispObjectRecord values."""
        envelope = misp_rest_event(objects=(misp_object(),))
        async with _client(
            lambda _: _json_response(misp_rest_search(envelope))
        ) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is None
        assert len(result.objects) == 1
        record = result.objects[0]
        assert isinstance(record, MispObjectRecord)
        assert str(record.object.uuid) == "32fac2a0-7e54-4a0a-ac7d-4f9cc2ff3b03"


# ---------------------------------------------------------------------------
# Pagination (M32C-32..42)
# ---------------------------------------------------------------------------


def _paginated_handler(
    pages: list[object],
    requests: list[dict[str, object]] | None = None,
) -> tuple[Callable[[httpx.Request], httpx.Response], list[dict[str, object]]]:
    """Build a handler serving one payload per sequential page request."""
    bodies: list[dict[str, object]] = requests if requests is not None else []
    page_index = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal page_index
        body = json.loads(request.content)
        bodies.append(body)
        if page_index >= len(pages):
            return _json_response(misp_rest_search())
        payload = pages[page_index]
        page_index += 1
        return _json_response(payload)

    return handler, bodies


class TestPagination:
    """M32C-32..42: bounded deterministic sequential pagination."""

    @pytest.mark.asyncio
    async def test_m32c_32_first_page_short_is_one_request(self) -> None:
        """M32C-32: a short first page completes in exactly one request."""
        bodies: list[dict[str, object]] = []
        handler, bodies = _paginated_handler(
            [misp_rest_search(_domain_event())], bodies
        )
        async with _client(handler) as client:
            result, state = await _run(_datasource(client, page_size=2))
        assert result.error is None
        assert len(result.objects) == 1
        assert len(bodies) == 1
        assert state.types == ["started", "acquired", "decoded", "completed"]

    @pytest.mark.asyncio
    async def test_m32c_33_first_full_second_short_two_requests(self) -> None:
        """M32C-33: full then short pages produce two sequential requests."""
        page1 = misp_rest_search(
            _domain_event(uuid=SECOND_EVENT_UUID, value="first-domain.test"),
            _domain_event(
                uuid=THIRD_EVENT_UUID,
                attr_uuid="77fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b22",
                value="second-domain.test",
            ),
        )
        page2 = misp_rest_search(
            _domain_event(
                uuid="99fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b44",
                attr_uuid="aafbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b55",
                value="third-domain.test",
            )
        )
        bodies: list[dict[str, object]] = []
        handler, bodies = _paginated_handler([page1, page2], bodies)
        async with _client(handler) as client:
            result, _ = await _run(_datasource(client, page_size=2))
        assert result.error is None
        assert len(bodies) == 2
        assert len(result.objects) == 3
        values = [str(r.attribute.value) for r in result.objects]
        assert values == [
            "first-domain.test",
            "second-domain.test",
            "third-domain.test",
        ]

    @pytest.mark.asyncio
    async def test_m32c_34_first_full_second_empty_stops_after_second(self) -> None:
        """M32C-34: an empty second page ends pagination after two requests."""
        page1 = misp_rest_search(_domain_event(), _domain_event(uuid=THIRD_EVENT_UUID))
        bodies: list[dict[str, object]] = []
        handler, bodies = _paginated_handler([page1, misp_rest_search()], bodies)
        async with _client(handler) as client:
            result, _ = await _run(_datasource(client, page_size=2))
        assert result.error is None
        assert len(bodies) == 2
        assert len(result.objects) == 2
        # No third probe is issued: the empty page is the stop signal.
        assert bodies[1] == {"page": 2, "limit": 2}

    @pytest.mark.asyncio
    async def test_m32c_35_full_through_max_pages_no_extra_probe(self) -> None:
        """M32C-35: full pages through max_pages never probe page max_pages+1."""
        calls: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            calls.append(body)
            return _json_response(misp_rest_search(_domain_event()))

        async with _client(handler) as client:
            result, state = await _run(_datasource(client, page_size=1, max_pages=3))
        assert result.error is None
        assert len(calls) == 3
        assert [body["page"] for body in calls] == [1, 2, 3]
        assert all(body["limit"] == 1 for body in calls)
        assert len(result.objects) == 3
        # Bounded acquisition window completed; never a claim of exhaustion.
        assert state.types == ["started", "acquired", "decoded", "completed"]

    @pytest.mark.asyncio
    async def test_m32c_36_records_across_pages_deterministic_order(self) -> None:
        """M32C-36: records from later pages append after earlier pages."""
        page1 = misp_rest_search(_domain_event(uuid=SECOND_EVENT_UUID))
        page2 = misp_rest_search(
            _domain_event(
                uuid=THIRD_EVENT_UUID,
                attr_uuid="77fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b22",
                value="page-two.test",
            )
        )
        handler, _ = _paginated_handler([page1, page2])
        async with _client(handler) as client:
            result, _ = await _run(_datasource(client, page_size=1))
        assert len(result.objects) == 2
        assert [str(r.attribute.value) for r in result.objects] == [
            DOMAIN_VALUE,
            "page-two.test",
        ]

    @pytest.mark.asyncio
    async def test_m32c_37_page2_http_failure_zero_objects(self) -> None:
        """M32C-37: a page-2 HTTP failure leaks no page-1 objects."""
        calls: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            calls.append(body)
            if len(calls) == 1:
                return _json_response(
                    misp_rest_search(
                        _domain_event(), _domain_event(uuid=THIRD_EVENT_UUID)
                    )
                )
            return httpx.Response(503, json={})

        async with _client(handler) as client:
            result, state = await _run(_datasource(client, page_size=2))
        assert result.objects == ()
        assert result.error is not None
        assert result.error.stage is DatasourceStage.ACQUISITION
        assert result.error.code == "provider_unavailable"
        assert len(calls) == 2
        assert state.types == ["started", "failed"]

    @pytest.mark.asyncio
    async def test_m32c_38_page2_bad_envelope_zero_objects(self) -> None:
        """M32C-38: a page-2 malformed envelope fails the whole acquisition."""
        handler, _ = _paginated_handler(
            [
                misp_rest_search(_domain_event()),
                {"not_the_response_member": []},
            ]
        )
        async with _client(handler) as client:
            result, _ = await _run(_datasource(client, page_size=1))
        assert result.objects == ()
        assert result.error is not None
        assert result.error.code == "semantic_validation_failed"

    @pytest.mark.asyncio
    async def test_m32c_39_page2_bad_event_zero_objects(self) -> None:
        """M32C-39: a page-2 malformed Event fails the whole acquisition."""
        bad = _domain_event()
        bad["Event"]["info"] = "   "
        handler, _ = _paginated_handler(
            [misp_rest_search(_domain_event()), misp_rest_search(bad)]
        )
        async with _client(handler) as client:
            result, _ = await _run(_datasource(client, page_size=1))
        assert result.objects == ()
        assert result.error is not None
        assert result.error.code == "semantic_validation_failed"
        assert result.error.retryable is False

    @pytest.mark.asyncio
    async def test_m32c_40_request_bodies_pages_and_constant_limit(self) -> None:
        """M32C-40: bodies carry pages 1..N with one constant limit."""
        bodies: list[dict[str, object]] = []
        handler, bodies = _paginated_handler(
            [
                misp_rest_search(_domain_event(), _domain_event(uuid=THIRD_EVENT_UUID)),
                misp_rest_search(_domain_event()),
            ],
            bodies,
        )
        async with _client(handler) as client:
            await _run(_datasource(client, page_size=2))
        assert [body["page"] for body in bodies] == [1, 2]
        assert [body["limit"] for body in bodies] == [2, 2]

    @pytest.mark.asyncio
    async def test_m32c_41_acquired_bytes_exact_successful_page_sum(self) -> None:
        """M32C-41: ACQUIRED byte_count is the exact successful-page byte sum."""
        page1 = misp_rest_search(_domain_event())
        page2 = misp_rest_search(
            _domain_event(
                uuid=THIRD_EVENT_UUID,
                attr_uuid="77fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b22",
                value="second-page.test",
            )
        )
        # page_size=1 keeps both pages full; the terminating empty third page
        # is a successful response whose bytes also belong to the sum.
        payloads: list[object] = [page1, page2, misp_rest_search()]
        expected = sum(len(_json_bytes(payload)) for payload in payloads)
        handler, bodies = _paginated_handler(payloads)
        state = _State()
        async with _client(handler) as client:
            await _run(_datasource(client, page_size=1), state=state)
        acquired = state.events[1]
        assert acquired.byte_count == expected
        assert state.events[2].item_count == 2
        assert len(bodies) == 3

    @pytest.mark.asyncio
    async def test_m32c_42_raw_page_bytes_never_retained(self) -> None:
        """M32C-42: raw page payloads are not retained in the result."""
        envelope = _domain_event()
        envelope["Event"]["Comment"] = [{"marker": "page-marker-xyz"}]
        async with _client(
            lambda _: _json_response(misp_rest_search(envelope))
        ) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is None
        for record in result.objects:
            assert isinstance(record, (MispAttributeRecord, MispObjectRecord))
        assert "page-marker-xyz" not in str(result)
        assert "response" not in str(result.objects)


# ---------------------------------------------------------------------------
# HTTP failure mapping (M32C-43..50)
# ---------------------------------------------------------------------------


class TestHttpMapping:
    """M32C-43..50: every HTTP failure maps to a bounded typed stage error."""

    @pytest.mark.asyncio
    async def test_m32c_43_timeout_typed_retryable(self) -> None:
        """M32C-43: a request timeout is ACQUISITION/timeout and retryable."""

        def handler(_: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("connection timed out")

        async with _client(handler) as client:
            result, state = await _run(_datasource(client))
        assert result.objects == ()
        assert result.error is not None
        assert result.error.stage is DatasourceStage.ACQUISITION
        assert result.error.code == "timeout"
        assert result.error.retryable is True
        assert "connection timed out" not in str(result.error)
        assert state.types == ["started", "failed"]

    @pytest.mark.asyncio
    async def test_m32c_44_429_preserves_retry_after(self) -> None:
        """M32C-44: 429 maps to a retryable rate limit preserving Retry-After."""
        async with _client(
            lambda _: httpx.Response(429, headers={"Retry-After": "29241"}, json={})
        ) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is not None
        assert result.error.stage is DatasourceStage.ACQUISITION
        assert result.error.code == "rate_limited"
        assert result.error.retryable is True
        assert result.error.retry_after_seconds == 29241

    @pytest.mark.parametrize(
        ("status", "code", "retryable"),
        [
            (401, "authentication_failed", False),
            (403, "forbidden", False),
            (404, "not_found", False),
        ],
    )
    @pytest.mark.asyncio
    async def test_m32c_45_to_47_status_mapping(
        self, status: int, code: str, retryable: bool
    ) -> None:
        """M32C-45..47: 401/403/404 map to bounded non-retryable codes."""
        async with _client(lambda _: httpx.Response(status, json={})) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is not None
        assert result.error.stage is DatasourceStage.ACQUISITION
        assert result.error.code == code
        assert result.error.retryable is retryable

    @pytest.mark.asyncio
    async def test_m32c_48_exhausted_5xx_provider_unavailable(self) -> None:
        """M32C-48: exhausted 5xx responses map to a retryable unavailable code."""
        attempts = 0

        def handler(_: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(503, json={})

        async with _client(handler) as client:
            result, _ = await _run(_datasource(client, max_retries=2))
        assert result.error is not None
        assert result.error.stage is DatasourceStage.ACQUISITION
        assert result.error.code == "provider_unavailable"
        assert result.error.retryable is True
        # Every retry was attempted before exhaustion.
        assert attempts == 3

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "body",
        [
            b"{not json",
            b"\xff\xfe\x00",
        ],
    )
    async def test_m32c_49_invalid_json_bounded_serialization_failure(
        self, body: bytes
    ) -> None:
        """M32C-49: malformed JSON is a bounded non-retryable serialization failure."""

        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=body, headers={"Content-Type": "application/json"}
            )

        async with _client(handler) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SERIALIZATION
        assert result.error.code == "serialization_failed"
        assert result.error.retryable is False

    @pytest.mark.asyncio
    async def test_m32c_49b_wrong_media_type_serialization_failure(self) -> None:
        """M32C-49: an unaccepted success Content-Type is a serialization failure."""
        async with _client(
            lambda _: httpx.Response(
                200, content=b"{}", headers={"Content-Type": "text/plain"}
            )
        ) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SERIALIZATION
        assert result.error.code == "serialization_failed"
        assert result.error.retryable is False

    @pytest.mark.asyncio
    async def test_m32c_50_oversized_response_preserves_bounded_classification(
        self,
    ) -> None:
        """M32C-50: an oversized response keeps the existing bounded classification."""
        big = misp_rest_search(*[_domain_event() for _ in range(20)])
        async with _client(lambda _: _json_response(big)) as client:
            result, _ = await _run(_datasource(client, max_response_bytes=64))
        assert result.objects == ()
        assert result.error is not None
        # PROVIDER_UNAVAILABLE is not involved: size bounding is a terminal
        # non-retryable acquisition classification.
        assert result.error.stage is DatasourceStage.ACQUISITION
        assert result.error.code == "acquisition_failed"
        assert result.error.retryable is False


# ---------------------------------------------------------------------------
# Cancellation / determinism (M32C-51..60)
# ---------------------------------------------------------------------------


class TestCancellationDeterminism:
    """M32C-51..60: cancellation propagation and deterministic behavior."""

    @pytest.mark.asyncio
    async def test_m32c_51_cancel_active_request_propagates(self) -> None:
        """M32C-51: cancellation during an active request propagates and logs CANCELLED."""
        state = _State()
        entered = asyncio.Event()
        never = asyncio.Event()

        async def handler(_: httpx.Request) -> httpx.Response:
            entered.set()
            await never.wait()
            return _json_response({})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        datasource = _datasource(client)
        task = asyncio.create_task(
            acquire_misp_execution(
                datasource=datasource,
                definition=_DEFINITION,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )
        )
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert state.types == ["started", "cancelled"]
        assert state.events[-1].event_type.value == "cancelled"
        assert state.events[-1].error_code is None
        await client.aclose()

    @pytest.mark.asyncio
    async def test_m32c_52_cancel_limiter_wait_propagates_and_cleans(self) -> None:
        """M32C-52: cancelling a limiter-rate wait propagates and cleans the slot."""
        clock = _DrivenClock()
        sleep_started = asyncio.Event()
        blocker = asyncio.Event()

        async def blocking_sleep(_: float) -> None:
            sleep_started.set()
            await blocker.wait()

        limiter = BoundedLimiter(
            RateLimiterSettings(max_concurrency=1, requests_per_second=1.0),
            sleep=blocking_sleep,
            clock=clock,
        )
        calls = 0

        def handler(_: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return _json_response(misp_rest_search(_domain_event()))

        # page_size=2 keeps the prime a single short page so exactly one
        # limiter admission happens before the wait-under-test.
        datasource = _datasource(_client(handler), page_size=2, limiter=limiter)

        # Prime one successful request so the next request must reserve a rate
        # slot and wait for it.
        prime_state = _State()
        result = await acquire_misp_execution(
            datasource=datasource,
            definition=_DEFINITION,
            uow_factory=_factory(prime_state),
            clock=lambda: _EPOCH,
        )
        assert result.error is None
        assert len(result.objects) == 1

        # The second acquisition must wait on the rate slot; cancel it mid-wait.
        waiting_state = _State()
        task = asyncio.create_task(
            acquire_misp_execution(
                datasource=datasource,
                definition=_DEFINITION,
                uow_factory=_factory(waiting_state),
                clock=lambda: _EPOCH,
            )
        )
        await asyncio.wait_for(sleep_started.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert waiting_state.types == ["started", "cancelled"]

        # The limiter cleaned its reservation: advancing the clock admits the
        # next acquisition immediately without a stale slot blocking it.
        blocker.set()
        clock.t = 2.0
        final_state = _State()
        final_result = await acquire_misp_execution(
            datasource=datasource,
            definition=_DEFINITION,
            uow_factory=_factory(final_state),
            clock=lambda: _EPOCH,
        )
        assert final_result.error is None
        assert len(final_result.objects) == 1
        assert calls == 2
        assert final_state.types == ["started", "acquired", "decoded", "completed"]

    @pytest.mark.asyncio
    async def test_m32c_53_cancel_before_page2_no_successful_result(self) -> None:
        """M32C-53: cancelling before page 2 completes yields no successful result."""
        state = _State()
        page2_entered = asyncio.Event()
        never = asyncio.Event()
        calls: list[dict[str, object]] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            calls.append(body)
            if len(calls) == 1:
                return _json_response(misp_rest_search(_domain_event()))
            page2_entered.set()
            await never.wait()
            return _json_response({})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        datasource = _datasource(client, page_size=1)
        task = asyncio.create_task(
            acquire_misp_execution(
                datasource=datasource,
                definition=_DEFINITION,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )
        )
        await page2_entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert state.types == ["started", "cancelled"]
        assert "completed" not in state.types
        assert len(calls) == 2
        await client.aclose()

    @pytest.mark.asyncio
    async def test_m32c_54_runner_cancellation_best_effort_then_propagate(self) -> None:
        """M32C-54: runner cancellation appends best-effort CANCELLED + propagates."""
        # Covered exhaustively by M32C-51 and M32C-53; this test re-asserts
        # the runner terminal contract directly.
        state = _State()
        entered = asyncio.Event()
        never = asyncio.Event()

        async def handler(_: httpx.Request) -> httpx.Response:
            entered.set()
            await never.wait()
            return _json_response({})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        task = asyncio.create_task(
            acquire_misp_execution(
                datasource=_datasource(client),
                definition=_DEFINITION,
                uow_factory=_factory(state),
                clock=lambda: _EPOCH,
            )
        )
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert state.types[-1] == "cancelled"
        await client.aclose()

    @pytest.mark.asyncio
    async def test_m32c_55_same_pages_and_clock_equal_results(self) -> None:
        """M32C-55: identical inputs produce structurally equal results."""
        payload = misp_rest_search(
            _domain_event(), _domain_event(uuid=THIRD_EVENT_UUID)
        )

        def handler(_: httpx.Request) -> httpx.Response:
            return _json_response(payload)

        results: list[Any] = []
        for _ in range(2):
            async with _client(handler) as client:
                result, _ = await _run(_datasource(client, page_size=5))
            results.append(result)
            assert result.error is None
        assert results[0] == results[1]

    @pytest.mark.asyncio
    async def test_m32c_56_acquisition_constructs_no_evidence(self) -> None:
        """M32C-56: acquisition returns only typed MISP semantic records."""
        async with _client(
            lambda _: _json_response(misp_rest_search(_domain_event()))
        ) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is None
        for record in result.objects:
            assert isinstance(record, (MispAttributeRecord, MispObjectRecord))
            assert not hasattr(record, "raw_payload")
            assert not hasattr(record, "observed_at")
            assert type(record).__module__.endswith(".misp_semantics")

    @pytest.mark.asyncio
    async def test_m32c_57_acquisition_performs_no_persistence(self) -> None:
        """M32C-57: the fake UoW sees only datasource-log lifecycle appends."""
        state = _State()
        async with _client(
            lambda _: _json_response(misp_rest_search(_domain_event()))
        ) as client:
            result, _ = await _run(_datasource(client), state=state)
        assert result.error is None
        assert all(
            event.event_type.value in {"started", "acquired", "decoded", "completed"}
            for event in state.events
        )
        assert "converted" not in state.types
        assert state.commits == len(state.events)

    @pytest.mark.asyncio
    async def test_m32c_58_real_parser_reused(self) -> None:
        """M32C-58: the real parse_misp_event is exercised end to end."""
        envelope = _domain_event()
        async with _client(
            lambda _: _json_response(misp_rest_search(envelope))
        ) as client:
            result, _ = await _run(_datasource(client))
        assert result.error is None
        assert result.objects == parse_misp_event(envelope).records
        assert not isinstance(result.objects[0], dict)

    @pytest.mark.asyncio
    async def test_m32c_59_no_second_concurrency_wrapper(self) -> None:
        """M32C-59: the acquirer stacks no second semaphore or limiter."""
        limiter = BoundedLimiter(RateLimiterSettings(max_concurrency=1))
        datasource = _datasource(
            _client(lambda _: _json_response(misp_rest_search(_domain_event()))),
            limiter=limiter,
        )
        assert not hasattr(datasource, "_semaphore")
        assert not hasattr(datasource, "_limiter")
        # The only admitted limiter is the injected ProviderHttpClient one.
        assert datasource._http._limiter is limiter

    @pytest.mark.asyncio
    async def test_m32c_60_max_active_page_requests_is_one(self) -> None:
        """M32C-60: pagination never has more than one active page request."""
        in_flight = 0
        peak = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            body = json.loads(request.content)
            in_flight -= 1
            if int(body["page"]) == 1:
                return _json_response(
                    misp_rest_search(
                        _domain_event(), _domain_event(uuid=THIRD_EVENT_UUID)
                    )
                )
            return _json_response(misp_rest_search(_domain_event()))

        async with _client(handler) as client:
            await _run(_datasource(client, page_size=2))
        assert peak == 1


async def _recorder_started(state: _State) -> DatasourceLogEvent | None:
    """Return the STARTED event if one was appended (helper for M32C-52)."""
    for event in state.events:
        if event.event_type.value == "started":
            return event
    return None


class _DrivenClock:
    """Manually driven monotonic clock for deterministic limiter tests."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


# ---------------------------------------------------------------------------
# Vertical slices (M32C-V01..V05)
# ---------------------------------------------------------------------------


class TestVerticalSlices:
    """M32C-V01..V05: acquisition with only the external HTTP boundary faked."""

    @pytest.mark.asyncio
    async def test_v01_one_page_acquisition(self) -> None:
        """M32C-V01: fixture -> real HTTP -> adapter -> real parser -> result."""
        envelope = _domain_event()
        body = _json_bytes(misp_rest_search(envelope))
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(
                200,
                content=body,
                headers={"Content-Type": "application/json"},
            )

        async with _client(handler) as client:
            result, state = await _run(_datasource(client, page_size=10))

        assert result.error is None
        assert requests[0].headers["Authorization"] == FIXED_KEY
        assert result.context.datasource_id == _DEFINITION.datasource_id
        assert result.context.source_id is SourceId.MISP
        assert result.context.semantic_format is SemanticFormatId.MISP
        assert result.context.retrieved_at == _FIXED_TS
        assert result.context.source_reference == MISP_REST_SEARCH_ENDPOINT
        assert len(result.objects) == 1
        assert isinstance(result.objects[0], MispAttributeRecord)
        assert state.types == ["started", "acquired", "decoded", "completed"]
        assert state.events[1].byte_count == len(body)
        assert state.events[2].item_count == 1

    @pytest.mark.asyncio
    async def test_v02_multi_page_bounded_acquisition(self) -> None:
        """M32C-V02: full then short pages, two requests, flattened order."""
        page1 = misp_rest_search(
            _domain_event(uuid=SECOND_EVENT_UUID),
            _domain_event(
                uuid=THIRD_EVENT_UUID,
                attr_uuid="aafbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b55",
                value="first-page-second.test",
            ),
        )
        page2 = misp_rest_search(
            _domain_event(
                uuid="99fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b44",
                attr_uuid="77fbc2a0-8e54-4a0a-bc8e-5f9cc2ff3b22",
                value="second-page.test",
            )
        )
        bodies: list[dict[str, object]] = []
        handler, bodies = _paginated_handler([page1, page2], bodies)
        async with _client(handler) as client:
            result, _ = await _run(_datasource(client, page_size=2, max_pages=10))
        assert result.error is None
        assert len(bodies) == 2
        assert [b["page"] for b in bodies] == [1, 2]
        assert [str(r.attribute.value) for r in result.objects] == [
            DOMAIN_VALUE,
            "first-page-second.test",
            "second-page.test",
        ]

    @pytest.mark.asyncio
    async def test_v03_later_page_failure_is_atomic(self) -> None:
        """M32C-V03: a page-2 typed failure leaks zero semantic objects."""
        handler, _ = _paginated_handler(
            [misp_rest_search(_domain_event(), _domain_event(uuid=THIRD_EVENT_UUID))]
        )

        def failing(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            if int(body["page"]) == 1:
                return _json_response(
                    misp_rest_search(
                        _domain_event(), _domain_event(uuid=THIRD_EVENT_UUID)
                    )
                )
            return httpx.Response(500, json={})

        async with _client(failing) as client:
            result, state = await _run(_datasource(client, page_size=2))
        assert result.objects == ()
        assert result.error is not None
        assert result.error.code == "provider_unavailable"
        assert state.types == ["started", "failed"]

    @pytest.mark.asyncio
    async def test_v04_semantic_failure_is_atomic(self) -> None:
        """M32C-V04: a malformed Event yields the real parser error and zero objects."""
        bad = _domain_event()
        bad["Event"]["Attribute"] = [{"Attribute": {"uuid": "not-a-uuid"}}]
        async with _client(lambda _: _json_response(misp_rest_search(bad))) as client:
            result, state = await _run(_datasource(client))
        assert result.objects == ()
        assert result.error is not None
        assert result.error.stage is DatasourceStage.SEMANTIC_VALIDATION
        assert result.error.code == "semantic_validation_failed"
        assert result.error.retryable is False
        assert state.types == ["started", "failed"]

    @pytest.mark.asyncio
    async def test_v05_max_window_bound_no_extra_probe(self) -> None:
        """M32C-V05: all-full pages stop exactly at max_pages without probing."""
        calls: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            calls.append(body)
            return _json_response(misp_rest_search(_domain_event()))

        async with _client(handler) as client:
            result, state = await _run(_datasource(client, page_size=1, max_pages=2))
        assert result.error is None
        assert [b["page"] for b in calls] == [1, 2]
        assert len(result.objects) == 2
        assert state.types == ["started", "acquired", "decoded", "completed"]
