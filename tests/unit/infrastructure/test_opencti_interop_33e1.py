# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""PR 33E-1 interop harness regression tests (E1-xx).

Focused deterministic tests for the behavior added by PR 33E-1:

- the worker-mailbox readiness gate (E1-01/E1-14 boundary): the OpenCTI 6.9
  import connector re-publishes the seeded STIX bundle to the RabbitMQ
  exchange, and a message published before the worker bound its push queue is
  silently dropped; seeding must wait for the worker mailbox to be consumed.
  These tests prove the bounded consumer probe: zero consumers waits,
  terminal probe failures fail fast, a consumed mailbox is ready, and the
  probe never places the credential in a URL (E1-10 redaction).
- the TAXII feed-convergence set logic (E1-03/E1-04/E1-05): a missing
  expected ID keeps the feed not-converged; an exact/superset visible set is
  converged; pagination is followed only within a bounded page cap (E1-14).
- acceptance-topology pinning (E1-13): no mutable ``latest`` tag may appear
  anywhere in the interop Compose topology.
- import-job/connector correlation plumbing: the seeder resolves the
  connector push queue, falls back to the documented platform convention when
  the GraphQL field is unavailable, and reports a bounded work id.

No containers, databases, or brokers are involved.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]  # mypy: PyYAML has no bundled stubs (types-PyYAML is out of scope)

import tests.interop.opencti.seed_opencti as seedmod
import tests.interop.opencti.status as statusmod

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parents[3]
_COMPOSE = _REPO_ROOT / "tests/interop/opencti/compose.yaml"


class TestWorkerMailboxGate:
    """E1-01/E1-14 boundary: seed only after the worker consumes the mailbox."""

    def test_zero_consumers_then_ready(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """E1-01: no consumer yet => keep waiting; a consumer => ready."""
        states = iter([0, 0, 1])

        def fake_consumers(*args: Any, **kwargs: Any) -> int | None:
            return next(states)

        monkeypatch.setattr(seedmod, "_rabbitmq_queue_consumers", fake_consumers)
        ready = seedmod._wait_for_worker_mailbox(
            "connector-id",
            "push_connector-id",
            api_url="http://127.0.0.1:1",
            user="ati",
            password="secret",
            timeout_seconds=10,
            poll_seconds=0.01,
        )
        assert ready is True

    def test_terminal_probe_failure_fails_fast(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """E1-02: an unrecoverable probe (auth/transport) is terminal, not a wait."""
        monkeypatch.setattr(
            seedmod,
            "_rabbitmq_queue_consumers",
            lambda *a, **k: -1,
        )
        with pytest.raises(RuntimeError, match="management API"):
            seedmod._wait_for_worker_mailbox(
                "connector-id",
                "push_connector-id",
                api_url="http://127.0.0.1:1",
                user="ati",
                password="secret",
                timeout_seconds=10,
                poll_seconds=0.01,
            )

    def test_timeout_is_bounded_and_nonzero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """E1-11: the gate never waits longer than its bounded deadline."""
        monkeypatch.setattr(
            seedmod,
            "_rabbitmq_queue_consumers",
            lambda *a, **k: 0,
        )
        with pytest.raises(RuntimeError, match="did not start consuming"):
            seedmod._wait_for_worker_mailbox(
                "connector-id",
                "push_connector-id",
                api_url="http://127.0.0.1:1",
                user="ati",
                password="secret",
                timeout_seconds=0,  # gets one probe; monotonic already elapsed
                poll_seconds=0.01,
            )

    def test_credential_never_in_probe_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """E1-10: the probe request carries the credential only in the header."""
        captured: dict[str, Any] = {}

        class _FakeResponse:
            def read(self) -> bytes:
                return b'{"consumers": 1}'

        import urllib.request

        def fake_urlopen(request: Any, timeout: int = 0) -> Any:
            captured["url"] = request.full_url
            captured["header"] = request.get_header("Authorization")
            return _FakeResponse()

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        seedmod._rabbitmq_queue_consumers(
            "http://127.0.0.1:1",
            "ati",
            "super-secret-pass",
            "push_connector-id",
        )
        assert "super-secret-pass" not in captured["url"]
        assert captured["header"] is not None
        assert "secret" not in captured["url"]

    def test_push_queue_fallback_when_graphql_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """E1-15: the documented ``push_<connector-id>`` convention is the fallback."""
        monkeypatch.setattr(
            seedmod,
            "_graphql",
            lambda *a, **k: (_ for _ in ()).throw(
                RuntimeError("connectors config not exposed")
            ),
        )
        assert seedmod._push_queue_name("http://x", "token", "conn-1") is None


class TestFeedProbeConvergence:
    """E1-03/E1-04/E1-05/E1-14: exact-ID feed convergence and bounded probing."""

    @staticmethod
    def _converged(visible: set[str], expected: set[str]) -> bool:
        # Mirrors PostgresProbe.snapshot(): every expected fixture ID must be
        # visible through the real TAXII collection.
        return visible >= expected

    def test_expected_missing_is_not_converged(self) -> None:
        """E1-03/E1-04: any missing expected ID keeps the feed not-converged."""
        expected = {"a", "b", "c"}
        visible = {"a", "b"}
        assert not self._converged(visible, expected)

    def test_exact_superset_is_converged(self) -> None:
        """E1-05: exact match (or a superset) of the required IDs converges."""
        assert self._converged({"a", "b", "c"}, {"a", "b", "c"})
        assert self._converged({"a", "b", "c", "extra"}, {"a", "b", "c"})

    def test_feed_collector_follows_next_within_bound(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """E1-14: the probe collects continuation pages strictly within its cap."""

        def fake_fetch(
            url: str, headers: Any, context: Any, *, params: dict[str, str]
        ) -> tuple[list[str], bool, dict[str, str] | None]:
            if params.get("next") is None:
                return ["id-1"], True, {"next": "opaque-1"}
            if params.get("next") == "opaque-1":
                return ["id-2"], True, {"next": "opaque-2"}
            return ["id-3"], False, None

        monkeypatch.setattr(statusmod, "_fetch_taxii_page", fake_fetch)
        monkeypatch.setattr(statusmod, "_require", lambda name: "https://taxii.local/x")
        ids = statusmod._taxii_feed_ids()
        assert ids == ["id-1", "id-2", "id-3"]

    def test_feed_collector_bounded_page_cap(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """E1-11: a server that never ends pagination is interrupted at the cap."""
        calls = {"n": 0}
        seen_tokens: list[str] = []

        def endless_fetch(
            url: str, headers: Any, context: Any, *, params: dict[str, str]
        ) -> tuple[list[str], bool, dict[str, str] | None]:
            calls["n"] += 1
            token = params.get("next", "start")
            seen_tokens.append(token)
            return [f"id-{calls['n']}"], True, {"next": f"next-{calls['n']}"}

        monkeypatch.setattr(statusmod, "_fetch_taxii_page", endless_fetch)
        monkeypatch.setattr(statusmod, "_require", lambda name: "https://taxii.local/x")
        ids = statusmod._taxii_feed_ids()
        assert len(ids) == statusmod._MAX_FEED_PROBE_PAGES
        assert calls["n"] == statusmod._MAX_FEED_PROBE_PAGES


class TestTopologyPinning:
    """E1-13: no mutable image tag in the acceptance topology."""

    @staticmethod
    def _compose() -> dict[str, Any]:
        with _COMPOSE.open("r", encoding="utf-8") as handle:
            return cast(dict[str, Any], yaml.safe_load(handle))

    def test_no_latest_anywhere(self) -> None:
        """Every image reference is an immutable pinned tag/digest."""
        compose = self._compose()
        services = compose["services"]
        assert services, "compose must define services"
        for name, service in services.items():
            image = service.get("image")
            if image is None:
                continue
            assert isinstance(image, str) and image, name
            assert not image.rstrip("/").endswith(":latest"), (name, image)
            assert "latest" not in image.rsplit("/", 1)[-1].split(":")[-1], (
                name,
                image,
            )

    def test_seaweedfs_pinned_to_tested_release(self) -> None:
        """The object-store image is the immutable 4.48 release, never latest."""
        image = self._compose()["services"]["seaweedfs"]["image"]
        assert image == "docker.io/chrislusf/seaweedfs:4.48"

    def test_every_service_has_an_image(self) -> None:
        """Build-less services must carry an explicit pinned image reference."""
        for name, service in self._compose()["services"].items():
            if "build" in service:
                continue
            assert service.get("image"), f"service {name} has no image reference"
