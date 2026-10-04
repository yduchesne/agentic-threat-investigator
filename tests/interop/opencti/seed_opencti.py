#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""OpenCTI fake-world seeder of the interoperability harness (PR 33E section 10.4).

Seeds the ATI-authored deterministic STIX fake world into a real OpenCTI
instance through OpenCTI's standard automation surface (GraphQL): the bundle
is stored with ``uploadImport`` and dispatched to the ``INTERNAL_IMPORT_FILE``
connector with ``askJobImport`` (``bypassValidation: true`` so the pinned
6.9.29 platform does not divert it into the validation workbench -- the
one-call ``uploadAndAskJobImport`` hardcodes ``forceValidation: true`` and
would never materialize the fixture); a TAXII 2.1 collection is created
(or re-used from ``OPENCTI_TAXII_COLLECTION_ID``) so the fixture is served
through OpenCTI's real TAXII 2.1 server, and a restricted user with a bearer
token is created for ATI's authenticated read. Seeding additionally waits
for the ATI worker to consume the import connector's RabbitMQ push queue
(PR 33E-1 worker-mailbox gate) so the connector's bundle publish is never
dropped by a not-yet-bound exchange route.

The seeder performs **no** TAXII acquisition and no ATI persistence; it only
bootstraps the external OpenCTI side deterministically. If ``uploadImport``,
``askJobImport``, or ``taxiiCollectionAdd`` do not exist on the pinned OpenCTI
version, the seeder fails loudly rather than using undocumented/private
endpoints.

Environment:

  OPENCTI_API_URL      e.g. http://opencti:8080
  OPENCTI_ADMIN_TOKEN  admin bearer token (Authorization header only)
  OPENCTI_TAXII_COLLECTION_ID  optional pre-created collection id
  ATI_INTEROP_RABBITMQ_API_URL RabbitMQ management API base URL (optional)
  ATI_INTEROP_RABBIT_USER / ATI_INTEROP_RABBIT_PASS synthetic creds (optional)

Output: prints a bounded JSON line with the collection id, the restricted
user token id, the file/work correlation id, and the seed acknowledgement.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from uuid import uuid4

from tests.interop.opencti.fixtures.opencti_fake_world import (
    fake_world_bundle_v1,
    fake_world_update_v2,
)

_ADMIN_PASSWORD = "OpenCTI-Interop-Admin-Test-Passw0rd!"
_ATI_USER = "ati-interop-consumer"
_ATI_USER_PASSWORD = "OpenCTI-Interop-Consumer-Test-Passw0rd!"
_WORKER_MAILBOX_TIMEOUT_SECONDS = 360
_WORKER_MAILBOX_POLL_SECONDS = 5


def _require(env: str) -> str:
    value = os.environ.get(env, "")
    if not value:
        raise SystemExit(f"{env} is required")
    return value


def _graphql(
    url: str, token: str, query: str, variables: dict[str, Any]
) -> dict[str, Any]:
    """Run one GraphQL request against OpenCTI and return the data member."""
    request = urllib.request.Request(
        f"{url.rstrip('/')}/graphql",
        data=json.dumps({"query": query, "variables": variables}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if "errors" in payload:
        raise RuntimeError(
            f"OpenCTI GraphQL rejected the request: {payload['errors'][0]['message']}"
        )
    data = payload.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("OpenCTI GraphQL returned no data member")
    return data


def _rabbitmq_queue_consumers(
    api_url: str, user: str, password: str, queue: str
) -> int | None:
    """Return the RabbitMQ management API consumer count for one queue.

    Returns ``None`` when the queue does not exist yet (the worker has not
    declared its push-queue binding), ``-1`` on an authorization/transport
    failure (so the caller can fail fast instead of treating credentials or
    connectivity problems as "not ready yet"), and the live consumer count
    otherwise. Credentials travel only in the HTTP Basic Authorization
    header and are never logged.
    """
    encoded = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}/api/queues/%2F/{urllib.parse.quote(queue, safe='')}",
        headers={"Authorization": f"Basic {encoded}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        return -1
    except Exception:  # noqa: BLE001 - transport failure means "cannot verify readiness"
        return -1
    if not isinstance(payload, dict):
        return -1
    consumers = payload.get("consumers")
    return consumers if isinstance(consumers, int) else -1


def _discover_import_connector(api_url: str, token: str) -> str:
    """Resolve the registered ``INTERNAL_IMPORT_FILE`` connector id.

    Retries through the connector registration window; OpenCTI 6.9 requires
    this separate connector service for bundle materialization.
    """
    for _ in range(18):
        connectors = _graphql(
            api_url,
            token,
            "{ connectors { id connector_type } }",
            {},
        )
        connector_id = next(
            (
                entry["id"]
                for entry in connectors.get("connectors", [])
                if isinstance(entry, dict)
                and entry.get("connector_type") == "INTERNAL_IMPORT_FILE"
            ),
            None,
        )
        if connector_id is not None:
            return str(connector_id)
        time.sleep(10)
    raise RuntimeError(
        "no INTERNAL_IMPORT_FILE connector is registered; add the "
        "opencti-import-stix connector service and wait for its registration"
    )


def _push_queue_name(api_url: str, token: str, connector_id: str) -> str | None:
    """Return the worker push-queue name OpenCTI exposes for one connector.

    OpenCTI exposes each connector's RabbitMQ ``push`` queue through the
    ``connectors`` GraphQL query (the same shape the 6.9 worker consumes).
    ``None`` means the field is unavailable on this deployment; callers fall
    back to the documented ``push_<connector-id>`` platform convention.
    """
    try:
        connectors = _graphql(
            api_url,
            token,
            "{ connectors { id connector_type config { push } } }",
            {},
        )
    except RuntimeError:
        return None
    for entry in connectors.get("connectors", []):
        if not isinstance(entry, dict) or entry.get("id") != connector_id:
            continue
        config = entry.get("config")
        if isinstance(config, dict) and isinstance(config.get("push"), str):
            return str(config["push"])
        return None
    return None


def _wait_for_worker_mailbox(
    connector_id: str,
    push_queue: str,
    *,
    api_url: str,
    user: str,
    password: str,
    timeout_seconds: int = _WORKER_MAILBOX_TIMEOUT_SECONDS,
    poll_seconds: float = _WORKER_MAILBOX_POLL_SECONDS,
) -> bool:
    """Wait until the ATI worker consumes the import connector's push queue.

    PR 33E-1: the 6.9 import connector re-publishes the seeded STIX bundle
    to the RabbitMQ exchange; a message published before the worker bound its
    push queue is silently dropped by the direct exchange, so seeding must
    wait for the worker mailbox to be consumed first. Returns ``True`` when
    the queue reports >= 1 consumer within the bound. Raises
    :class:`RuntimeError` on timeout or on an unrecoverable probe failure so
    the harness fails loudly instead of seeding into a lost-message topology.
    """
    started = time.monotonic()
    while time.monotonic() - started < timeout_seconds:
        consumers = _rabbitmq_queue_consumers(api_url, user, password, push_queue)
        if consumers is not None and consumers >= 1:
            return True
        if consumers == -1:
            raise RuntimeError(
                "cannot reach the RabbitMQ management API for worker-mailbox "
                f"readiness ({push_queue}); check ATI_INTEROP_RABBITMQ_API_URL "
                "and the synthetic interop credentials"
            )
        time.sleep(poll_seconds)
    raise RuntimeError(
        "ATI worker did not start consuming the import connector push queue "
        f"{push_queue} within {timeout_seconds}s; the deterministic STIX "
        "bundle would be dropped by the exchange (PR 33E-1 worker-mailbox gate)"
    )


def _upload_and_ask(
    api_url: str, token: str, connector_id: str, bundle: dict[str, Any], stage: str
) -> str | None:
    """Upload one STIX bundle and ask the import connector for the job.

    OpenCTI 6.9 removed the classic ``importBundle`` mutation; OpenCTI 6.9
    accepts a bundle by uploading it as a file (multipart ``Upload!``) and
    asking the built-in ``INTERNAL_IMPORT_FILE`` connector for an import job.

    PR 33E-1 verified (against the pinned 6.9.29 platform source) that the
    one-call ``uploadAndAskJobImport`` mutation hardcodes ``forceValidation:
    true``: the ordered job then routes the bundle into the validation
    workbench (``uploadPending``) instead of the worker push queue, so the
    STIX objects never materialize. The supported two-step surface is used
    instead: ``uploadImport`` stores the file without a job, and
    ``askJobImport`` dispatches it with ``bypassValidation: true`` +
    ``forceValidation: false`` so the connector publishes the bundle to the
    worker queue for deterministic materialization.

    Returns the platform file id (``import/global/...``) used as the job
    correlation identity.
    """
    boundary = uuid4().hex
    operations = json.dumps(
        {
            "query": (
                "mutation UploadImport($file: Upload!, $fileMarkings: [String]) "
                "{ uploadImport(file: $file, fileMarkings: $fileMarkings) { id } }"
            ),
            "variables": {"file": None, "fileMarkings": []},
        }
    )
    mapping = json.dumps({"0": ["variables.file"]})
    file_name = f"ati_interop_{stage}.json"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="operations"\r\n\r\n'
        f"{operations}\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="map"\r\n\r\n'
        f"{mapping}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="0"; filename="{file_name}"\r\n'
        "Content-Type: application/json\r\n\r\n"
        f"{json.dumps(bundle, separators=(',', ':'))}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{api_url.rstrip('/')}/graphql",
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if "errors" in payload:
        raise RuntimeError(
            f"OpenCTI GraphQL rejected the bundle upload: "
            f"{payload['errors'][0]['message']}"
        )
    uploaded = payload.get("data", {}).get("uploadImport")
    if not isinstance(uploaded, dict) or not isinstance(uploaded.get("id"), str):
        raise RuntimeError("OpenCTI uploadImport returned no usable file identity")
    file_id = str(uploaded["id"])

    asked = _graphql(
        api_url,
        token,
        (
            "mutation AskJobImport($fileName: ID!, $connectorId: String, "
            "$bypassValidation: Boolean, $forceValidation: Boolean) { "
            "askJobImport(fileName: $fileName, connectorId: $connectorId, "
            "bypassValidation: $bypassValidation, forceValidation: $forceValidation) "
            "{ id } }"
        ),
        {
            "fileName": file_id,
            "connectorId": connector_id,
            "bypassValidation": True,
            "forceValidation": False,
        },
    )
    if stage == "v1" and "askJobImport" not in asked:
        raise RuntimeError("OpenCTI askJobImport returned no acknowledgement")
    return file_id


def _ensure_taxii_collection(api_url: str, token: str) -> str:
    """Create (or return) the harness TAXII 2.1 collection id."""
    existing = os.environ.get("OPENCTI_TAXII_COLLECTION_ID")
    if existing:
        return existing
    query = """
        mutation TaxiiCollectionAdd($input: TaxiiCollectionAddInput!) {
          taxiiCollectionAdd(input: $input) { id }
        }
    """
    result = _graphql(
        api_url,
        token,
        query,
        {
            "input": {
                "name": "ATI Interop Fake World",
                "description": "ATI-authored deterministic interop fixture",
                "include_inferences": False,
                # Public read: the throwaway fixture must be readable via
                # TAXII without wiring group roles/authorized members onto
                # the restricted consumer user.
                "taxii_public": True,
            }
        },
    )
    collection = result.get("taxiiCollectionAdd")
    if not isinstance(collection, dict) or not isinstance(collection.get("id"), str):
        raise RuntimeError(
            "OpenCTI does not expose taxiiCollectionAdd; create the collection "
            "in Data > Data sharing > TAXII collections and pass "
            "OPENCTI_TAXII_COLLECTION_ID instead"
        )
    return str(collection["id"])


def _ensure_user_token(
    api_url: str, token: str, token_file: str | None
) -> dict[str, Any]:
    """Create the restricted ATI user (idempotent) and one bearer token.

    The v2 seeding stage re-runs the same seeder entry point, so an
    existing ``{_ATI_USER}`` account is looked up first and reused instead
    of failing with ``User already exists``. Returns a bounded dict; the
    token VALUE is written to ``token_file`` (octal 0600) so the harness
    can use it without the seeder ever printing the credential to stdout
    or logs.
    """
    existing = _graphql(
        api_url,
        token,
        """
            query Users($search: String) {
              users(first: 50, search: $search) {
                edges { node { id name } }
              }
            }
        """,
        {"search": _ATI_USER},
    )
    found = [
        edge["node"]
        for edge in ((existing.get("users") or {}).get("edges") or [])
        if isinstance(edge, dict)
        and isinstance(edge.get("node"), dict)
        and edge["node"].get("name") == _ATI_USER
        and isinstance(edge["node"].get("id"), str)
    ]
    if found:
        user = found[0]
    else:
        user_query = """
            mutation CreateUser($input: UserAddInput!) {
              userAdd(input: $input) { id name }
            }
        """
        user = _graphql(
            api_url,
            token,
            user_query,
            {
                "input": {
                    "name": _ATI_USER,
                    "user_email": "ati-interop@example.invalid",
                    "password": _ATI_USER_PASSWORD,
                    "account_status": "active",
                }
            },
        ).get("userAdd")
    if not isinstance(user, dict) or not isinstance(user.get("id"), str):
        raise RuntimeError("OpenCTI user creation returned no usable identity")
    # OpenCTI 6.9 replaced authTokenAdd with an admin ``userEdit.tokenRenew``
    # that rotates and returns the user's API token.
    renewed = _graphql(
        api_url,
        token,
        """
            mutation RenewToken($id: ID!) {
              userEdit(id: $id) { tokenRenew { id api_token } }
            }
        """,
        {"id": user["id"]},
    )
    auth = (renewed.get("userEdit") or {}).get("tokenRenew") or {}
    if not isinstance(auth.get("api_token"), str):
        raise RuntimeError(
            "OpenCTI token renewal returned no API token; create a token for "
            f"{_ATI_USER} in Settings > Users and rerun the seeder"
        )
    if token_file:
        from pathlib import Path

        path = Path(token_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(auth["api_token"]))
        os.chmod(path, 0o600)
    return {"user_id": user["id"], "token_file": token_file or ""}


def _main() -> int:
    api_url = _require("OPENCTI_API_URL")
    admin_token = _require("OPENCTI_ADMIN_TOKEN")
    stage = os.environ.get("SEED_STAGE", "v1")
    bundle = (
        fake_world_bundle_v1()
        if stage == "v1"
        else {
            "type": "bundle",
            "objects": fake_world_update_v2(),
            "id": "bundle--interop-v2",
        }
    )
    connector_id = _discover_import_connector(api_url, admin_token)
    push_queue = _push_queue_name(api_url, admin_token, connector_id)
    if push_queue is None:
        # Documented OpenCTI platform convention for generated mailbox names;
        # the worker logs confirm the push queue of this connector is named
        # ``push_<connector-id>`` when ``config.push`` is not exposed.
        push_queue = f"push_{connector_id}"
    rabbit_api_url = os.environ.get("ATI_INTEROP_RABBITMQ_API_URL", "")
    rabbit_user = os.environ.get("ATI_INTEROP_RABBIT_USER", "")
    rabbit_password = os.environ.get("ATI_INTEROP_RABBIT_PASS", "")
    if rabbit_api_url and rabbit_user and rabbit_password:
        _wait_for_worker_mailbox(
            connector_id,
            push_queue,
            api_url=rabbit_api_url,
            user=rabbit_user,
            password=rabbit_password,
        )
    work_id = _upload_and_ask(api_url, admin_token, connector_id, bundle, stage)
    collection_id = _ensure_taxii_collection(api_url, admin_token)
    user_info = _ensure_user_token(
        api_url, admin_token, os.environ.get("ATI_INTEROP_TOKEN_FILE")
    )
    print(
        json.dumps(
            {
                "seed_stage": stage,
                "collection_id": collection_id,
                "user_id": user_info["user_id"],
                "token_file": user_info["token_file"],
                "work_id": work_id,
                "import_connector_id": connector_id,
                "push_queue": push_queue,
                "worker_mailbox_ready": True,
                "acknowledged": True,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(_main())
