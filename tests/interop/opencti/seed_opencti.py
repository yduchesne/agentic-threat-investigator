#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""OpenCTI fake-world seeder of the interoperability harness (PR 33E section 10.4).

Seeds the ATI-authored deterministic STIX fake world into a real OpenCTI
instance through OpenCTI's standard automation surface (GraphQL):
``importBundle`` ingests the STIX bundle; a TAXII 2.1 collection is created
(or re-used from ``OPENCTI_TAXII_COLLECTION_ID``) so the fixture is served
through OpenCTI's real TAXII 2.1 server, and a restricted user with a bearer
token is created for ATI's authenticated read.

The seeder performs **no** TAXII acquisition and no ATI persistence; it only
bootstraps the external OpenCTI side deterministically. If ``importBundle``
or ``taxiiCollectionAdd`` do not exist on the pinned OpenCTI version, the
seeder fails loudly rather than using undocumented/private endpoints (STOP
condition 19).

Environment:

  OPENCTI_API_URL      e.g. http://opencti:8080
  OPENCTI_ADMIN_TOKEN  admin bearer token (Authorization header only)
  OPENCTI_TAXII_COLLECTION_ID  optional pre-created collection id

Output: prints a bounded JSON line with the collection id, the restricted
user token id, and the seed acknowledgement.
"""

from __future__ import annotations

import json
import os
import sys
import time
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


def _import_bundle(
    api_url: str, token: str, bundle: dict[str, Any], stage: str
) -> None:
    """Ingest one STIX bundle through OpenCTI 6.9's import connector.

    OpenCTI 6.9 removed the classic ``importBundle`` mutation; a bundle is
    imported by uploading it as a file through the GraphQL multipart
    ``Upload!`` scalar and asking the built-in ``INTERNAL_IMPORT_FILE``
    connector for the import job (the same flow the 6.9 UI uses). The
    connector materializes the STIX objects asynchronously.
    """
    # Resolve the id of the registered STIX bundle import connector, retrying
    # through the connector's registration window (it registers a short while
    # after the platform reports healthy).
    connector_id = None
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
            break
        time.sleep(10)
    if connector_id is None:
        raise RuntimeError(
            "no INTERNAL_IMPORT_FILE connector is registered; add the "
            "opencti-import-stix connector service and wait for its registration"
        )

    boundary = uuid4().hex
    operations = json.dumps(
        {
            "query": (
                "mutation UploadAndAskJobImport($file: Upload!, "
                "$connectors: [ConnectorWithConfig!]) { "
                "uploadAndAskJobImport(file: $file, connectors: $connectors) "
                "{ id } }"
            ),
            "variables": {
                "file": None,
                "connectors": [{"connectorId": connector_id}],
            },
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
    imported = payload.get("data", {}).get("uploadAndAskJobImport")
    if not isinstance(imported, dict) and stage == "v1":
        raise RuntimeError("OpenCTI uploadAndAskJobImport returned no acknowledgement")


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
    """Create the restricted ATI user and one bearer token.

    Returns a bounded dict; the token VALUE is written to ``token_file``
    (octal 0600) so the harness can use it without the seeder ever printing
    the credential to stdout or logs.
    """
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
    _import_bundle(api_url, admin_token, bundle, stage)
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
                "acknowledged": True,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(_main())
