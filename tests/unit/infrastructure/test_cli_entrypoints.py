# SPDX-License-Identifier: AGPL-3.0-only
"""PR 26B-2 installed CLI entrypoint tests (G26B2-CLI01..05).

Proves the installed package metadata exposes ``ati-geography-import`` and
``ati-geography-build``, that each resolves to its documented main, and that
``--help`` exits successfully without a database connection or network
access.
"""

from __future__ import annotations

from importlib import metadata
from pathlib import Path

import pytest

from agentic_threat_investigator.cli import geography_build_main, geography_import_main

_IMPORT_TARGET = "agentic_threat_investigator.cli:geography_import_main"
_BUILD_TARGET = "agentic_threat_investigator.cli:geography_build_main"


def _console_scripts() -> dict[str, metadata.EntryPoint]:
    """Return the installed console-script entry points by name."""
    return {
        entry.name: entry for entry in metadata.entry_points(group="console_scripts")
    }


def test_cli01_geography_import_registered() -> None:
    """G26B2-CLI01 ati-geography-import exists in the installed scripts."""
    scripts = _console_scripts()
    assert "ati-geography-import" in scripts
    assert scripts["ati-geography-import"].value == _IMPORT_TARGET


def test_cli02_geography_import_resolves_to_main() -> None:
    """G26B2-CLI02 it resolves to the documented geography_import_main."""
    scripts = _console_scripts()
    assert scripts["ati-geography-import"].load() is geography_import_main


def test_cli03_import_help_succeeds_offline() -> None:
    """G26B2-CLI03 importer --help exits 0 without DB or network access."""
    with pytest.raises(SystemExit) as excinfo:
        geography_import_main(["--help"])
    assert excinfo.value.code == 0


def test_cli04_geography_build_registered() -> None:
    """G26B2-CLI04 ati-geography-build is registered and resolves."""
    scripts = _console_scripts()
    assert "ati-geography-build" in scripts
    assert scripts["ati-geography-build"].value == _BUILD_TARGET
    assert scripts["ati-geography-build"].load() is geography_build_main


def test_cli05_build_help_succeeds_offline() -> None:
    """G26B2-CLI05 builder --help exits 0 without DB or network access."""
    with pytest.raises(SystemExit) as excinfo:
        geography_build_main(["--help"])
    assert excinfo.value.code == 0


def test_cli05b_build_refuses_output_and_validate_only(tmp_path: Path) -> None:
    """G26B2 the builder refuses mutually exclusive output modes with exit 2."""
    country = tmp_path / "countryInfo.txt"
    admin1 = tmp_path / "admin1CodesASCII.txt"
    cities = tmp_path / "cities1000.txt"
    country.write_text(
        "US\tUSA\t840\tUS\tUnited States\tWashington\t1\t1\tNA\t.us\tUSD\tDollar\t1\t\t\ten\t1\t\t\n",
        encoding="utf-8",
    )
    admin1.write_text("US.WA\tWashington\tWashington\t1\n", encoding="utf-8")
    cities.write_text(
        "1\tSeattle\tSeattle\tSeattle\t47.60621\t-122.33207\tP\tPPLA\tUS\t\tWA\t\t\t\t737015\t56\t56\tAmerica/Los_Angeles\t2011-06-22\n",
        encoding="utf-8",
    )
    common = [
        "--geonames-country-info",
        str(country),
        "--geonames-admin1",
        str(admin1),
        "--geonames-cities",
        str(cities),
    ]
    assert (
        geography_build_main(
            [*common, "--validate-only", "--output", str(tmp_path / "x.ndjson")]
        )
        == 2
    )
    assert geography_build_main([*common]) == 2
