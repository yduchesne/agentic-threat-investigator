# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Loading, validating, merging, and safely logging configuration profiles."""

import importlib
import json
import logging
import os
import re
from collections.abc import Callable, Mapping, Sequence
from types import ModuleType
from typing import Any

Config = dict[str, Any]

_PROFILE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_SENSITIVE_MARKERS = (
    "secret",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "credentials",
    "auth",
    "cookie",
    "session",
)
_PACKAGE = "agentic_threat_investigator.config"
_LOGGER = logging.getLogger(__name__)
_PROCESS_ENV = os.environ


class ConfigProfileNotFoundError(RuntimeError):
    """Raised when the selected configuration profile does not exist."""


class ConfigModuleError(RuntimeError):
    """Raised when a configuration module does not meet its contract."""


def override(original_config: Config, override_config: Config) -> Config:
    """Return a shallow merge without modifying either input mapping."""
    merged = dict(original_config)
    merged.update(override_config)
    return merged


def _validate_config_module(module: ModuleType, module_name: str) -> Config:
    """Validate and return a profile module's configuration dictionary."""
    if not hasattr(module, "CONFIG"):
        raise ConfigModuleError(f"configuration module {module_name} has no CONFIG")
    config = module.CONFIG
    if not isinstance(config, dict):
        raise ConfigModuleError(
            f"configuration module {module_name} CONFIG must be a dict"
        )
    if any(not isinstance(key, str) for key in config):
        raise ConfigModuleError(
            f"configuration module {module_name} CONFIG keys must be strings"
        )
    return config


def _missing_profile_error(exc: ImportError, module_name: str) -> bool:
    """Determine whether an import error means the profile module is absent."""
    if isinstance(exc, ModuleNotFoundError):
        return exc.name == module_name
    return getattr(exc, "name", None) == module_name


def _load_module(
    module_name: str, import_module: Callable[[str], ModuleType]
) -> ModuleType:
    """Import a module, translating only an absent profile into a domain error."""
    try:
        return import_module(module_name)
    except (ModuleNotFoundError, ImportError) as exc:
        if not _missing_profile_error(exc, module_name):
            raise
        raise ConfigProfileNotFoundError(
            f"configuration profile module not found: {module_name}"
        ) from exc


def _redact_config(value: Any, key: str | None = None) -> Any:
    """Return a recursively copied value with sensitive values redacted."""
    if key is not None and any(marker in key.lower() for marker in _SENSITIVE_MARKERS):
        return "<redacted>"
    if isinstance(value, Mapping):
        return {
            item_key: _redact_config(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redact_config(item) for item in value]
    return value


def _log_config(profile: str, config: Config, modules: Sequence[str]) -> None:
    """Log bootstrap events and a deterministic redacted effective config."""
    _LOGGER.info("configuration.profile_selected profile=%s", profile)
    for module in modules:
        _LOGGER.info("configuration.module_loaded module=%s", module)
    rendered = json.dumps(_redact_config(config), sort_keys=True, default=repr)
    _LOGGER.info("configuration.loaded profile=%s config=%s", profile, rendered)


def load_config(
    env: Mapping[str, str] | None = None,
    import_module: Callable[[str], ModuleType] = importlib.import_module,
) -> Config:
    """Load and merge the selected profile using an injectable environment/loader."""
    environment = _PROCESS_ENV if env is None else env
    selected = environment.get("ATI_CONFIG_PROFILE", "").strip() or "default"
    if _PROFILE_PATTERN.fullmatch(selected) is None:
        raise ValueError(
            "ATI_CONFIG_PROFILE must match the profile grammar ^[a-z][a-z0-9_]*$"
        )

    default_name = f"{_PACKAGE}.config_default"
    default_module = _load_module(default_name, import_module)
    default_config = _validate_config_module(default_module, default_name)
    if selected == "default":
        result = dict(default_config)
        _log_config(selected, result, (default_name,))
        return result

    profile_name = f"{_PACKAGE}.config_{selected}"
    profile_module = _load_module(profile_name, import_module)
    profile_config = _validate_config_module(profile_module, profile_name)
    result = override(default_config, profile_config)
    _log_config(selected, result, (default_name, profile_name))
    return result
