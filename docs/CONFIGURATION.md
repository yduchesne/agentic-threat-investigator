# Agentic Threat Investigator — Configuration

## Table of contents

- [Purpose](#purpose)
- [Package layout](#package-layout)
- [Profile selection](#profile-selection)
- [Configuration modules](#configuration-modules)
- [Configuration value types](#configuration-value-types)
- [`override`](#override)
- [`load_config`](#load_config)
- [Profile name validation](#profile-name-validation)
- [Missing profiles](#missing-profiles)
- [Configuration module validation](#configuration-module-validation)
- [Logging](#logging)
- [Sensitive-value redaction](#sensitive-value-redaction)
- [Nested values](#nested-values)
- [Environment variables and configuration values](#environment-variables-and-configuration-values)
- [Configuration loading lifecycle](#configuration-loading-lifecycle)
- [Process consistency](#process-consistency)
- [Authentication settings](#authentication-settings)
- [Configuration and secrets](#configuration-and-secrets)
- [Testing requirements](#testing-requirements)
- [Implementation invariants](#implementation-invariants)
- [Secret resolution](#secret-resolution)
- [SecretsResolver contract](#secretsresolver-contract)

## Purpose

ATI uses source-controlled configuration profiles to define runtime settings for different execution environments.

Configuration is kept under the backend `config` subpackage. A profile is selected with the `ATI_CONFIG_PROFILE` environment variable. The profile mechanism is deliberately simple, deterministic, testable, and independent of the application framework.

The core rule is:

> ATI always starts from the default configuration. If a non-default configuration profile is selected, that profile overrides the default configuration. The resulting merged configuration is the application configuration for that process.

## Package layout

```text
src/agentic_threat_investigator/config/
├── __init__.py
├── config_default.py
├── config_local.py
├── config_dev.py
├── config_prod.py
├── config_utils.py
└── settings.py
```

Additional profiles may use the same naming convention:

```text
config_<profile>.py
```

The strings `default`, `local`, `dev`, `prod`, and similar values are called **configuration profiles**.

## Profile selection

The desired profile is selected through:

```text
ATI_CONFIG_PROFILE
```

Examples:

```bash
ATI_CONFIG_PROFILE=local
ATI_CONFIG_PROFILE=dev
ATI_CONFIG_PROFILE=prod
```

If `ATI_CONFIG_PROFILE` is absent or blank, ATI uses `default`.

The default configuration is always loaded first. If the selected profile is `default`, no additional module is loaded. Otherwise:

```text
default CONFIG
      +
selected profile CONFIG
      ↓
final CONFIG
```

A profile overrides only the settings it explicitly defines.

Profiles do not implicitly inherit from other non-default profiles.

## Configuration modules

Every configuration profile module must expose a module-level variable named exactly:

```python
CONFIG
```

Example:

```python
CONFIG: dict = {
    "db_batch_size": 100,
}
```

A profile file should contain configuration data and only minimal code required to construct that data.

## Configuration value types

Configuration values are not limited to strings. For example:

```python
CONFIG: dict[str, object] = {
    "db_batch_size": 100,
    "feature_enabled": True,
    "provider_timeout_seconds": 10.0,
}
```

Accordingly, configuration utilities should use value typing compatible with heterogeneous configuration values rather than `Dict[str, str]`.

Conceptually:

```python
from typing import Any

Config = dict[str, Any]
```

## `override`

`config_utils.py` provides:

```python
def override(
    original_config: Config,
    override_config: Config,
) -> Config:
    ...
```

The function:

1. creates a new dictionary;
2. copies every setting from `original_config`;
3. applies every setting from `override_config`;
4. returns the new dictionary.

Values in `override_config` replace values having the same key in `original_config`.

Neither argument is mutated.

The v0.1 override operation is **shallow**. Nested dictionaries are replaced as values rather than recursively merged unless a future explicit requirement changes this contract.

## `load_config`

`config_utils.py` also provides `load_config`.

Conceptually:

```python
import os
from collections.abc import Mapping

def load_config(
    env: Mapping[str, str] = os.environ,
    import_module: Callable[[str], ModuleType] = importlib.import_module,
) -> Config:
    ...
```

The supplied mapping represents environment variables.

The function performs:

```text
read ATI_CONFIG_PROFILE
        ↓
missing / blank?
        ├── yes → profile = "default"
        └── no  → normalize and validate profile
        ↓
load config_default.CONFIG
        ↓
profile == "default"?
        ├── yes → return copy of default CONFIG
        └── no
              ↓
      load config_<profile>.CONFIG
              ↓
      override(default, profile)
              ↓
      log selected profile and redacted final configuration
              ↓
      return merged configuration
```

The environment mapping is injectable so configuration loading can be tested without mutating process-global environment state.

## Profile name validation

`ATI_CONFIG_PROFILE` must not be treated as an arbitrary Python module path.

Before dynamic import, validate the profile name against a restricted grammar, initially:

```text
^[a-z][a-z0-9_]*$
```

Valid examples:

```text
default
local
dev
prod
test
ci
staging_us
```

Invalid examples:

```text
../prod
ati.other.module
config-prod
/dev/null
```

The implementation constructs the module name internally as:

```text
agentic_threat_investigator.config.config_<profile>
```

This prevents path traversal or arbitrary module-import behavior through `ATI_CONFIG_PROFILE`.

## Missing profiles

If the selected profile module does not exist, configuration loading fails immediately.

ATI must not silently fall back to `default`.

A dedicated exception is preferred, for example:

```python
class ConfigProfileNotFoundError(RuntimeError):
    ...
```

Import errors raised *inside* an existing configuration module must not be misreported as “profile not found.” They represent genuine configuration-module failures and should retain their underlying cause.

## Configuration module validation

After importing a profile module, ATI verifies that:

1. the module exposes `CONFIG`;
2. `CONFIG` is a dictionary;
3. configuration keys are strings.

A malformed configuration module must fail startup rather than being partially accepted.

## Logging

Configuration loading must be observable.

At startup ATI logs at least:

- the selected configuration profile;
- whether the default profile alone or default-plus-override was loaded;
- the loaded profile module name;
- the final effective configuration after sensitive-value redaction.

Example conceptual events:

```text
configuration.profile_selected profile=dev
configuration.module_loaded module=ati.config.config_default
configuration.module_loaded module=ati.config.config_dev
configuration.loaded profile=dev
```

Configuration logging must work during early startup before the full application logging subsystem is necessarily initialized. Use standard Python logging and avoid dependencies on application services.

The final configuration should be logged in a deterministic form suitable for debugging.

## Sensitive-value redaction

ATI must never knowingly log sensitive configuration values.

Before logging effective configuration, classify keys case-insensitively using a conservative set of sensitive-name markers.

Initial markers should include at least:

```text
secret
password
passwd
token
api_key
apikey
private_key
credential
credentials
auth
cookie
session
```

If a configuration key contains one of these markers, replace its value in logs with:

```text
<redacted>
```

Examples:

```text
db_password       → <redacted>
THREATFOX_API_KEY → <redacted>
langsmith_token   → <redacted>
client_secret     → <redacted>
private_key_path  → <redacted>
```

The original in-memory configuration value is not modified. Redaction applies only to the representation sent to logs.

The marker list is intentionally conservative.

## Nested values

If configuration values contain nested mappings or sequences, redaction must recurse through them rather than checking only top-level keys.

For example:

```python
{
    "provider": {
        "username": "ati",
        "password": "secret-value",
    }
}
```

must be logged as:

```python
{
    "provider": {
        "username": "ati",
        "password": "<redacted>",
    }
}
```

## Environment variables and configuration values

`ATI_CONFIG_PROFILE` selects the source-controlled profile.

Profile values are passed as constructor values to the typed `Settings` bridge
(`settings_from_config`), so a profile key pins that setting for the process.
Fields not defined by a profile remain injectable through `ATI_*` environment
variables (or `.env`) according to the typed settings model. Profiles never
contain secrets; therefore `config_default` pins only stable,
non-deployment-tunable values and deployment values such as credentials remain
externally provisioned. `get_settings()` loads this bridge once during process
bootstrap and returns the cached settings instance.

The optional `import_module` argument to `load_config` defaults to
`importlib.import_module` and is an injectable test seam for malformed or
missing modules. The normal `load_config(env)` call shape is unchanged.

## Configuration loading lifecycle

Configuration should be loaded once during process bootstrap and then injected into application components.

Application/domain code should not repeatedly call `load_config()` or access `os.environ` directly.

Preferred flow:

```text
process startup
    ↓
load_config()
    ↓
validate application configuration
    ↓
construct dependencies
    ↓
run API / worker / scheduler / migration process
```

## Process consistency

The same profile mechanism applies to ATI processes including:

- API;
- worker;
- scheduler;
- migration tooling where application configuration is required.

Each process receives `ATI_CONFIG_PROFILE` through its environment.

## Authentication settings

The local authentication profile may define the following settings (environment
variables use the corresponding `ATI_` prefix):

- `ATI_SESSION_ABSOLUTE_EXPIRY_SECONDS` (default `28800`);
- `ATI_SESSION_IDLE_TIMEOUT_SECONDS` (optional);
- `ATI_SESSION_COOKIE_SECURE` (set `true` when served over HTTPS);
- `ATI_LOGIN_RATE_LIMIT_MAXIMUM` and `ATI_LOGIN_RATE_LIMIT_WINDOW_SECONDS`;
- `ATI_PUBLIC_BASE_URL` (default `http://localhost:8000`; must match the externally visible scheme, host, and port and is validated at startup);
- `ATI_BOOTSTRAP_ADMIN_USERNAME` and `ATI_BOOTSTRAP_ADMIN_PASSWORD`.

Bootstrap credentials are used only when the database contains no users. They
are hashed immediately and changing these settings cannot reset an existing
account. Password values are always redacted from configuration logging.

## Configuration and secrets

Source-controlled profile modules must not contain actual credentials or secrets.

Files such as:

```text
config_default.py
config_dev.py
config_prod.py
```

may define defaults, names, URLs, limits, feature settings, and references to secret mechanisms, but repository-committed code must not contain production secrets.

Secret provisioning remains an external runtime concern.

## Testing requirements

Unit tests for `override` must cover:

- empty dictionaries;
- no overlapping keys;
- overlapping keys;
- immutability of both inputs;
- heterogeneous values;
- shallow replacement semantics.

Unit tests for `load_config` must cover:

- missing `ATI_CONFIG_PROFILE`;
- blank profile;
- explicit `default`;
- valid profile override;
- missing profile module;
- invalid profile name;
- module without `CONFIG`;
- `CONFIG` having the wrong type;
- import failure inside an existing profile module;
- deterministic merging.

Logging/redaction tests must cover:

- selected-profile logging;
- effective-config logging;
- case-insensitive sensitive names;
- all supported sensitive-name markers;
- nested mappings;
- nested lists/sequences;
- confirmation that the original configuration is not modified.

## Implementation invariants

1. `default` is always the base profile.
2. A non-default profile overrides only `default`.
3. `ATI_CONFIG_PROFILE` selects the profile.
4. Missing or blank `ATI_CONFIG_PROFILE` means `default`.
5. An unknown profile is an error; no silent fallback occurs.
6. Profile names cannot specify arbitrary import paths.
7. Every profile module exposes `CONFIG`.
8. `override` returns a new dictionary and does not mutate its inputs.
9. Effective configuration is logged with sensitive values redacted.
10. Actual secrets are never committed to configuration profile modules.
11. Application components receive loaded configuration through bootstrap/dependency construction rather than independently reading environment variables.

## Secret resolution

Configuration profiles and secret acquisition are separate concerns. Source-controlled profile modules must not contain secret values.

ATI defines a `SecretsResolver` ABC for resolving secrets by logical/name reference. The only required v0.1 implementation is `EnvVarSecretsResolver`, which obtains secret values from the process environment. Application bootstrap/composition resolves required secrets and passes the resulting credentials to providers or infrastructure components; providers should not depend directly on a SecretsResolver.

Configuration may contain a secret reference such as `ATI_ABUSEIPDB_API_KEY`, but resolved secret values must never be included in effective-configuration logging. Missing required secrets fail clearly at bootstrap. Future resolvers may target managed secret stores without changing provider contracts.


## SecretsResolver contract

The secret-resolution abstraction is intentionally small and independent of configuration-profile loading.

Conceptually:

```python
from abc import ABC, abstractmethod

class SecretsResolver(ABC):
    @abstractmethod
    def get(self, name: str) -> str | None:
        ...

    def require(self, name: str) -> str:
        value = self.get(name)
        if value is None:
            raise SecretNotFoundError(name)
        return value
```

The only v0.1 implementation is:

```python
import os
from collections.abc import Mapping

class EnvVarSecretsResolver(SecretsResolver):
    def __init__(self, env: Mapping[str, str] = os.environ):
        self._env = env

    def get(self, name: str) -> str | None:
        return self._env.get(name)
```

The injectable environment mapping is required for deterministic unit testing without mutating process-global environment state.

A configuration profile stores only a secret reference/name, never the secret value itself. For example:

```python
CONFIG: dict = {
    "abuseipdb": {
        "enabled": True,
        "api_key_secret": "ATI_ABUSEIPDB_API_KEY",
    },
}
```

During bootstrap/composition:

```text
loaded configuration
      +
SecretsResolver
      ↓
resolve required secret reference
      ↓
construct provider/infrastructure component
```

Prefer:

```python
AbuseIPDBProvider(
    api_key=secrets.require(config["abuseipdb"]["api_key_secret"])
)
```

over passing `SecretsResolver` into the provider. Providers consume resolved credentials and remain independent of secret-storage infrastructure.

Future implementations may include managed secret stores (for example cloud secret managers or Vault), but those are not v0.1 requirements and must not alter provider contracts.

Secret reference names may appear in configuration diagnostics. Resolved values must never be logged. Missing required secrets fail clearly during bootstrap.
