#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
#
# local-port-config.sh -- shared local host-port resolution (PR 39-10).
#
# Sourced by ATI-owned local entry points (start.sh) so Compose publication,
# Redpanda advertisement, host probes, the endpoint summary, and the default
# browser origins all agree on one effective host port per service.
#
# This file is data-only and side-effect free when sourced. It never executes
# .env as shell: values are read with the same safe process-environment >
# .env > default precedence already used by start.sh, and only key=value
# lines are read.
#
# ATI_PORT_PREFIX (optional, exactly one digit 1..5) namespaces host-published
# ports only:
#
#   derived_host_port = ATI_PORT_PREFIX * 10000 + (default_host_port % 10000)
#
# Explicit ATI_<SERVICE>_HOST_PORT values always win and are never prefixed.
# Container ports, Compose-network DNS/service discovery, and all in-container
# endpoints never change. Absent/empty ATI_PORT_PREFIX keeps the standard
# defaults. Invalid values fail before any Compose mutation.

# get_env <key> [default]: resolve a value with the same precedence Compose
# uses: process environment > `ATI_ENV_FILE` (default `.env`) > documented
# default. Empty service-specific values count as unspecified (an empty
# process value falls through to the file and then to the default).
# podman-compose 1.0.6 does not honour COMPOSE_PROJECT_NAME from .env, so the
# default project name is derived exactly the way podman-compose derives it
# (directory basename).
get_env() {
  local key="$1" default="${2:-}" value=""
  if [[ -n "${!key:-}" ]]; then
    printf '%s\n' "${!key}"
    return 0
  fi
  if [[ -f "${ATI_ENV_FILE:-.env}" ]]; then
    value=$(sed -n "s/^${key}=//p" "${ATI_ENV_FILE:-.env}" | tail -n 1)
    if [[ -n "$value" ]]; then
      printf '%s\n' "$value"
      return 0
    fi
  fi
  printf '%s\n' "$default"
}

# validate_port_prefix <prefix>: 0 when absent/empty or exactly one digit
# 1..5; nonzero (with a concise message on stderr) otherwise. Rejects 0,
# negatives, multi-digit, whitespace-padded, and nonnumeric values.
validate_port_prefix() {
  local prefix="$1"
  [[ -z "$prefix" ]] && return 0
  if [[ ! "$prefix" =~ ^[0-9]$ ]]; then
    printf 'error: ATI_PORT_PREFIX must be a single digit 1..5 (got %q)\n' "$prefix" >&2
    return 1
  fi
  if ((10#$prefix < 1 || 10#$prefix > 5)); then
    printf 'error: ATI_PORT_PREFIX must be between 1 and 5 (got %q)\n' "$prefix" >&2
    return 1
  fi
  return 0
}

# validate_host_port <name> <value>: 0 when value is a numeric TCP port in
# 1..65535; nonzero (with a concise message on stderr) otherwise.
validate_host_port() {
  local name="$1" value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    printf 'error: %s must be a numeric TCP port 1..65535 (got %q)\n' "$name" "$value" >&2
    return 1
  fi
  if ((10#$value < 1 || 10#$value > 65535)); then
    printf 'error: %s must be between 1 and 65535 (got %q)\n' "$name" "$value" >&2
    return 1
  fi
  return 0
}

# derive_prefixed_port <prefix> <default_port>: print the namespaced host
# port. The numeric rule (rather than string concatenation) keeps five-digit
# defaults such as Jaeger's 16686 valid: prefix 5 -> 56686, never 516686.
derive_prefixed_port() {
  local prefix="$1" default_port="$2"
  printf '%s\n' "$((10#$prefix * 10000 + 10#$default_port % 10000))"
}

# resolve_host_port <name> <default_port>: print the effective host port for
# one service using the required precedence:
#   non-empty explicit ATI_<SERVICE>_HOST_PORT -> use it unchanged
#   else non-empty ATI_PORT_PREFIX             -> prefix * 10000 + default % 10000
#   else                                       -> documented default
resolve_host_port() {
  local name="$1" default_port="$2" prefix explicit derived
  prefix=$(get_env ATI_PORT_PREFIX "")
  validate_port_prefix "$prefix" || return 1
  explicit=$(get_env "$name" "")
  if [[ -n "$explicit" ]]; then
    validate_host_port "$name" "$explicit" || return 1
    printf '%s\n' "$explicit"
    return 0
  fi
  if [[ -n "$prefix" ]]; then
    derived=$(derive_prefixed_port "$prefix" "$default_port")
    validate_host_port "$name" "$derived" || return 1
    printf '%s\n' "$derived"
    return 0
  fi
  printf '%s\n' "$default_port"
}

# resolve_local_ports: validate and export every host-published service port
# plus the default browser origins. On any invalid input it prints a concise
# error and returns nonzero; callers must fail before Compose mutation.
#
# When a browser origin is not explicitly configured it follows the effective
# frontend/API host ports, so prefix 5 yields http://localhost:58080 and
# http://localhost:58000. Explicit ATI_PUBLIC_BASE_URL / ATI_WEB_BASE_URL
# values remain authoritative.
resolve_local_ports() {
  local spec var default value prefix public_base web_base
  prefix=$(get_env ATI_PORT_PREFIX "")
  validate_port_prefix "$prefix" || return 1

  # Service host-port variables and their standard (unprefixed) defaults, in
  # the order used by the documentation and tests.
  for spec in \
    "ATI_POSTGRES_HOST_PORT:5432" \
    "ATI_REDPANDA_HOST_PORT:9092" \
    "ATI_API_HOST_PORT:8000" \
    "ATI_FRONTEND_HOST_PORT:8080" \
    "ATI_GRAFANA_HOST_PORT:3000" \
    "ATI_PROMETHEUS_HOST_PORT:9090" \
    "ATI_JAEGER_HOST_PORT:16686"; do
    var="${spec%%:*}"
    default="${spec#*:}"
    value=$(resolve_host_port "$var" "$default") || return 1
    export "${var}=${value}"
  done

  public_base=$(get_env ATI_PUBLIC_BASE_URL "")
  if [[ -z "$public_base" ]]; then
    public_base="http://localhost:${ATI_FRONTEND_HOST_PORT}"
  fi
  export ATI_PUBLIC_BASE_URL="$public_base"

  web_base=$(get_env ATI_WEB_BASE_URL "")
  if [[ -z "$web_base" ]]; then
    web_base="http://localhost:${ATI_API_HOST_PORT}"
  fi
  export ATI_WEB_BASE_URL="$web_base"
  return 0
}
