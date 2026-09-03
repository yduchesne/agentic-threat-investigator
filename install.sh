#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Agentic Threat Investigator contributors
# SPDX-License-Identifier: AGPL-3.0-only
set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SUDO=()
if [[ ${EUID} -ne 0 ]]; then command -v sudo >/dev/null || { echo 'sudo is required to install system packages.' >&2; exit 1; }; SUDO=(sudo); fi

have() { command -v "$1" >/dev/null 2>&1; }
install_packages() {
  local manager=$1; shift
  [[ $# -eq 0 ]] && return 0
  case "$manager" in
    apt-get) "${SUDO[@]}" apt-get update; "${SUDO[@]}" apt-get install -y "$@" ;;
    dnf) "${SUDO[@]}" dnf install -y "$@" ;;
    yum) "${SUDO[@]}" yum install -y "$@" ;;
    zypper) "${SUDO[@]}" zypper --non-interactive install "$@" ;;
    pacman) "${SUDO[@]}" pacman -Sy --needed --noconfirm "$@" ;;
    apk) "${SUDO[@]}" apk add "$@" ;;
    *) echo "Unsupported package manager: $manager" >&2; exit 1 ;;
  esac
}

if have apt-get; then PM=apt-get; PKGS=(python3 python3-venv python3-dev build-essential curl git nodejs npm podman podman-compose)
elif have dnf; then PM=dnf; PKGS=(python3 python3-devel gcc gcc-c++ make curl git nodejs npm podman podman-compose)
elif have yum; then PM=yum; PKGS=(python3 python3-devel gcc gcc-c++ make curl git nodejs npm podman podman-compose)
elif have zypper; then PM=zypper; PKGS=(python3 python3-devel gcc gcc-c++ make curl git nodejs npm podman podman-compose)
elif have pacman; then PM=pacman; PKGS=(python python-pip base-devel curl git nodejs npm podman podman-compose)
elif have apk; then PM=apk; PKGS=(python3 py3-pip py3-virtualenv gcc musl-dev libffi-dev curl git nodejs npm podman podman-compose)
else echo 'No supported Linux package manager found (apt, dnf, yum, zypper, pacman, or apk).' >&2; exit 1; fi
install_packages "$PM" "${PKGS[@]}"

# Podman is daemonless, so no system service needs to be enabled or started.
if ! have podman; then
  echo 'Podman installation completed, but the podman command is unavailable.' >&2
  exit 1
fi
podman info >/dev/null 2>&1 || {
  echo 'Podman is installed but could not initialize its runtime.' >&2
  exit 1
}
if ! podman compose version >/dev/null 2>&1 && ! have podman-compose; then
  echo 'Podman Compose is required but was not found.' >&2
  exit 1
fi

if have node; then
  NODE_VERSION=$(node --version | sed 's/^v//')
  if [[ "$(printf '%s\n' '20.19.0' "$NODE_VERSION" | sort -V | head -n1)" != '20.19.0' ]]; then
    echo "Node.js >=20.19.0 is required; found v$NODE_VERSION." >&2
    echo 'Install a current Node.js LTS release and rerun install.sh.' >&2
    exit 1
  fi
else
  echo 'Node.js is required for the frontend but was not installed.' >&2
  exit 1
fi

if ! have uv; then
  curl --proto '=https' --tlsv1.2 -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi
have uv || { echo 'uv installation succeeded but uv is not on PATH; restart your shell and retry.' >&2; exit 1; }

cd "$ROOT_DIR"
uv sync --locked
if have npm && [[ -f frontend/package-lock.json ]]; then (cd frontend && npm ci); fi
if have pre-commit; then pre-commit install; else uv run pre-commit install; fi
printf 'Installation complete. Run ./build.sh --check to validate the project.\n'
