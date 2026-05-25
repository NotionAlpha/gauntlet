#!/usr/bin/env bash
# scripts/lima/install-gauntlet-venv.sh
#
# Runs INSIDE the Lima VM. Sets up a Python venv at ~/work/gauntlet-venv
# with gauntlet + [dev,integration] extras + the canonical agent's runtime
# deps + the openshell Python SDK built from our fork.
#
# Assumes:
#   - The Lima VM is running.
#   - This gauntlet repo is mounted writable at the path passed in $PWD when
#     the script is invoked (gateway-up.sh does this automatically).
#   - install-openshell-from-fork.sh has already been run (the fork is at
#     ~/work/fork and the OpenShell deb is installed).

set -euo pipefail

VENV="${HOME}/work/gauntlet-venv"
FORK_DIR="${HOME}/work/fork"
GAUNTLET_REPO="${GAUNTLET_REPO:-$(pwd)}"

info() { printf "==> %s\n" "$*" >&2; }

# Detect the gauntlet repo — the script may be invoked from outside its dir.
# Walk up from this script's location to find pyproject.toml with name="gauntlet".
if [ ! -f "${GAUNTLET_REPO}/pyproject.toml" ] || ! grep -q '^name = "gauntlet"' "${GAUNTLET_REPO}/pyproject.toml"; then
  # Try to derive from script path: scripts/lima/install-gauntlet-venv.sh → repo root is ../..
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  CANDIDATE="$(cd "${SCRIPT_DIR}/../.." && pwd)"
  if [ -f "${CANDIDATE}/pyproject.toml" ] && grep -q '^name = "gauntlet"' "${CANDIDATE}/pyproject.toml"; then
    GAUNTLET_REPO="$CANDIDATE"
  else
    echo "ERROR: cannot locate gauntlet repo. Set GAUNTLET_REPO env var." >&2
    exit 1
  fi
fi
info "Using gauntlet repo at: ${GAUNTLET_REPO}"

# 1. Create venv if absent.
if [ ! -x "${VENV}/bin/python" ]; then
  info "Creating Python venv at ${VENV}"
  python3 -m venv "${VENV}"
fi

# 2. Install gauntlet [dev,integration] from the mounted repo.
info "pip install -e .[dev,integration] (editable; picks up host repo edits)"
"${VENV}/bin/pip" install -q -e "${GAUNTLET_REPO}[dev,integration]"

# 3. Install canonical agent runtime deps (flask + openai).
info "pip install -r agents/canonical/requirements.txt"
"${VENV}/bin/pip" install -q -r "${GAUNTLET_REPO}/agents/canonical/requirements.txt"

# 4. Replace the broken upstream Linux openshell wheel with our fork's build.
#    Why: PyPI ships `openshell` 0.0.47 with empty _proto/ on both Linux
#    platforms (proto stubs missing; SDK ImportErrors). Our fork's protos are
#    generated from the .proto sources via `mise run python:proto`.
info "Replace broken PyPI openshell with our fork's build"
"${VENV}/bin/pip" install -q 'maturin>=1.5,<2.0'

# TODO(openshell Fix 2): remove this regen step when the fork's wheel
# build includes the generated _pb2.* stubs (currently they are
# gitignored and produced only at build time).
# Generate proto stubs IN the fork's source tree.
cd "${FORK_DIR}"
if [ ! -f "python/openshell/_proto/sandbox_pb2.py" ]; then
  info "mise run python:proto"
  # python:proto needs the uv-managed venv for grpc_tools — sync first.
  mise exec -- uv sync --group dev
  mise run python:proto
fi

# Install the fork's openshell as editable (uses mise's Rust 1.95.0).
"${VENV}/bin/pip" uninstall -y -q openshell || true
info "pip install -e ${FORK_DIR} (uses mise's Rust 1.95.0)"
mise exec -- "${VENV}/bin/pip" install -q --no-build-isolation -e "${FORK_DIR}"

# 5. Verify.
info "Verifying full stack"
"${VENV}/bin/python" -c "
import openshell
from openshell._proto import sandbox_pb2
print('openshell SDK:', openshell.__file__)
print('SandboxPolicy proto loads:', sandbox_pb2.SandboxPolicy() is not None)
"
"${VENV}/bin/gauntlet" --version
info "Gauntlet venv ready at ${VENV}"
