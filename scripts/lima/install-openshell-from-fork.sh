#!/usr/bin/env bash
# scripts/lima/install-openshell-from-fork.sh
#
# Runs INSIDE the Lima VM. Builds OpenShell from the NotionAlpha/OpenShell
# fork and installs the deb locally, starting the user-scope systemd gateway
# service. Idempotent — re-running on an already-provisioned VM is a no-op
# for completed steps.
#
# Pinned to OpenShell SHA recorded by the M1.3.5 spike (currently
# 686b24d, upstream parity).

set -euo pipefail

OPENSHELL_FORK_URL="${OPENSHELL_FORK_URL:-https://github.com/NotionAlpha/OpenShell.git}"
OPENSHELL_FORK_SHA="${OPENSHELL_FORK_SHA:-686b24d}"
FORK_DIR="${HOME}/work/fork"
MISE_VERSION="${MISE_VERSION:-v2026.5.15}"

info() { printf "==> %s\n" "$*" >&2; }

# 1. Install apt-level build deps (clang, libz3-dev, etc) per the canonical
#    OpenShell CI Dockerfile.
info "Installing apt build deps"
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  ca-certificates curl git build-essential clang libclang-dev libz3-dev \
  pkg-config libssl-dev musl-tools cmake socat unzip xz-utils jq rsync zstd \
  python3-venv rustc cargo

# 2. Install mise (build orchestrator) if absent.
if ! command -v mise >/dev/null 2>&1; then
  info "Installing mise ${MISE_VERSION}"
  ARCH="$(uname -m)"
  case "$ARCH" in
    aarch64) MISE_ARCH=linux-arm64 ;;
    x86_64)  MISE_ARCH=linux-x64 ;;
    *) echo "unsupported arch: $ARCH"; exit 1 ;;
  esac
  sudo curl -fsSL -o /usr/local/bin/mise \
    "https://github.com/jdx/mise/releases/download/${MISE_VERSION}/mise-${MISE_VERSION}-${MISE_ARCH}"
  sudo chmod +x /usr/local/bin/mise
fi

# 3. Clone (or update) the fork at the pinned SHA.
mkdir -p "$(dirname "$FORK_DIR")"
if [ ! -d "$FORK_DIR/.git" ]; then
  info "Cloning fork: $OPENSHELL_FORK_URL"
  git clone --quiet "$OPENSHELL_FORK_URL" "$FORK_DIR"
fi

cd "$FORK_DIR"
git fetch --quiet origin
info "Checking out pinned SHA: $OPENSHELL_FORK_SHA"
git checkout --quiet "$OPENSHELL_FORK_SHA"

# 4. Install Rust toolchain + protoc + sccache (etc.) per the fork's mise.toml.
info "mise install (Rust 1.95.0 + protoc + sccache, first-time ~5 min)"
mise trust --yes
mise install

# 5. Build OpenShell + install the deb + start the systemd user service.
#    This task ALSO registers https://127.0.0.1:17670 as the active gateway.
if openshell status 2>/dev/null | grep -q "Connected"; then
  info "OpenShell gateway already installed and healthy — skipping rebuild"
else
  info "Building OpenShell from source + installing deb (cold cache ~15 min)"
  mise run package:deb:install
fi

info "OpenShell installed. Verifying:"
openshell status | head -5
