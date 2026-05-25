#!/usr/bin/env bash
# scripts/lima/gateway-up.sh
#
# One-command bootstrap for the Gauntlet OpenShell gateway VM.
#
# Run from the gauntlet repo root:
#     bash scripts/lima/gateway-up.sh
#
# What this does:
#   1. Verifies lima is installed (brew install lima if absent).
#   2. Substitutes the host gauntlet repo path into a per-host copy of the
#      Lima template (so the writable mount points at THIS clone, not at
#      ~/code/gauntlet which is the template's hardcoded default).
#   3. `limactl create` the openshell-gateway VM (idempotent — skipped if
#      it exists).
#   4. `limactl start`.
#   5. Inside the VM, runs `scripts/lima/install-openshell-from-fork.sh`
#      to build OpenShell from our fork and start the systemd user service.
#   6. Inside the VM, runs `scripts/lima/install-gauntlet-venv.sh` to set
#      up a Python venv with gauntlet + RAMPART + the fork's openshell SDK.
#   7. Smoke-checks: `openshell status` HEALTHY, `gauntlet --version` works.
#
# Idempotent: re-running on an existing VM re-runs only the install scripts.

set -euo pipefail

VM_NAME="${OPENSHELL_VM_NAME:-openshell-gateway}"
TEMPLATE_SRC="$(cd "$(dirname "$0")/.." && pwd)/../lima/openshell-gateway.yaml"
TEMPLATE_DST="${TMPDIR:-/tmp}/openshell-gateway.${USER}.yaml"
GAUNTLET_REPO_HOST="$(cd "$(dirname "$0")/../.." && pwd)"

info()  { printf "==> %s\n" "$*" >&2; }
error() { printf "ERROR: %s\n" "$*" >&2; exit 1; }

# 1. Lima present?
if ! command -v limactl >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    info "Lima not installed. Running: brew install lima"
    brew install lima
  else
    error "Lima not installed and brew not found. Install Lima from https://lima-vm.io/"
  fi
fi

# 2. Substitute host gauntlet repo path into a per-host template copy.
info "Templating Lima YAML with gauntlet repo path: $GAUNTLET_REPO_HOST"
# Replace the default `location: "~/code/gauntlet"` with the actual path.
# Lima accepts `~` only when literal; absolute paths work universally.
sed -e "s|location: \"~/code/gauntlet\"|location: \"${GAUNTLET_REPO_HOST}\"|" \
    "$TEMPLATE_SRC" > "$TEMPLATE_DST"

# 3. Create VM if it doesn't exist.
if ! limactl list --quiet | grep -qx "$VM_NAME"; then
  info "Creating Lima VM: $VM_NAME (first-time provisioning ~5 min)"
  limactl create --name="$VM_NAME" --tty=false "$TEMPLATE_DST"
else
  info "Lima VM '$VM_NAME' already exists — skipping create"
fi

# 4. Start (idempotent if already running).
info "Starting VM"
limactl start "$VM_NAME" --tty=false

# 5. Build OpenShell from our fork (inside the VM).
info "Provisioning: OpenShell built from NotionAlpha/OpenShell fork"
limactl shell "$VM_NAME" -- bash "${GAUNTLET_REPO_HOST}/scripts/lima/install-openshell-from-fork.sh"

# 6. Install Gauntlet venv (inside the VM).
info "Provisioning: Gauntlet venv + integration deps + fork's openshell Python SDK"
limactl shell "$VM_NAME" -- bash "${GAUNTLET_REPO_HOST}/scripts/lima/install-gauntlet-venv.sh"

# 7. Smoke checks.
info "Smoke: openshell status"
limactl shell "$VM_NAME" -- openshell status

info "Smoke: gauntlet --version"
limactl shell "$VM_NAME" -- ~/work/gauntlet-venv/bin/gauntlet --version

cat <<EOF

Gateway VM '$VM_NAME' is up.

Next:
  # Run Gauntlet's M1.4 acceptance demo (when M1.4 ships):
  limactl shell $VM_NAME -- ~/work/gauntlet-venv/bin/gauntlet run \\
    --agent-image gauntlet/canonical-agent:0.1.0 \\
    --policy policy/canonical-agent.yaml

Lifecycle:
  limactl stop $VM_NAME       # halt the VM
  limactl start $VM_NAME      # resume (gateway service auto-restarts)
  limactl delete $VM_NAME     # nuke entirely (~/.lima/$VM_NAME removed)
EOF
