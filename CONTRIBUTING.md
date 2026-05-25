# Contributing to Gauntlet

Gauntlet is the seam artifact: RAMPART assurance against an agent running
inside an OpenShell sandbox. Contributions are welcome — bug reports,
documentation improvements, and pull requests.

## Local development

### Install (unit tests only)

```bash
pip install -e ".[dev]"
pytest
```

Unit tests run on any host with Python 3.12+ and don't require RAMPART,
OpenShell, or Docker — they exercise the adapter contracts against the
fake adapters (`FakeSandbox`, `FakeAssurance`).

### Install (integration tests + live demo)

The integration tests and the acceptance demo require a running **OpenShell
gateway** with real Linux kernel features (Landlock + seccomp). Because
those features don't exist on macOS, we provide a one-command bootstrap
that provisions a **Lima-managed Ubuntu 24.04 VM** with everything
pre-installed: the gateway built from our NotionAlpha/OpenShell fork, the
gauntlet venv with all integration extras, and the canonical-agent Docker
image. See [`docs/m1.3.6-gateway-setup.md`](docs/m1.3.6-gateway-setup.md)
for the full walkthrough and rationale.

**Prerequisites:** macOS (Apple Silicon supported), Homebrew (`brew install lima`
if not already installed), ~25 GB free disk for the VM image and build
cache.

**One-command bootstrap (from the gauntlet repo root):**

```bash
bash scripts/lima/gateway-up.sh        # idempotent, ~15–25 min cold cache
```

This provisions the VM, builds OpenShell from the NotionAlpha/OpenShell
fork, installs the gauntlet venv at `~/work/gauntlet-venv` inside the VM
(with `[dev,integration]` extras + canonical-agent runtime deps), builds
the `gauntlet/canonical-agent:0.1.0` image in the VM's Docker, registers
the gateway at `https://127.0.0.1:17670`, and overrides the gateway's
bind-address to `0.0.0.0:17670` so sandbox containers can reach it.

**Verify:**

```bash
limactl shell openshell-gateway -- openshell status
# Expected: Gateway: openshell, Server: https://127.0.0.1:17670, Status: Connected
```

**Run the integration tests inside the VM:**

```bash
export HF_TOKEN=hf_...                  # token must have "Make calls to Inference Providers" scope
limactl shell openshell-gateway -- bash -lc \
  "cd $PWD && HF_TOKEN='$HF_TOKEN' ~/work/gauntlet-venv/bin/pytest -m integration"
```

Integration tests skip cleanly with a remediation message if any
precondition is missing.

**Daily lifecycle:**

```bash
limactl stop  openshell-gateway        # halt
limactl start openshell-gateway        # resume (gateway service auto-restarts)
limactl shell openshell-gateway        # interactive shell inside the VM
limactl delete openshell-gateway       # nuke (reclaim ~10 GB; re-run gateway-up.sh to recreate)
```

**Convenient alias** (add to your shell rc):

```bash
alias gv='limactl shell openshell-gateway -- ~/work/gauntlet-venv/bin/gauntlet'
```

**Custom gateway endpoint.** The openshell SDK respects `$OPENSHELL_GATEWAY`
inside the VM. The default Lima setup registers `https://127.0.0.1:17670`;
contributors with a non-default endpoint can `export OPENSHELL_GATEWAY=...`
inside their VM session without any code change.

### M1.4 acceptance demo

```bash
limactl shell openshell-gateway -- bash -lc \
  "cd $PWD && HF_TOKEN='$HF_TOKEN' ~/work/gauntlet-venv/bin/gauntlet run \
      --agent-image gauntlet/canonical-agent:0.1.0 \
      --policy policy/canonical-agent.yaml"
```

Runs the RAMPART XPIA scenario against the Qwen 3 canonical agent inside
an OpenShell sandbox with real Landlock + seccomp enforcement. The report
shows both the sandbox-layer verdict (OpenShell deny-by-default policy
active) and the model-layer verdict (RAMPART per-test findings)
independently.

## Tests

Unit tests run on every push (no install of openshell/rampart required):

```bash
pytest
```

The `byoc` marker covers the canonical-agent Dockerfile smoke; gated on
Docker + image present (inside the Lima VM):

```bash
limactl shell openshell-gateway -- bash -lc \
  "cd $PWD && ~/work/gauntlet-venv/bin/pytest -m byoc"
```

## Commit style

Conventional commits. PRs are squash-merged to `main`. Linear history.
