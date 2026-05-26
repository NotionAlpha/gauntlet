# Changelog

All notable changes to Gauntlet are recorded here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-25

First public release.

Gauntlet is the seam between two open-source projects: it runs Microsoft RAMPART's pytest-native safety/security assurance suite against an agent that is itself running inside an NVIDIA OpenShell sandbox, and emits a two-layer report describing both the isolation guarantee and the assurance verdict.

### Added

- `gauntlet run` CLI — `--agent-image`, `--policy`, `--use-fakes`, `--dry-run`, `--output {text,json}`. One command runs the whole seam.
- `SandboxAdapter` interface with two implementations: `FakeSandbox` (scripted, no real deps) and `OpenShellSandbox` (wraps `openshell.Sandbox`).
- `AssuranceAdapter` interface with two implementations: `FakeAssurance` (scripted) and `RampartAssurance` (drives RAMPART's pytest collection against a target agent endpoint).
- `SandboxPolicy` — deny-by-default declarative policy mapped to OpenShell's filesystem / Landlock / network rule protos.
- Two-layer report renderer (text + JSON) — Sandbox section reports isolation kind and the deny-by-default boundary; Assurance section reports the upstream RAMPART verdict including findings.
- Output sanitizer — redacts host paths, bearer tokens, API key shapes before any string reaches a report.
- Lima-based reproducible gateway — `bash scripts/lima/gateway-up.sh` provisions a Linux VM with the OpenShell gateway from the fork (`OPENSHELL_FORK_REF=v0.0.47-gauntlet-2`) and a Python venv with gauntlet + integration deps.
- Canonical agent image (`gauntlet/canonical-agent:0.1.0`) — Qwen 3 over HuggingFace Inference Providers, Flask `/chat` + `/health`, two tools. Used by the real-demo command and as a default target for new contributors.
- Apache-2.0 licensed; CONTRIBUTING.md describes development setup; this CHANGELOG and SECURITY.md track the project's open-source posture.

### OpenShell SDK improvements landed upstream-of-public via the NotionAlpha fork

Gauntlet's M1.4 integration discovered nine workarounds against the upstream `openshell` Python SDK. Eight of those have been patched on `NotionAlpha/OpenShell` on the `gauntlet-bindings` branch (tagged `v0.0.47-gauntlet-2`) and Gauntlet pins to that tag. The fixes are documented as squash-friendly single-purpose commits intended for future upstream submission once NotionAlpha is vouched into the OpenShell contributor program.

Fixes added to the SDK (each one removes a workaround Gauntlet would otherwise have to carry):

1. Top-level proto aliases — `from openshell import sandbox_pb2, openshell_pb2, datamodel_pb2` works without reaching into `openshell._proto`.
2. Linux wheel includes the generated `_pb2.*` stubs (gitignore + maturin wheel build).
3. `Sandbox.expose_http(port)` — public convenience over the private `ExposeService` gRPC stub call.
4. `Sandbox.exec_detached(command)` + `ExecHandle` — non-blocking variant for long-running processes; thread + error capture managed by the SDK.
5. `openshell.policy_from_network_allow(destinations)` — builder that parses URL / host:port / bare-hostname / bracketed-IPv6 forms into a SandboxPolicy proto.
6. `openshell.http_client_for_sandbox(target)` — returns a requests.Session pre-configured with the active gateway's mTLS material; replaces a private auto-discovery helper Gauntlet was carrying.
7. `SandboxError` with a remediation hint instead of cryptic `FileNotFoundError` when no active gateway is configured.
8. `Sandbox(start_command=, start_env=)` convenience kwargs — auto-launches a detached process after `wait_ready`.

### Initial milestones

- **M1.1** — Gauntlet extracted from the prior advisory monorepo to its own public repository with history preserved.
- **M1.2** — Canonical Qwen 3 agent over HuggingFace Inference Providers.
- **M1.3** — Real RAMPART vs canonical agent, no sandbox.
- **M1.3.5** — OpenShell Python binding spike, decision recorded in `docs/m1.3.5-openshell-binding-spike.md`.
- **M1.3.6** — Lima-managed Ubuntu VM running the OpenShell gateway from the fork; reproducible via `scripts/lima/gateway-up.sh`.
- **M1.4** — Real OpenShell sandbox wired end-to-end; `gauntlet run --policy policy/canonical-agent.yaml` produces the two-layer report (sandbox isolated + RAMPART model-layer verdict). Squash-merged as `ac03210`.
- **M1.4 tightening** — `isolation_kind` field, daemon-thread error surfacing, sanitizer hex-id exemption. Squash-merged as `2232108`.
- **M1.4.5** — workaround-deletion pass after the eight SDK fixes land; `src/gauntlet/sandbox.py` shrinks 605 → 504 lines; `src/gauntlet/_openshell_mtls.py` is deleted. Squash-merged as `c6c1a00`.
- **M1.4.6** — proto-regen step removed from `scripts/lima/install-gauntlet-venv.sh` after the SDK wheel-packaging fix lands. Squash-merged as `de7eb78`.
- **v0.1.0** — release prep: PyPI metadata, trusted-publishing workflow, asciinema demo recording, CHANGELOG, SECURITY.

[0.1.0]: https://github.com/NotionAlpha/gauntlet/releases/tag/v0.1.0
