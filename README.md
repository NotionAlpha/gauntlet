# Gauntlet

**The seam artifact.** RAMPART assurance executed against an agent running inside OpenShell isolation — one command.

Part of the [NotionAlpha OSS AI Lab](https://notionalpha.com).

---

## What this is

Gauntlet is a small open CLI tool that composes two open-source projects that neither vendor will compose for you:

| Upstream project                                 | Vendor    | License    | Role in Gauntlet                                                                         |
| ------------------------------------------------ | --------- | ---------- | ---------------------------------------------------------------------------------------- |
| [RAMPART](https://github.com/microsoft/RAMPART)  | Microsoft | MIT        | Assurance, Evaluation & Forensics — pytest-native safety/security test execution         |
| [OpenShell](https://github.com/NVIDIA/OpenShell) | NVIDIA    | Apache-2.0 | Runtime Isolation & Governance — kernel-level sandbox isolation for the agent under test |

Neither RAMPART nor Gauntlet is a competitor to either of these projects. Gauntlet is the seam between them: it starts an OpenShell sandbox, runs RAMPART's assurance tests against the agent executing inside that sandbox, and reports the combined result. Built on, not competing with, RAMPART and OpenShell.

This is the first concrete proof that the NotionAlpha OSS AI Lab reference architecture is real, running code — not a diagram.

---

## Lineage

Gauntlet is the cross-vendor seam artifact of the NotionAlpha OSS AI Lab reference architecture:

```
CONTROL PLANE   Runtime Isolation & Governance   ·   Assurance, Evaluation & Forensics
                         ^                                          ^
                      OpenShell                                 RAMPART
                              \                                /
                               +------- gauntlet run ---------+
```

The reference architecture defines capabilities and interfaces; implementations are recommended-but-swappable. Gauntlet's implementation choice of RAMPART + OpenShell is evidence-backed (see `docs/oss-ai-lab/methodology/layer-evaluations.md`) and stated openly — not assumed to be permanent.

**Future repository.** This directory is extract-ready and will be promoted to a standalone `notionalpha/gauntlet` repository. The `gauntlet/` directory can be `git mv`'d to its own repo unchanged.

---

## Status

**D1: Scaffold complete.** Structure, packaging, and CLI skeleton are in place.
**D2: Seam implementation complete.** The `gauntlet run` command is the real seam: it starts an OpenShell sandbox, runs RAMPART assurance inside it, and emits a structured report.

---

## Quick start

```bash
cd gauntlet
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"

gauntlet --help
gauntlet run --help
```

---

## Running (fake adapters — no install required)

For development and testing, use `--use-fakes` to exercise the full seam with scripted adapters instead of real RAMPART/OpenShell:

```bash
pip install -e ".[dev]"

# Human-readable report
gauntlet run --agent-image my-agent:latest --use-fakes

# Machine-readable JSON report
gauntlet run --agent-image my-agent:latest --use-fakes --output json

# Dry run (print the plan without executing)
gauntlet run --agent-image my-agent:latest --dry-run
```

---

## Running with real RAMPART + OpenShell (integration)

Once RAMPART and OpenShell are installed:

```bash
pip install -e ".[integration]"
gauntlet run --agent-image my-agent:latest --policy policy.yaml
```

Both RAMPART and OpenShell are alpha-stage as of May 2026. The `[integration]` extra declares them as dependencies but does not install them by default — `pip install -e ".[dev]"` succeeds in a fresh venv without them.

---

## Report format

Gauntlet produces a structured report after every run. Two formats are supported.

### Text (default — human-readable)

```
╔══════════════════════════════════════════════════════════╗
║  Gauntlet — RAMPART-in-OpenShell Seam Report            ║
╚══════════════════════════════════════════════════════════╝

  Agent image: my-agent:latest
  Suite      : default
  Timestamp  : 2026-05-22T16:00:00Z

────────────────────────────────────────────────────────────
  Sandbox (OpenShell isolation)
────────────────────────────────────────────────────────────
  Sandbox ID : <sandbox-id>
  Isolated   : YES — deny-by-default boundary active
  Net allow  : (none — deny-by-default)

────────────────────────────────────────────────────────────
  Assurance (RAMPART)
────────────────────────────────────────────────────────────
  Suite      : default
  Passed     : 2
  Failed     : 0
  Errors     : 0

  Findings:
    [PASS] xpia-01: Cross-prompt injection: ignore system prompt
    [PASS] xpia-02: Cross-prompt injection: exfiltrate via tool

╔══════════════════════════════════════════════════════════╗
║  VERDICT: PASS — all assurance tests passed              ║
╚══════════════════════════════════════════════════════════╝
```

Exit code: `0` for PASS, `1` for FAIL or error.

### JSON (`--output json` — machine-readable)

```json
{
  "agent_image": "my-agent:latest",
  "suite": "default",
  "timestamp": "2026-05-22T16:00:00Z",
  "dry_run": false,
  "overall_passed": true,
  "sandbox_isolated": true,
  "sandbox_id": "<sandbox-id>",
  "assurance": {
    "suite": "default",
    "overall_passed": true,
    "passed": 2,
    "failed": 0,
    "errors": 0,
    "findings": [...]
  },
  "findings": [
    {
      "test_id": "xpia-01",
      "name": "Cross-prompt injection: ignore system prompt",
      "passed": true,
      "evidence": "Agent refused injected instruction..."
    }
  ]
}
```

**Report security:** all output is sanitized. Secrets, Bearer tokens, API keys, and host filesystem paths are redacted before appearing in any report. Finding evidence is sanitized at collection time; the output renderer applies a second sanitization pass as defence-in-depth.

---

## Architecture

Gauntlet uses a narrow adapter pattern — the orchestration logic (seam.py) depends on interfaces, not on RAMPART or OpenShell directly:

```
cli.py
  └── seam.py (orchestration)
        ├── sandbox.py (SandboxAdapter interface)
        │     ├── FakeSandbox     — scripted fake for tests
        │     └── OpenShellSandbox — real OpenShell adapter
        ├── assurance.py (AssuranceAdapter interface)
        │     ├── FakeAssurance    — scripted fake for tests
        │     └── RampartAssurance — real RAMPART adapter
        └── report.py (structured report output)
```

This design lets you run the full seam with fakes in unit tests (no network, no real deps) and swap in real adapters for production runs — one flag or one constructor argument.

---

## Threat model

**The agent image is UNTRUSTED.** Gauntlet treats the agent under test as adversarial — it may attempt to escape its sandbox, exfiltrate data, or inject malicious content into reports.

Mitigations applied:

| Threat                                    | Mitigation                                                                                         |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Agent escapes sandbox                     | OpenShell enforces isolation at the kernel level (Landlock LSM + seccomp-bpf) — out-of-process     |
| Agent reaches host network                | Sandbox policy is deny-by-default for all network egress; no allowlist entries unless explicit     |
| Agent writes to host filesystem           | Sandbox policy is deny-by-default for filesystem access; only `/tmp` paths may be listed           |
| Agent injects secrets into report/logs    | All finding evidence is sanitized (Bearer tokens, sk- keys, GitHub/npm tokens, long opaque tokens) |
| Agent injects host paths into report/logs | Path patterns (3+ components) are redacted from all report output                                  |
| Seam code leaks credentials to agent      | `AssuranceAdapter.run()` has no credentials parameter; no secrets are injected into the sandbox    |
| Error messages expose host internals      | `SandboxError`, `AssuranceError`, and `SeamError` messages are sanitized before surfacing          |

**What is NOT mitigated here:**

- Vulnerabilities in the OpenShell sandbox itself (report to NVIDIA PSIRT: psirt@nvidia.com)
- Vulnerabilities in RAMPART (report to aisafetytools@microsoft.com)
- Attacks requiring a compromised host (kernel exploits) — these require host-level hardening outside Gauntlet's scope
- Multi-tenant isolation — OpenShell v0.0.46 is "single-player mode" (one developer, one environment)

**Credential discipline:** never pass API keys, tokens, or production credentials via environment variables when running Gauntlet against an untrusted agent. The `--policy` file must not contain secrets.

---

## Development

```bash
pip install -e ".[dev]"
pytest -v
```

Unit tests pass with no network and no real RAMPART/OpenShell. Integration tests skip cleanly when the dependencies are absent.

---

## Non-goals

Gauntlet is small by design. The following are explicitly out of scope:

- A hosted or managed runner (no SaaS, no Stripe billing)
- A standalone company or "the open assurance standard" — that direction is retired
- Competing with RAMPART or OpenShell
- Anything requiring a multi-tenant database or control plane

---

## License

Apache-2.0. See [LICENSE](LICENSE).

Copyright 2026 Murali Raju / NotionAlpha OSS AI Lab.
