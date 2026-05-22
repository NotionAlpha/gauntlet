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

**Future repository.** This directory is extract-ready and will be promoted to a standalone `notionalpha/gauntlet` repository when the seam implementation (D2) is complete. The `gauntlet/` directory can be `git mv`'d to its own repo unchanged.

---

## Status

**D1: Scaffold complete.** Structure, packaging, and CLI skeleton are in place.  
**D2: Seam implementation — pending.** The `gauntlet run` command is a documented stub. D2 implements the actual RAMPART + OpenShell wiring.

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

## Running with real RAMPART + OpenShell (integration)

Once D2 is complete and RAMPART/OpenShell are installed:

```bash
pip install -e ".[integration]"
gauntlet run --agent-image my-agent:latest --policy policy.yaml
```

Both RAMPART and OpenShell are alpha-stage as of May 2026. The `[integration]` extra declares them as dependencies but does not install them by default — `pip install -e ".[dev]"` succeeds in a fresh venv without them.

---

## Development

```bash
pip install -e ".[dev]"
pytest -v
```

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
