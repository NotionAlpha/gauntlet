# Security Policy

## Supported versions

Gauntlet is alpha-stage software. Security fixes land on the latest released minor version (currently `0.1.x`). Earlier prereleases are not supported.

| Version  | Supported |
| -------- | --------- |
| 0.1.x    | ✅        |
| < 0.1    | ❌        |

## Reporting a vulnerability

If you believe you have found a security vulnerability in Gauntlet, please **do not open a public GitHub issue**. Instead:

1. Use GitHub's [private security advisory](https://github.com/NotionAlpha/gauntlet/security/advisories/new) flow, or
2. Email the maintainer at `murali.raju@appliv.com` with `[gauntlet security]` in the subject line.

Please include:

- A clear description of the issue and the affected component (CLI, sandbox adapter, assurance adapter, sanitizer, report renderer, or upstream-SDK integration).
- Reproduction steps and, if possible, a minimal proof-of-concept.
- The impact you observed and any environmental notes (Python version, OS, OpenShell / RAMPART versions).

You can expect an acknowledgment within **3 business days** and a substantive response within **10 business days**. Coordinated disclosure timelines are negotiable based on severity and the upstream chain (RAMPART, OpenShell).

## Threat model

Gauntlet is designed around the assumption that **the agent under test is adversarial**. The threat model is documented inline in `src/gauntlet/sandbox.py` and the project README; the short version:

- The OpenShell sandbox isolation boundary is **deny-by-default**: no network egress, no filesystem access, no host environment exposure beyond what a `SandboxPolicy` explicitly allows. The policy is immutable after construction.
- Report output is **sanitized** through `gauntlet._sanitizer.sanitize()` before any string reaches the renderer. Bearer tokens, API key shapes, and host filesystem paths are redacted.
- `SandboxError` messages must not expose host paths or credential-like strings — this is checked in tests.
- Gauntlet does not pass host credentials INTO the sandbox unless a credential is explicitly named in the agent forwarded-env allowlist (currently `HF_TOKEN`, `OPENAI_BASE_URL`, `OPENAI_API_KEY` — see `_agent_runtime_env()` in `src/gauntlet/sandbox.py`). Everything else is denied by the policy's isolation contract.

## Out of scope

The following are explicitly NOT in Gauntlet's security scope:

- Vulnerabilities in the upstream dependencies it integrates with — **RAMPART** (Microsoft, MIT) and **OpenShell** (NVIDIA, Apache-2.0). Please report those to their respective projects directly; Gauntlet maintainers will track and pin to fixed upstream releases.
- The behavior of the agent under test. Gauntlet's job is to measure that behavior, not to defend against it. A failing RAMPART verdict is a working Gauntlet outcome.
- Misconfigured OpenShell deployments outside of Gauntlet's control (e.g., a gateway bound to a public interface without an authentication layer in front).
