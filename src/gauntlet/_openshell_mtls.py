"""
Auto-discover the active OpenShell gateway's mTLS material.

The OpenShell gateway requires mutual TLS for sandbox-service traffic. The
client cert/key are written by the openshell CLI when a gateway is registered,
under `~/.config/openshell/gateways/<name>/mtls/{tls.crt,tls.key,ca.crt}`.
We auto-discover them so callers (the agent-readiness probe in
`gauntlet.sandbox.OpenShellSandbox`, the HTTP adapter in
`gauntlet.rampart_suite.conftest`) don't have to know the file layout.

Returns `(None, False)` when no active gateway is configured — appropriate
for the `--no-sandbox` path and for unit tests that don't have OpenShell
installed.

`verify` is always `False` because sandbox-service URLs use a routing
hostname (e.g. `<sandbox>--http.openshell.localhost`) that doesn't match
the gateway cert's SAN (`host.openshell.internal`). Skipping hostname
verification is intentional — see docs/m1.3.6-gateway-setup.md.
"""

from __future__ import annotations

import os
from pathlib import Path


def discover_openshell_mtls() -> tuple[tuple[str, str] | None, bool]:
    """Return `(cert_pair, verify)` suitable for `requests`.

    cert_pair is `(tls.crt path, tls.key path)` or None if no active gateway.
    """
    config_dir = (
        Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "openshell"
    )
    active_file = config_dir / "active_gateway"
    if not active_file.exists():
        return None, False
    try:
        gateway_name = active_file.read_text().strip()
    except OSError:
        return None, False
    mtls_dir = config_dir / "gateways" / gateway_name / "mtls"
    crt = mtls_dir / "tls.crt"
    key = mtls_dir / "tls.key"
    if not (crt.exists() and key.exists()):
        return None, False
    return (str(crt), str(key)), False


__all__ = ["discover_openshell_mtls"]
