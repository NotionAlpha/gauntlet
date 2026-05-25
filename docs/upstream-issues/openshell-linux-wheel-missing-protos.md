# DRAFT — Upstream issue for NVIDIA/OpenShell

**Status:** Drafted, held for founder submission per the OSS Lab convention
("forks and upstream PRs are founder-driven decisions, not automated steps").

**Target repo:** https://github.com/NVIDIA/OpenShell/issues

**Title:** Linux wheels for `openshell==0.0.47` (and 0.0.46) are missing all `_pb2.*` proto stubs — package fails to import on import-time

---

## Body

The published Linux wheels for the `openshell` Python package are missing the
generated proto bindings, which makes `import openshell` fail at import time
on any Linux host.

### Reproduction

```bash
python3.12 -m venv .venv
.venv/bin/pip install openshell==0.0.47
.venv/bin/python -c "import openshell"
```

On `linux/aarch64` and `linux/amd64`:

```
Traceback (most recent call last):
  File "<string>", line 1, in <module>
  File ".../site-packages/openshell/__init__.py", line 8, in <module>
    from .sandbox import (
  File ".../site-packages/openshell/sandbox.py", line 18, in <module>
    from ._proto import (
  File ".../site-packages/openshell/_proto/__init__.py", line 1, in <module>
    from . import datamodel_pb2, openshell_pb2
ImportError: cannot import name 'datamodel_pb2' from partially initialized
module 'openshell._proto' (most likely due to a circular import)
```

On `darwin/arm64` the same `pip install` works because the macOS wheel ships
the proto stubs correctly.

### Scope

Wheel contents at the `_proto/` package, for `openshell==0.0.47`:

| Wheel | `_proto/__init__.py` | `*_pb2.py` files | `*_pb2.pyi` | `*_pb2_grpc.py` |
|---|---|---|---|---|
| `openshell-0.0.47-py3-none-macosx_13_0_arm64.whl` | ✅ | ✅ (4) | ✅ (4) | ✅ (4) |
| `openshell-0.0.47-py3-none-manylinux_2_39_aarch64.whl` | ✅ | ❌ all 4 missing | ❌ all 4 missing | ❌ all 4 missing |
| `openshell-0.0.47-py3-none-manylinux_2_39_x86_64.whl` | ✅ | ❌ all 4 missing | ❌ all 4 missing | ❌ all 4 missing |

Same pattern in `openshell==0.0.46` (verified — likely a long-standing
regression in the Linux wheel-build path).

`_proto/__init__.py` line 1 reads `from . import datamodel_pb2, openshell_pb2`,
which expects sibling modules that the Linux wheels never include. The
"circular import" message is misleading — the underlying cause is the missing
files.

### Suspected cause

Comparing the published wheels: the macOS wheel was built after `mise run
python:proto` had populated `python/openshell/_proto/*.py` from `proto/*.proto`
via `grpc_tools.protoc`. The Linux wheel-build path appears to be missing this
generation step (or the `MANIFEST.in` / `pyproject.toml` package-data inclusion
isn't picking the generated `.py` files up).

The fix is likely one of:
- Ensure `mise run python:proto` runs before `mise run build:python:wheel:linux`
- Confirm the Linux build environment has `grpc_tools` available
- Confirm the wheel-build packaging rules include `openshell/_proto/*.py`

### Workaround for downstream users

```bash
# Clone the repo
git clone https://github.com/NVIDIA/OpenShell.git
cd OpenShell
# Generate protos
uv sync --group dev
mise run python:proto
# Install from source instead of PyPI
pip install -e .   # requires Rust 1.95+, libz3-dev, libclang-dev
```

### Evidence

Generated using `pip` and `unzip`:

```bash
# Confirms wheel filenames
curl -s https://pypi.org/pypi/openshell/0.0.47/json | jq -r '.urls[].filename'
# openshell-0.0.47-py3-none-macosx_13_0_arm64.whl
# openshell-0.0.47-py3-none-manylinux_2_39_aarch64.whl
# openshell-0.0.47-py3-none-manylinux_2_39_x86_64.whl

# Confirms _proto/ contents per wheel
unzip -l openshell-0.0.47-py3-none-macosx_13_0_arm64.whl | grep _proto/
unzip -l openshell-0.0.47-py3-none-manylinux_2_39_aarch64.whl | grep _proto/
unzip -l openshell-0.0.47-py3-none-manylinux_2_39_x86_64.whl | grep _proto/
```

---

## Context

I'm building [Gauntlet](https://github.com/NotionAlpha/gauntlet), a Python tool
that runs Microsoft RAMPART safety tests against an agent inside an OpenShell
sandbox in one command. Gauntlet imports `openshell.Sandbox` from the Python
SDK; the broken Linux wheels block any CI or Linux-dev path until we work
around it (we currently build the SDK from source per the workaround above).

Happy to help test a fix — I have a Lima-based Linux setup that replicates the
issue cleanly.
