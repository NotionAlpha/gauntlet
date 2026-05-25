# Canonical Gauntlet test agent — Qwen 3 (open weights) via OpenAI-compatible SDK.
# Image: gauntlet/canonical-agent:0.1.0
# Default provider: HuggingFace Inference Providers (HF_TOKEN required at runtime).
# Override provider: set OPENAI_BASE_URL + OPENAI_API_KEY.
# Listens on 0.0.0.0:8080.
#
# BYOC-compatible: runs as user `sandbox` (uid/gid 1000660000) so the same image
# works under both Docker (`--no-sandbox`) and OpenShell (`--policy ...`). See
# examples/bring-your-own-container/README.md in the OpenShell repo for the
# contract that pins the uid + iproute2 requirement.

FROM python:3.11-slim

# iproute2 provides `ip` for network namespace isolation under OpenShell's
# sandbox supervisor. Harmless under plain Docker.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 \
 && rm -rf /var/lib/apt/lists/*

# Non-root user with the OpenShell BYOC uid/gid. High UID avoids host-uid
# collisions when user-namespace remapping is off (Docker Desktop default).
RUN groupadd --gid 1000660000 sandbox \
 && useradd --create-home --uid 1000660000 --gid 1000660000 sandbox

WORKDIR /app

# Install Python deps first (cached layer).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the agent. /app is owned by root with mode 755, so sandbox can read.
COPY agent.py ./

# Drop privileges, expose port, run.
USER sandbox
EXPOSE 8080
ENV PORT=8080
# CMD is the entrypoint under plain Docker. OpenShell's sandbox supervisor
# replaces CMD/ENTRYPOINT and expects the start command via SandboxSpec.command
# — Gauntlet's OpenShellSandbox passes ["python", "/app/agent.py"] there.
CMD ["python", "agent.py"]
