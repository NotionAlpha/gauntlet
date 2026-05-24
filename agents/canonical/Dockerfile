# Canonical Gauntlet test agent — Qwen 3 (open weights) via OpenAI-compatible SDK.
# Image: gauntlet/canonical-agent:0.1.0
# Default provider: HuggingFace Inference Providers (HF_TOKEN required at runtime).
# Override provider: set OPENAI_BASE_URL + OPENAI_API_KEY.
# Listens on 0.0.0.0:8080.

FROM python:3.11-slim

# Run as a non-root user.
RUN useradd --create-home --uid 1000 agent

WORKDIR /app

# Install Python deps first (cached layer).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the agent.
COPY agent.py ./

# Drop privileges, expose port, run.
USER agent
EXPOSE 8080
ENV PORT=8080
CMD ["python", "agent.py"]
