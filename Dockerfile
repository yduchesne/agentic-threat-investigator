# syntax=docker/dockerfile:1
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./
RUN pip install --no-cache-dir uv && uv sync --locked --no-dev
ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH=/app/src
CMD ["uvicorn", "agentic_threat_investigator.main:app", "--host", "0.0.0.0", "--port", "8000"]
