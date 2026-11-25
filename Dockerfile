FROM python:3.12-slim AS build
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
RUN useradd -u 10001 -m app
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH HOME=/home/app
USER 10001
ENTRYPOINT ["kube-triage-mcp"]
