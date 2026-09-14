# Keep this version in step with the `caddy` service image in the compose files:
# this binary runs `caddy fmt` / `caddy validate` on what the other one loads.
FROM caddy:2.11.4-alpine AS caddy-bin

FROM python:3.14-alpine

RUN apk add --no-cache curl openssl

COPY --from=caddy-bin /usr/bin/caddy /usr/bin/caddy
COPY --from=ghcr.io/astral-sh/uv:0.12.10 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy

WORKDIR /app
# Install from the committed lockfile so image builds are reproducible.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY app.py gunicorn.conf.py ./
COPY src/ src/

EXPOSE 9090

CMD ["/app/.venv/bin/gunicorn", "app:app", "-b", "0.0.0.0:9090", "--access-logfile", "-", "-c", "gunicorn.conf.py"]
