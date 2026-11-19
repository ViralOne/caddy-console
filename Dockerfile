# Override to match your Caddy if you rely on the local-validation fallback,
# for example a DNS-01 build carrying the same modules as the target.
ARG CADDY_IMAGE=caddy:2.11.9-alpine
FROM ${CADDY_IMAGE} AS caddy-bin

FROM python:3.15.2-alpine

COPY --from=caddy-bin /usr/bin/caddy /usr/bin/caddy
COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 HOME=/tmp

WORKDIR /app
# Install from the committed lockfile so image builds are reproducible.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY app.py gunicorn.conf.py ./
COPY src/ src/

# The web process needs no root privileges. Named volumes mounted at these paths
# inherit this ownership when first created; the host Caddy directory must be
# owned by the same UID so atomic replace() is possible.
RUN addgroup -S -g 10001 caddy-console \
    && adduser -S -D -H -u 10001 -G caddy-console caddy-console \
    && mkdir -p /backups /data/geoip \
    && chown -R 10001:10001 /app /backups /data/geoip

USER 10001:10001

EXPOSE 9090

CMD ["/app/.venv/bin/gunicorn", "app:app", "-b", "0.0.0.0:9090", "--access-logfile", "-", "-c", "gunicorn.conf.py"]
