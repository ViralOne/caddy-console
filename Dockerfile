FROM caddy:2.11.4-alpine AS caddy-bin

FROM python:3.14-alpine

RUN apk add --no-cache curl openssl

COPY --from=caddy-bin /usr/bin/caddy /usr/bin/caddy

WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir uv && uv sync --no-dev

COPY app.py gunicorn.conf.py ./
COPY src/ src/

EXPOSE 9090

CMD ["/app/.venv/bin/gunicorn", "app:app", "-b", "0.0.0.0:9090", "--access-logfile", "-", "-c", "gunicorn.conf.py"]
