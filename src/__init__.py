from datetime import timedelta
import os
import secrets

from flask import Flask, jsonify, request

from .auth import auth_bp, cf_jwt_enabled, csrf_valid, oauth
from .config import AUTH_MODE, BACKUP_DIR, SESSION_TIMEOUT_HOURS
from .routes.editor import editor_bp
from .routes.ops import ops_bp

# Known placeholder secrets that must never be used to sign real sessions.
_INSECURE_SECRETS = {"", "dev-secret-change-me", "change-me-to-a-random-string"}


def _persisted_secret_key() -> str:
    """A generated secret that is stable across workers and restarts.

    Every gunicorn worker calls create_app() separately, so generating a random
    key per process would sign each worker's session cookies with a different
    key and CSRF checks would fail whenever a request landed on another worker.
    """
    path = os.path.join(BACKUP_DIR, ".secret_key")
    generated = secrets.token_hex(32)
    try:
        with open(path) as f:
            existing = f.read().strip()
        if existing:
            return existing
    except OSError:
        pass
    # Write the full key to a private temp file first, then link it into place.
    # link() fails if the target exists, so concurrent workers can never observe
    # a half-written key: whoever wins the link has already written everything.
    tmp = f"{path}.{os.getpid()}.{secrets.token_hex(4)}"
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, generated.encode())
        finally:
            os.close(fd)
        try:
            os.link(tmp, path)
            return generated
        except FileExistsError:
            with open(path) as f:
                return f.read().strip() or generated
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
    except OSError:
        # Read-only volume: fall back to a per-process key. Single-worker only.
        return generated


def create_app():
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )

    secret_key = os.environ.get("SECRET_KEY", "").strip()
    if secret_key in _INSECURE_SECRETS:
        if AUTH_MODE == "google":
            raise RuntimeError(
                "SECRET_KEY must be set to a strong random value when AUTH_MODE=google. "
                'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
            )
        secret_key = _persisted_secret_key()
    app.secret_key = secret_key

    app.config["PREFERRED_URL_SCHEME"] = "http"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=SESSION_TIMEOUT_HOURS)
    # A Caddyfile is kilobytes; anything near this is a mistake or abuse, and it
    # would otherwise be handed straight to `caddy fmt`.
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

    if AUTH_MODE == "cloudflare" and not cf_jwt_enabled():
        app.logger.warning(
            "AUTH_MODE=cloudflare without CF_ACCESS_TEAM_DOMAIN/CF_ACCESS_AUD: trusting the "
            "Cf-Access-Authenticated-User-Email header. Anything that can reach this port "
            "directly can impersonate any user. Set both variables to verify the Access JWT."
        )

    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower()
        != "false",
    )

    if AUTH_MODE == "google":
        oauth.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(editor_bp)
    app.register_blueprint(ops_bp)

    @app.before_request
    def csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.path.startswith("/api/"):
            if not csrf_valid():
                return jsonify({"error": "csrf token missing or invalid"}), 403

    @app.after_request
    def security_headers(response):
        response.headers["Server"] = "Microsoft-IIS/10.0"
        response.headers["X-Powered-By"] = "ASP.NET"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        return response

    return app
