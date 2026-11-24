"""Security view and IP-ban API (docs/security.md). Registered only when
BANS_ENABLED; every mutation is under /api/ so the app's CSRF hook covers it."""
from flask import Blueprint, jsonify, render_template, request, session

from ..auth import get_or_create_csrf, login_required
from ..bans import service

security_bp = Blueprint("security", __name__)


def _actor() -> str:
    return session.get("user", {}).get("email", "unknown")


def _payload():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _reply(result):
    body, status = result
    return jsonify(body), status


@security_bp.route("/security")
@login_required
def page():
    return render_template("index.html", csrf_token=get_or_create_csrf(), bans_enabled=True)


@security_bp.route("/api/security", methods=["GET"])
@login_required
def security_status():
    return jsonify(service.status(request.remote_addr))


@security_bp.route("/api/security/recovery", methods=["GET"])
@login_required
def recovery_get():
    return jsonify(service.recovery_info())


@security_bp.route("/api/security/recovery", methods=["POST"])
@login_required
def recovery_post():
    return _reply(service.recovery_post(_payload(), _actor()))


@security_bp.route("/api/security/reapply", methods=["POST"])
@login_required
def reapply():
    return _reply(service.reapply(_payload() or {}, _actor(), request.remote_addr))


@security_bp.route("/api/security/reset", methods=["POST"])
@login_required
def reset():
    return _reply(service.reset(_payload(), _actor(), request.remote_addr))


@security_bp.route("/api/bans", methods=["GET"])
@login_required
def list_bans():
    return _reply(service.list_bans(request.args.get("covering")))


@security_bp.route("/api/bans", methods=["POST"])
@login_required
def add_ban():
    return _reply(service.add_ban(_payload(), _actor(), request.remote_addr))


@security_bp.route("/api/bans/<record_id>", methods=["DELETE"])
@login_required
def remove_ban(record_id):
    return _reply(service.remove_ban(record_id, _actor(), request.remote_addr))


@security_bp.route("/api/security/crowdsec/decisions/<decision_id>", methods=["DELETE"])
@login_required
def delete_crowdsec_decision(decision_id):
    return _reply(service.delete_crowdsec_decision(decision_id, _actor(), request.remote_addr))


@security_bp.route("/api/security/client-ip-profile", methods=["GET"])
@login_required
def client_ip_profile_get():
    return jsonify(service.client_ip_profile_info())


@security_bp.route("/api/security/cloudflare-ranges/refresh", methods=["POST"])
@login_required
def cloudflare_ranges_refresh():
    return _reply(service.refresh_cloudflare_ranges(_actor(), manual=True))


@security_bp.route("/api/security/client-ip-profile", methods=["PUT"])
@login_required
def client_ip_profile_put():
    return _reply(service.set_client_ip_profile(_payload(), _actor()))


@security_bp.route("/api/security/country-policy", methods=["GET"])
@login_required
def country_policy_get():
    return jsonify(service.country_policy_info())


@security_bp.route("/api/security/country-policy", methods=["PUT"])
@login_required
def country_policy_put():
    return _reply(service.set_country_policy(_payload(), _actor()))
