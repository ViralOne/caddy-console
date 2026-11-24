"""CrowdSec Local API as a machine (watcher), only to delete one decision.

Optional: without CROWDSEC_MACHINE_ID and a password the console stays the
read-only bouncer of lapi.py. Verified against CrowdSec v1.8.2
(pkg/apiserver/controllers/controller.go, middlewares/v1/jwt.go):

  POST   /v1/watchers/login {"machine_id", "password"} -> {"code", "expire", "token"}
  DELETE /v1/decisions/<decision_id>  Authorization: Bearer <token> -> {"nbDeleted": "1"}

The by-id route expires exactly one decision (ExpireDecisionByID); an unknown
id answers 500 "decision with id ... doesn't exist". The JWT lives one hour.
The password is only ever sent in the login body: it never appears in an
exception message, a log line, an audit entry or an API response.
"""
import json
import re
import threading
import time
from datetime import datetime, timezone

import requests as http_client

from .. import config
from . import lapi

LOGIN_PATH = "/v1/watchers/login"
DECISION_PATH = "/v1/decisions/{}"
TIMEOUT = (3.05, 10)
DEADLINE = 20.0                     # whole exchange, as lapi.read_deadline() bounds a poll
MAX_BYTES = 64 * 1024
TOKEN_MAX = 4096
TOKEN_MARGIN = 60                   # re-login this long before LAPI's expiry
TOKEN_FALLBACK = 30 * 60
_ID = re.compile(r"^[\x21-\x7e]{1,128}$")
_DECISION_ID = re.compile(r"^[1-9][0-9]{0,19}$")


class DecisionGone(Exception):
    """LAPI has no such decision (already deleted or expired)."""


def _read(value, path, name, limit):
    if path:
        try:
            with open(path, "rb") as f:
                return f.read(limit + 2).decode("utf-8", "replace").strip(), None
        except OSError as e:
            return None, f"Cannot read {name}_FILE ({e.strerror or type(e).__name__})."
    return (value or "").strip(), None


def configured() -> bool:
    """Has the operator asked for write access at all (either part set)?"""
    return bool(config.CROWDSEC_MACHINE_ID or config.CROWDSEC_MACHINE_ID_FILE
                or config.CROWDSEC_MACHINE_PASSWORD or config.CROWDSEC_MACHINE_PASSWORD_FILE)


def read_credentials():
    """((machine_id, password), None), or (None, problem), or (None, None) when
    not configured. _FILE variants win and are re-read on every use, so a
    rotated password is picked up. Problems never contain either value."""
    if not configured():
        return None, None
    mid, problem = _read(config.CROWDSEC_MACHINE_ID, config.CROWDSEC_MACHINE_ID_FILE, "CROWDSEC_MACHINE_ID", 128)
    if problem:
        return None, problem
    pw, problem = _read(config.CROWDSEC_MACHINE_PASSWORD, config.CROWDSEC_MACHINE_PASSWORD_FILE,
                        "CROWDSEC_MACHINE_PASSWORD", lapi.KEY_MAX)
    if problem:
        return None, problem
    if not mid or not pw:
        return None, "Set both CROWDSEC_MACHINE_ID and CROWDSEC_MACHINE_PASSWORD (or their _FILE forms)."
    if not _ID.match(mid):
        return None, "The machine ID must be 1-128 printable ASCII characters without spaces."
    if not lapi._KEY.match(pw):
        return None, "The machine password must be 1-256 printable ASCII characters without spaces."
    key, _ = lapi.read_key()
    if key is not None and key == pw:
        return None, "The machine password must differ from the bouncer key."
    return (mid, pw), None


def valid_decision_id(raw) -> bool:
    return isinstance(raw, str) and bool(_DECISION_ID.match(raw))


# --- one bounded request ---------------------------------------------------------------

_inflight = threading.Lock()        # at most one write exchange parked on a stuck peer


def _exchange(method, url, headers, body=None):
    """(status, parsed JSON or None). Raises lapi.LapiUnavailable or
    lapi.LapiMalformed; the messages name exception types and statuses only."""
    if not _inflight.acquire(blocking=False):
        raise lapi.LapiUnavailable("the previous request has not finished")
    box, aborted = {}, threading.Event()

    def run():
        try:
            fn = http_client.post if method == "POST" else http_client.delete
            kw = {"json": body} if body is not None else {}
            try:
                resp = fn(url, headers=headers, timeout=TIMEOUT, stream=True, allow_redirects=False, **kw)
            except Exception as e:      # noqa: BLE001 - named by type only
                box["error"] = lapi.LapiUnavailable(type(e).__name__)
                return
            box["resp"] = resp
            try:
                chunks, size = [], 0
                for chunk in resp.iter_content(8192):
                    if aborted.is_set():
                        return
                    size += len(chunk)
                    if size > MAX_BYTES:
                        box["error"] = lapi.LapiMalformed("the response is larger than 64 KiB")
                        return
                    chunks.append(chunk)
                box["status"], box["body"] = resp.status_code, b"".join(chunks)
            except Exception as e:      # noqa: BLE001
                box["error"] = lapi.LapiUnavailable(f"reading the response failed ({type(e).__name__})")
            finally:
                try:
                    resp.close()
                except Exception:       # noqa: BLE001
                    pass
        finally:
            _inflight.release()
    worker = threading.Thread(target=run, name="crowdsec-lapi-write", daemon=True)
    try:
        worker.start()
    except RuntimeError:
        _inflight.release()
        raise lapi.LapiUnavailable("cannot start the request thread") from None
    worker.join(DEADLINE)
    if worker.is_alive():
        aborted.set()
        if box.get("resp") is not None:
            lapi._abort(box["resp"])
        raise lapi.LapiUnavailable(f"the response took too long (over {DEADLINE:g} s)")
    if "error" in box:
        raise box["error"]
    if "status" not in box:
        raise lapi.LapiUnavailable("the request ended without a response")
    try:
        doc = json.loads(box["body"].decode("utf-8")) if box["body"] else None
    except (UnicodeDecodeError, ValueError, RecursionError):
        doc = None
    return box["status"], doc


# --- token cache and the delete --------------------------------------------------------

_lock = threading.Lock()            # one login at a time; never held across the delete
_token = {"value": None, "until": 0.0, "who": None}


def reset_cache() -> None:
    with _lock:
        _token.update(value=None, until=0.0, who=None)


def _headers(extra=None):
    return {"Accept": "application/json", "User-Agent": lapi.USER_AGENT, **(extra or {})}


def _lifetime(expire) -> float:
    try:
        at = datetime.fromisoformat(str(expire).replace("Z", "+00:00"))
        if at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        seconds = (at - datetime.now(timezone.utc)).total_seconds()
    except ValueError:
        seconds = TOKEN_FALLBACK
    return max(0.0, min(seconds, 3600.0) - TOKEN_MARGIN)


def _login(base, creds, who) -> str:
    status, doc = _exchange("POST", base + LOGIN_PATH, _headers({"Content-Type": "application/json"}),
                            {"machine_id": creds[0], "password": creds[1]})
    if status in (401, 403):
        raise lapi.LapiAuthError(f"login refused, HTTP {status}")
    if status != 200:
        raise lapi.LapiUnavailable(f"login answered HTTP {status}")
    token = doc.get("token") if isinstance(doc, dict) else None
    if not isinstance(token, str) or not 0 < len(token) <= TOKEN_MAX or not lapi._KEY.match(token[:256]):
        raise lapi.LapiMalformed("the login response has no usable token")
    _token.update(value=token, until=time.monotonic() + _lifetime(doc.get("expire")), who=who)
    return token


def _token_for(base, creds, fresh=False) -> str:
    who = (base, creds[0], hash(creds[1]))
    with _lock:
        if not fresh and _token["value"] and _token["who"] == who and time.monotonic() < _token["until"]:
            return _token["value"]
        _token.update(value=None, until=0.0, who=None)
        return _login(base, creds, who)


def delete_decision(decision_id, creds, base=None) -> int:
    """Expire one decision in LAPI; returns nbDeleted. Raises DecisionGone,
    lapi.LapiAuthError, lapi.LapiUnavailable or lapi.LapiMalformed. A 401 on
    the delete (expired or revoked token) logs in once more and retries."""
    if not valid_decision_id(decision_id):
        raise ValueError("invalid decision id")
    base = base or lapi.url()
    url = base + DECISION_PATH.format(decision_id)
    for attempt in (0, 1):
        token = _token_for(base, creds, fresh=attempt == 1)
        status, doc = _exchange("DELETE", url, _headers({"Authorization": f"Bearer {token}"}))
        if status == 401 and attempt == 0:
            continue
        if status in (401, 403):
            reset_cache()
            raise lapi.LapiAuthError(f"HTTP {status}")
        message = doc.get("message", "") if isinstance(doc, dict) else ""
        if status == 404 or (status == 500 and isinstance(message, str) and "doesn't exist" in message):
            raise DecisionGone()
        if status != 200:
            raise lapi.LapiUnavailable(f"HTTP {status}")
        try:
            return int((doc or {}).get("nbDeleted", "0"))
        except (TypeError, ValueError, AttributeError):
            raise lapi.LapiMalformed("the delete response has no nbDeleted") from None
    raise lapi.LapiAuthError("HTTP 401")            # not reached
