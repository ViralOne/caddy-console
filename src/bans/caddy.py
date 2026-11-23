"""The three admin-API calls the ban transaction needs, with explicit outcomes."""
import hashlib
import json
from dataclasses import dataclass

import requests as http_client

from .. import validator
from ..config import CADDY_API_URL

CONFIG_TIMEOUT = 5
LOAD_TIMEOUT = 10          # the editor's save path uses the same bound


class CaddyUnavailable(Exception):
    pass


@dataclass(frozen=True)
class AdaptResult:
    ok: bool
    config: object
    message: str


@dataclass(frozen=True)
class LoadResult:
    status: str            # applied | rejected | failed | unknown
    message: str


def normalize(config) -> bytes:
    return json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def config_hash(config) -> str:
    return "sha256:" + hashlib.sha256(normalize(config)).hexdigest()


def live_config():
    try:
        resp = http_client.get(f"{CADDY_API_URL}/config/", timeout=CONFIG_TIMEOUT)
    except http_client.RequestException as e:
        raise CaddyUnavailable(type(e).__name__) from e
    if resp.status_code != 200:
        raise CaddyUnavailable(f"GET /config/ returned HTTP {resp.status_code}")
    try:
        return resp.json()
    except ValueError as e:
        raise CaddyUnavailable("GET /config/ returned invalid JSON") from e


def adapt(text: str) -> AdaptResult:
    resp = validator.adapt_caddyfile(text)
    if resp is None:
        raise CaddyUnavailable("POST /adapt failed")
    if resp.status_code != 200:
        return AdaptResult(False, None, validator.admin_error(resp))
    try:
        body = resp.json()
    except ValueError:
        return AdaptResult(False, None, "Caddy returned an invalid /adapt response")
    if not isinstance(body, dict) or "result" not in body:
        return AdaptResult(False, None, "Caddy's /adapt response has no result")
    return AdaptResult(True, body["result"], "adapted")


def load(text: str) -> LoadResult:
    """POST the unchanged on-disk Caddyfile. Only a connect timeout proves the
    request never reached Caddy; any other transport error is ambiguous."""
    try:
        resp = http_client.post(f"{CADDY_API_URL}/load", data=text.encode("utf-8"),
                                headers={"Content-Type": "text/caddyfile"}, timeout=LOAD_TIMEOUT)
    except http_client.ConnectTimeout:
        return LoadResult("failed", "A connection to Caddy could not be established.")
    except http_client.RequestException as e:
        return LoadResult("unknown", f"Caddy did not confirm the reload ({type(e).__name__}).")
    if 200 <= resp.status_code < 300:
        return LoadResult("applied", "")
    return LoadResult("rejected", validator.admin_error(resp)[:2000])
