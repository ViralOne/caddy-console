"""Shared fixtures for the IP-ban tests (not a test module: never discovered).

reset() returns every ban-related file to a clean slate; FakeCaddy (Task 6)
stands in for the admin API.
"""
import contextlib
import glob
import json
import os
import re
import shutil
import unittest
from unittest import mock

import requests
from urllib3 import exceptions as urllib3_exc

import tests._env as env

MANUAL_SITE = "example.com {{\n\timport {bans_dir}/bans-manual*.caddy\n\trespond 200\n}}\n"


def write_caddyfile(text):
    with open(env.CADDYFILE, "w", encoding="utf-8") as f:
        f.write(text)


def reset(caddyfile=None):
    for name in os.listdir(env.BACKUP_DIR):
        if name.startswith("bans") or name.startswith(".bans") or name == "plugin-policy.json":
            path = os.path.join(env.BACKUP_DIR, name)
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.remove(path)
    shutil.rmtree(os.path.join(env.BACKUP_DIR, ".policy-transactions"), ignore_errors=True)
    shutil.rmtree(env.BANS_DIR, ignore_errors=True)
    shutil.rmtree(os.path.join(os.path.dirname(env.CADDYFILE), "sites-itest"), ignore_errors=True)
    os.makedirs(env.BANS_DIR)
    write_caddyfile(caddyfile if caddyfile is not None else MANUAL_SITE.format(bans_dir=env.BANS_DIR))


def MANUAL_PATH():
    return os.path.join(env.BANS_DIR, "bans-manual.caddy")


def fresh_audit(test):
    """tests/_env.py caps the audit log at 400 bytes to exercise rotation; ban
    tests count entries, so start empty and lift the cap for this test."""
    from src import audit
    for path in (env.AUDIT_LOG, env.AUDIT_LOG + ".1"):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    patcher = mock.patch.object(audit, "AUDIT_LOG_MAX_BYTES", 10 ** 9)
    patcher.start()
    test.addCleanup(patcher.stop)


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or ("" if payload is None else json.dumps(payload))

    def json(self):
        if self._payload is None:
            raise ValueError("no JSON body")
        return self._payload


_IMPORT_RE = re.compile(r"(?m)^\s*import\s+(/\S+)")
_MARKER_RE = re.compile(r"(?m)^vars (caddy_console_\w+) (\S+)$")
_CROWDSEC_BLOCK = re.compile(r"(?m)^\s*crowdsec\s*\{")


class FakeCaddy:
    """Stands in for Caddy's admin API by patching requests.get/post.

    /adapt resolves absolute import globs from disk, so the adapted config (and
    its hash) changes exactly when an imported file or the Caddyfile changes,
    and a managed file's vars marker shows up as a real vars handler.
    """

    def __init__(self, live=None):
        self.live = {"apps": {}} if live is None else live
        self.down = False
        self.adapt_status = 200
        self.plugin = False                       # the running build has the crowdsec module
        self.load_mode = "ok"
        self.live_after_load = None
        self.hide_imports = False
        self.calls = []

    def adapt_text(self, text):
        routes = []
        if not self.hide_imports:
            self._resolve_imports(text, routes, depth=0)
        routes.append({"handle": [{"handler": "fake_caddyfile", "body": text}]})
        return {"apps": {"http": {"servers": {"srv0": {"listen": [":80"], "routes": [
            {"match": [{"host": ["example.com"]}],
             "handle": [{"handler": "subroute", "routes": routes}], "terminal": True}]}}}}}

    def _resolve_imports(self, text, routes, depth):
        """Absolute import globs, followed into imported files like Caddy does."""
        if depth > 4:
            return
        for pattern in _IMPORT_RE.findall(text):
            for path in sorted(glob.glob(pattern)):
                with open(path, encoding="utf-8") as f:
                    body = f.read()
                handlers = [{"handler": "vars", m.group(1): m.group(2)} for m in _MARKER_RE.finditer(body)]
                handlers.append({"handler": "fake_import", "path": path, "body": body})
                routes.append({"handle": handlers})
                self._resolve_imports(body, routes, depth + 1)

    def _post(self, url, data=None, headers=None, timeout=None, **kw):
        if self.down:
            raise requests.ConnectionError("fake caddy is down")
        text = data.decode("utf-8") if isinstance(data, bytes) else (data or "")
        if url.endswith("/adapt"):
            self.calls.append(("adapt", text))
            if self.adapt_status != 200:
                return FakeResponse(self.adapt_status, {"error": "fake adapt rejection"})
            if _CROWDSEC_BLOCK.search(text) and not self.plugin:
                return FakeResponse(400, {"error": "adapting config using caddyfile: unrecognized global option: crowdsec"})
            return FakeResponse(200, {"result": self.adapt_text(text)})
        if url.endswith("/load"):
            self.calls.append(("load", text))
            if self.load_mode == "connect_timeout":
                raise requests.ConnectTimeout("fake connect timeout")
            if self.load_mode == "connection_refused":
                reason = urllib3_exc.NewConnectionError(None, "Failed to establish a new connection: refused")
                raise requests.ConnectionError(urllib3_exc.MaxRetryError(None, url, reason))
            if self.load_mode == "connection_reset":
                reason = urllib3_exc.ProtocolError("Connection aborted.", ConnectionResetError(54, "reset"))
                raise requests.ConnectionError(reason)
            if self.load_mode == "reject":
                return FakeResponse(400, {"error": "fake load rejection"})
            self.live = self.live_after_load if self.live_after_load is not None else self.adapt_text(text)
            if self.load_mode == "read_timeout":
                raise requests.ReadTimeout("fake read timeout after the config was applied")
            return FakeResponse(200, None, "")
        raise AssertionError(f"unexpected POST {url}")

    def _get(self, url, timeout=None, **kw):
        if self.down:
            raise requests.ConnectionError("fake caddy is down")
        if url.endswith("/config/"):
            self.calls.append(("config", None))
            return FakeResponse(200, self.live)
        if url.endswith("/config/apps/http/servers"):
            return FakeResponse(200, ((self.live or {}).get("apps", {}).get("http") or {}).get("servers", {}))
        raise AssertionError(f"unexpected GET {url}")

    def install(self, test):
        for name, fn in (("post", self._post), ("get", self._get)):
            patcher = mock.patch.object(requests, name, fn)
            patcher.start()
            test.addCleanup(patcher.stop)
        return self


class SimulatedCrash(BaseException):
    """Raised from txn._checkpoint; BaseException so no `except OSError` swallows it."""


@contextlib.contextmanager
def crash_at(point):
    from src.bans import txn

    def boom(name):
        if name == point:
            raise SimulatedCrash(name)
    with mock.patch.object(txn, "_checkpoint", boom):
        yield


def manual_changes(*values):
    from src.bans import addr, fsio, render, store, txn
    src = render.SOURCES["manual"]
    nets = [addr.canonical(v) for v in values]
    policy = render.render_policy(src, nets, ["private_ranges"], 100000)
    state = store.State(last_rendered_hashes={src.filename: fsio.sha256_tag(policy)})
    for n in nets:
        state.records.append(store.new_manual_record(n, "permanent", "", "t@example.com", store.utc_now()))
    return [txn.Change(src.path, "policy", policy, marker=src.marker),
            txn.Change(store.STATE_PATH, "state", store.dumps(state), owns=(src.filename,))]


def apply(changes, audit=(), **kw):
    from src.bans import txn
    from src.routes.editor import caddyfile_lock
    with caddyfile_lock():
        return txn.apply_locked(changes, actor="t@example.com", source="manual", audit_events=audit, **kw)


def write_included_site(name="site.caddy"):
    """A site defined in a file the main Caddyfile imports, which itself imports
    the ban glob: the main text never mentions the policy file."""
    sites = os.path.join(os.path.dirname(env.CADDYFILE), "sites-itest")
    shutil.rmtree(sites, ignore_errors=True)
    os.makedirs(sites)
    with open(os.path.join(sites, name), "w", encoding="utf-8") as f:
        f.write(MANUAL_SITE.format(bans_dir=env.BANS_DIR))
    return f"import {sites}/*.caddy\n"


AUTH = {"Cf-Access-Authenticated-User-Email": "admin@example.com"}


class ApiCase(unittest.TestCase):
    """Flask test client plus FakeCaddy. No test methods, so never collected itself."""
    app = None

    @classmethod
    def setUpClass(cls):
        from src import create_app
        if ApiCase.app is None:
            ApiCase.app = create_app()
            ApiCase.app.testing = True

    def setUp(self):
        from src.routes import editor as editor_mod
        reset()
        fresh_audit(self)
        self.caddy = FakeCaddy().install(self)
        from src.bans import protected
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        for name, value in (("caddy_fmt", lambda c: c),
                            ("caddy_validate", lambda c: (True, "ok")),
                            ("caddy_check", lambda c: (True, "ok", "adapted"))):
            p = mock.patch.object(editor_mod, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.client = self.app.test_client()
        html = self.client.get("/", headers=AUTH).get_data(as_text=True)
        self.csrf = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)

    def _h(self, kw):
        return {**AUTH, "X-CSRF-Token": self.csrf, **kw.pop("headers", {})}

    def get(self, url, **kw):
        return self.client.get(url, headers={**AUTH, **kw.pop("headers", {})}, **kw)

    def post(self, url, payload=None, **kw):
        return self.client.post(url, json=payload, headers=self._h(kw), **kw)

    def put(self, url, payload=None, **kw):
        return self.client.put(url, json=payload, headers=self._h(kw), **kw)

    def delete(self, url, **kw):
        return self.client.delete(url, headers=self._h(kw), **kw)
