"""Shared fixtures for the CrowdSec tests (not a test module: never discovered).

FakeLapi stands in for CrowdSec's Local API by patching requests.get. Install it
after _bans.FakeCaddy: GETs that are not for URL go to the previous requests.get,
so both fakes work in one test. Empty lists are sent as null, as LAPI does.
"""
import json
import json as _json
from datetime import timedelta
from unittest import mock

import requests

from src import config

URL = "http://crowdsec.invalid:8080"
KEY = "console-test-key-6f1d0c2a9b"
MACHINE_ID = "caddy-console-writer"
MACHINE_PASSWORD = "machine-test-password-41c7e9"


def enable(test, **extra):
    values = {"CROWDSEC_URL": URL, "CROWDSEC_CONSOLE_BOUNCER_KEY": KEY, "CROWDSEC_CONSOLE_BOUNCER_KEY_FILE": "",
              "CROWDSEC_ORIGINS": "crowdsec,cscli", **extra}
    for name, value in values.items():
        p = mock.patch.object(config, name, value)
        p.start()
        test.addCleanup(p.stop)


def accepted(value, decision_id="1", origin="crowdsec", scenario="crowdsecurity/http-probing", hours=4, now=None):
    from src.bans import addr, lapi, store
    now = now or store.utc_now()
    return lapi.Accepted(str(decision_id), addr.canonical(value), origin, scenario, now, now + timedelta(hours=hours))


class FakeStreamResponse:
    def __init__(self, status_code=200, body=b""):
        self.status_code, self.body, self.closed = status_code, body, False
        self.headers = {"Content-Type": "application/json"}

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self.body), chunk_size):
            yield self.body[i:i + chunk_size]

    def close(self):
        self.closed = True


class FakeLapi:
    def __init__(self):
        self.current = {}                    # id -> decision dict, the active set
        self.new_since, self.deleted_since = [], []
        self.mode = "ok"                     # ok | down | status | raw | response
        self.status = 200
        self.raw = b""
        self.response = None                 # returned as is in "response" mode
        self.calls = []
        self._seq = 100
        self.machines = {MACHINE_ID: MACHINE_PASSWORD}   # watcher logins LAPI accepts
        self.tokens = set()                              # JWTs LAPI currently honours
        self.write_mode = "ok"                           # ok | down
        self.writes = []                                 # login and delete calls, as sent

    def add(self, value, *, scope="Ip", type="ban", origin="crowdsec", scenario="crowdsecurity/http-probing",
            duration="3h59m58.5s", id=None):
        if id is None:
            self._seq += 1
            id = self._seq
        d = {"id": int(id), "scope": scope, "value": value, "type": type, "origin": origin,
             "scenario": scenario, "duration": duration}
        self.current[str(id)] = d
        self.new_since.append(d)
        return str(id)

    def delete(self, id):
        d = self.current.pop(str(id), None) or {"id": int(id), "scope": "Ip", "value": "192.0.2.250", "type": "ban",
                                                "origin": "crowdsec", "scenario": "x"}
        self.deleted_since.append({**d, "duration": "-1m5.5s"})

    def _body(self, startup):
        if startup:
            new, deleted = list(self.current.values()), []
        else:
            new, deleted = self.new_since, self.deleted_since
        self.new_since, self.deleted_since = [], []
        return json.dumps({"new": new or None, "deleted": deleted or None}).encode()

    def _get(self, url, params=None, headers=None, timeout=None, **kw):
        if not url.startswith(URL):
            return self._prev(url, params=params, headers=headers, timeout=timeout, **kw)
        self.calls.append({"path": url[len(URL):], "params": dict(params or {}),
                           "key": (headers or {}).get("X-Api-Key"), "stream": kw.get("stream"),
                           "allow_redirects": kw.get("allow_redirects"), "timeout": timeout,
                           "headers": dict(headers or {})})
        if self.mode == "down":
            raise requests.ConnectionError("fake lapi is down")
        if self.mode == "status":
            return FakeStreamResponse(self.status, b'{"message":"access forbidden"}')
        if self.mode == "raw":
            return FakeStreamResponse(200, self.raw)
        if self.mode == "response":
            return self.response
        return FakeStreamResponse(200, self._body((params or {}).get("startup") == "true"))

    def revoke_tokens(self):
        self.tokens.clear()

    def _post(self, url, data=None, json=None, headers=None, timeout=None, **kw):
        if not url.startswith(URL):
            return self._prev_post(url, data=data, json=json, headers=headers, timeout=timeout, **kw)
        self.writes.append({"method": "POST", "path": url[len(URL):], "json": json, "headers": dict(headers or {}),
                            "timeout": timeout, "allow_redirects": kw.get("allow_redirects")})
        if self.write_mode == "down":
            raise requests.ConnectionError("fake lapi is down")
        if url[len(URL):] != "/v1/watchers/login":
            return FakeStreamResponse(404, b'{"message":"not found"}')
        body = json or {}
        if self.machines.get(body.get("machine_id")) != body.get("password") or not body.get("password"):
            return FakeStreamResponse(401, b'{"code":401,"message":"incorrect Username or Password"}')
        self._seq += 1
        token = f"jwt-{self._seq}"
        self.tokens.add(token)
        return FakeStreamResponse(200, _json.dumps({"code": 200, "expire": "2999-01-01T00:00:00Z",
                                                    "token": token}).encode())

    def _delete(self, url, headers=None, timeout=None, **kw):
        if not url.startswith(URL):
            return self._prev_delete(url, headers=headers, timeout=timeout, **kw)
        self.writes.append({"method": "DELETE", "path": url[len(URL):], "headers": dict(headers or {}),
                            "timeout": timeout, "allow_redirects": kw.get("allow_redirects")})
        if self.write_mode == "down":
            raise requests.ConnectionError("fake lapi is down")
        auth = (headers or {}).get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] not in self.tokens:
            return FakeStreamResponse(401, b'{"code":401,"message":"Token is expired"}')
        did = url[len(URL) + len("/v1/decisions/"):]
        if did not in self.current:
            msg = f"decision with id '{did}' doesn't exist: unable to delete"
            return FakeStreamResponse(500, _json.dumps({"message": msg}).encode())
        self.delete(did)
        return FakeStreamResponse(200, b'{"nbDeleted":"1"}')

    def install(self, test):
        self._prev, self._prev_post = requests.get, requests.post
        self._prev_delete = getattr(requests, "delete")
        for name, fn in (("get", self._get), ("post", self._post), ("delete", self._delete)):
            p = mock.patch.object(requests, name, fn)
            p.start()
            test.addCleanup(p.stop)
        return self
