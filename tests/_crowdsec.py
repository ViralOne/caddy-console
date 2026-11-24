"""Shared fixtures for the CrowdSec tests (not a test module: never discovered).

FakeLapi stands in for CrowdSec's Local API by patching requests.get. Install it
after _bans.FakeCaddy: GETs that are not for URL go to the previous requests.get,
so both fakes work in one test. Empty lists are sent as null, as LAPI does.
"""
import json
from datetime import timedelta
from unittest import mock

import requests

from src import config

URL = "http://crowdsec.invalid:8080"
KEY = "console-test-key-6f1d0c2a9b"


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
        self.mode = "ok"                     # ok | down | status | raw
        self.status = 200
        self.raw = b""
        self.calls = []
        self._seq = 100

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
                           "allow_redirects": kw.get("allow_redirects"), "timeout": timeout})
        if self.mode == "down":
            raise requests.ConnectionError("fake lapi is down")
        if self.mode == "status":
            return FakeStreamResponse(self.status, b'{"message":"access forbidden"}')
        if self.mode == "raw":
            return FakeStreamResponse(200, self.raw)
        return FakeStreamResponse(200, self._body((params or {}).get("startup") == "true"))

    def install(self, test):
        self._prev = requests.get
        p = mock.patch.object(requests, "get", self._get)
        p.start()
        test.addCleanup(p.stop)
        return self
