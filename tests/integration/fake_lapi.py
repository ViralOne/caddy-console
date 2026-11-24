"""A fake CrowdSec LAPI for the plugin integration suite (never discovered).

Speaks the bouncer side of LAPI v1: GET /v1/decisions/stream (startup=true
returns the active set, later polls the changes since that bouncer's last
poll), GET /v1/decisions (live mode: always null) and POST /v1/usage-metrics.
Each bouncer is told apart by its key: FAKE_LAPI_KEYS="console:<key>,plugin:<key>",
and the two keys must differ. The suite drives it through /it/* with the
FAKE_LAPI_CONTROL token. Runs only on the internal crowdsec-lapi network.

  python -m tests.integration.fake_lapi
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

KEYS = {}
for item in os.environ.get("FAKE_LAPI_KEYS", "").split(","):
    name, _, key = item.partition(":")
    if name and key:
        KEYS[key] = name
if len(KEYS) != 2 or set(KEYS.values()) != {"console", "plugin"}:
    sys.exit("fake_lapi: FAKE_LAPI_KEYS needs two different keys named console and plugin")
CONTROL = os.environ["FAKE_LAPI_CONTROL"]
lock = threading.Lock()
state = {"seq": 0, "events": [], "active": {}, "cursors": {}, "calls": [], "next_id": 1000}


def decision(value, origin, scenario, scope):
    state["next_id"] += 1
    return {"id": state["next_id"], "origin": origin, "scenario": scenario, "scope": scope, "type": "ban",
            "value": value, "duration": "3h59m58s"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(n, 1 << 20)) if n else b""
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return {}

    def _bouncer(self, path, query):
        name = KEYS.get(self.headers.get("X-Api-Key", ""))
        with lock:
            state["calls"].append({"name": name, "ua": self.headers.get("User-Agent", "")[:100], "path": path,
                                   "startup": (query.get("startup") or [""])[0]})
            del state["calls"][:-500]
        return name

    def do_GET(self):
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        if u.path == "/it/calls":
            if self.headers.get("X-Control") != CONTROL:
                return self._send(403, {"message": "control token"})
            with lock:
                return self._send(200, state["calls"])
        name = self._bouncer(u.path, q)
        if name is None:
            return self._send(403, {"message": "access forbidden"})
        if u.path == "/v1/decisions/stream":
            startup = (q.get("startup") or ["false"])[0] == "true"
            with lock:
                since = 0 if startup else state["cursors"].get(name, 0)
                if startup:
                    new, deleted = list(state["active"].values()), []
                else:
                    new = [d for s, kind, d in state["events"] if s > since and kind == "new"]
                    deleted = [{**d, "duration": "-1s"} for s, kind, d in state["events"] if s > since and kind == "deleted"]
                state["cursors"][name] = state["seq"]
            sys.stderr.write(f"fake_lapi: stream {name} startup={startup} cursor {since}->{state['seq']} "
                             f"new={len(new)} deleted={len(deleted)}\n")
            return self._send(200, {"new": new or None, "deleted": deleted or None})
        if u.path == "/v1/decisions":
            return self._send(200, None)
        return self._send(404, {"message": "not found"})

    def do_POST(self):
        u = urlsplit(self.path)
        if u.path.startswith("/it/"):
            if self.headers.get("X-Control") != CONTROL:
                return self._send(403, {"message": "control token"})
            body = self._body()
            with lock:
                state["seq"] += 1
                if u.path == "/it/add":
                    d = decision(body["value"], body.get("origin", "lists:it"), body.get("scenario", "it/plugin"),
                                 body.get("scope", "Ip"))
                    state["active"][d["id"]] = d
                    state["events"].append((state["seq"], "new", d))
                    return self._send(200, d)
                if u.path == "/it/delete":
                    d = state["active"].pop(int(body["id"]), None)
                    if d:
                        state["events"].append((state["seq"], "deleted", d))
                    return self._send(200, {"deleted": bool(d)})
            return self._send(404, {"message": "not found"})
        name = self._bouncer(u.path, {})
        if name is None:
            return self._send(403, {"message": "access forbidden"})
        self._body()
        return self._send(201, {})

    def log_message(self, fmt, *args):
        sys.stderr.write("fake_lapi: " + (fmt % args) + "\n")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
