"""Decision stream client and classification (spec 2.4).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_lapi -v
"""
import json
import socket
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import tests._env  # noqa: F401
import requests

from tests import _bans, _crowdsec

from src import config
from src.bans import addr, lapi

NOW = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)
ORIGINS = ("crowdsec", "cscli")


def d(**kw):
    base = {"id": "7", "scope": "Ip", "value": "203.0.113.7", "type": "ban", "origin": "crowdsec",
            "scenario": "crowdsecurity/http-probing", "remaining": 3600.0}
    base.update(kw)
    return lapi.Decision(**base)


def _worker_gone(timeout=5) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if not any(t.name == "crowdsec-lapi-request" for t in threading.enumerate()):
            return True
        time.sleep(0.01)
    return False


class FetchTest(unittest.TestCase):
    def setUp(self):
        _bans.FakeCaddy().install(self)
        self.lapi = _crowdsec.FakeLapi().install(self)

    def test_request_shape(self):
        self.lapi.add("203.0.113.7")
        stream = lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        call = self.lapi.calls[0]
        self.assertEqual(call["path"], "/v1/decisions/stream")
        self.assertEqual(call["params"], {"startup": "true", "scopes": "Ip,Range", "origins": "crowdsec,cscli"})
        self.assertEqual((call["key"], call["stream"], call["allow_redirects"]), (_crowdsec.KEY, True, False))
        self.assertEqual([x.value for x in stream.new], ["203.0.113.7"])
        lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=False, origins=ORIGINS)
        self.assertEqual(self.lapi.calls[1]["params"]["startup"], "false")

    def test_null_lists_are_empty(self):
        stream = lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=False, origins=ORIGINS)
        self.assertEqual((stream.new, stream.deleted), ((), ()))

    def test_errors_are_typed_and_never_carry_the_key(self):
        self.lapi.mode = "down"
        with self.assertRaises(lapi.LapiUnavailable) as cm:
            lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        self.assertNotIn(_crowdsec.KEY, str(cm.exception))
        self.lapi.mode = "status"
        for status, exc in ((401, lapi.LapiAuthError), (403, lapi.LapiAuthError), (500, lapi.LapiUnavailable)):
            self.lapi.status = status
            with self.subTest(status=status), self.assertRaises(exc) as cm:
                lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
            self.assertNotIn(_crowdsec.KEY, str(cm.exception))

    def test_malformed_bodies_never_carry_the_key(self):
        self.lapi.mode = "raw"
        for raw in (b"{", b"[]", json.dumps({"new": [{"id": "x", "value": _crowdsec.KEY}], "deleted": None}).encode()):
            self.lapi.raw = raw
            with self.subTest(raw=raw[:10]), self.assertRaises(lapi.LapiMalformed) as cm:
                lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
            self.assertNotIn(_crowdsec.KEY, str(cm.exception))

    def test_origins_are_sent_in_operator_case(self):
        lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=("CAPI", "cscli"))
        self.assertEqual(self.lapi.calls[0]["params"]["origins"], "CAPI,cscli")

    def test_user_agent_names_the_console_and_its_version(self):
        # CrowdSec (pkg/apiserver/middlewares/v1/api_key.go) splits the UA on "/"
        # and warns on every request unless it gets exactly name/version.
        lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        ua = self.lapi.calls[0]["headers"]["User-Agent"]
        self.assertEqual(ua, f"caddy-console/{config.APP_VERSION}")
        self.assertEqual(len(ua.split("/")), 2)
        self.assertNotIn(_crowdsec.KEY, ua)

    def test_redirect_is_refused_as_unavailable(self):
        self.lapi.mode = "status"
        for status in (301, 302, 307, 308):
            self.lapi.status = status
            with self.subTest(status=status), self.assertRaises(lapi.LapiUnavailable) as cm:
                lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
            self.assertEqual(str(cm.exception), f"HTTP {status}")
        self.assertTrue(all(c["allow_redirects"] is False for c in self.lapi.calls))

    def test_slow_drip_body_hits_the_total_deadline(self):
        # One byte, then a read that blocks until the watchdog shuts the socket
        # down: no single blocking call may outlast the deadline.
        class Sock:
            def __init__(self, woken):
                self.woken = woken

            def shutdown(self, how):
                self.woken.set()

        class Drip(_crowdsec.FakeStreamResponse):
            def __init__(self):
                super().__init__()
                self.woken = threading.Event()
                self.raw = type("Raw", (), {})()
                self.raw._connection = type("Conn", (), {})()
                self.raw._connection.sock = Sock(self.woken)

            def iter_content(self, chunk_size=1):
                yield b" "
                if not self.woken.wait(10):
                    return
                raise requests.ConnectionError("shut down by the watchdog")

        resp = Drip()
        self.lapi.mode, self.lapi.response = "response", resp
        started = time.monotonic()
        with mock.patch.object(lapi, "read_deadline", lambda: 0.3), self.assertRaises(lapi.LapiUnavailable) as cm:
            lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        self.assertLess(time.monotonic() - started, 2)
        self.assertIn("took too long", str(cm.exception))
        self.assertNotIn(_crowdsec.KEY, str(cm.exception))
        self.assertTrue(_worker_gone(), "the request thread must end once the socket is shut down")
        self.assertTrue(resp.closed, "the worker closes the response after its read returns")

    def test_hung_request_is_bounded_and_never_piles_up_threads(self):
        release = threading.Event()
        self.addCleanup(release.set)
        real_get = requests.get

        def hang(url, **kw):
            release.wait(10)
            return real_get(url, **kw)
        with mock.patch.object(requests, "get", hang), mock.patch.object(lapi, "read_deadline", lambda: 0.2):
            with self.assertRaisesRegex(lapi.LapiUnavailable, "took too long"):
                lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
            with self.assertRaisesRegex(lapi.LapiUnavailable, "previous request has not finished"):
                lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
            release.set()
            self.assertTrue(_worker_gone())
        self.lapi.add("203.0.113.7")
        stream = lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        self.assertEqual([x.value for x in stream.new], ["203.0.113.7"])

    def test_non_ban_decision_in_a_stream_is_parsed_then_ignored(self):
        self.lapi.add("203.0.113.7")
        self.lapi.add("203.0.113.8", type="captcha")
        stream = lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=False, origins=ORIGINS)
        self.assertEqual([x.type for x in stream.new], ["ban", "captcha"])
        results = [lapi.classify(x, ORIGINS, NOW)[1] for x in stream.new]
        self.assertEqual(results, [None, "not_ban"])

    def test_oversized_response_is_malformed(self):
        self.lapi.mode, self.lapi.raw = "raw", b" " * 64
        with mock.patch.object(lapi, "MAX_BYTES", 32), self.assertRaises(lapi.LapiMalformed):
            lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)

    def test_deadline_returns_even_when_the_socket_cannot_be_found(self):
        # (a) No private attribute path leads to a socket, and close() blocks
        # like BufferedReader.close() does while another thread is in read().
        # The caller must still return at the deadline and never call close().
        release = threading.Event()
        self.addCleanup(release.set)
        closed_by = []

        class Stuck(_crowdsec.FakeStreamResponse):
            def iter_content(self, chunk_size=1):
                yield b" "
                release.wait(10)
                raise requests.ConnectionError("released")

            def close(self):
                closed_by.append(threading.current_thread().name)
                release.wait(10)
                super().close()

        self.lapi.mode, self.lapi.response = "response", Stuck()
        started = time.monotonic()
        with mock.patch.object(lapi, "read_deadline", lambda: 0.3):
            with self.assertRaisesRegex(lapi.LapiUnavailable, "took too long"):
                lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        self.assertLess(time.monotonic() - started, 2)
        self.assertNotIn(threading.current_thread().name, closed_by)
        release.set()
        self.assertTrue(_worker_gone())
        self.assertEqual(closed_by, ["crowdsec-lapi-request"])

    def test_unexpected_exceptions_in_the_worker_are_unavailable(self):
        # (c) Not a RequestException: before the response, and while reading it.
        def boom(url, **kw):
            raise ValueError(f"bad url with {kw['headers']['X-Api-Key']}")
        with mock.patch.object(requests, "get", boom):
            with self.assertRaises(lapi.LapiUnavailable) as cm:
                lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        self.assertEqual(str(cm.exception), "the request failed (ValueError)")

        class Odd(_crowdsec.FakeStreamResponse):
            def iter_content(self, chunk_size=1):
                raise RuntimeError("urllib3 internals changed " + _crowdsec.KEY)
                yield b""
        self.lapi.mode, self.lapi.response = "response", Odd()
        with self.assertRaises(lapi.LapiUnavailable) as cm:
            lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)
        self.assertEqual(str(cm.exception), "reading the response failed (RuntimeError)")
        self.assertNotIn(_crowdsec.KEY, str(cm.exception))
        self.assertTrue(self.lapi.response.closed)


class DeadlineWindowTest(unittest.TestCase):
    def test_read_deadline_stays_inside_the_staleness_window(self):
        # (b) The longest gap between status writes is one poll wait plus one
        # fetch; it must stay below service's stale limit for every bound.
        from src.bans import service
        for poll in (5, 10, 60, 300):
            for sync in (10, 30, 600, 3600):
                with mock.patch.object(config, "CROWDSEC_POLL_INTERVAL", poll), \
                        mock.patch.object(config, "BANS_SYNC_INTERVAL", sync):
                    deadline = lapi.read_deadline()
                    limit = service.STALE_POLLS * poll + sync
                    self.assertLessEqual(deadline, lapi.READ_DEADLINE_MAX)
                    self.assertLessEqual(poll + deadline + lapi.DEADLINE_MARGIN, limit, (poll, sync))
                    self.assertGreaterEqual(deadline, 10, (poll, sync))
        with mock.patch.object(config, "CROWDSEC_POLL_INTERVAL", 5), mock.patch.object(config, "BANS_SYNC_INTERVAL", 10):
            self.assertEqual(lapi.read_deadline(), 15)
        with mock.patch.object(config, "CROWDSEC_POLL_INTERVAL", 10), mock.patch.object(config, "BANS_SYNC_INTERVAL", 30):
            self.assertEqual(lapi.read_deadline(), 45)


class RealSocketDeadlineTest(unittest.TestCase):
    """The watchdog against a real socket and the real requests/urllib3 stack:
    a peer on loopback sends valid headers, then one body byte every 50 ms."""

    def test_slow_drip_over_a_real_socket(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        self.addCleanup(server.close)
        stop = threading.Event()
        self.addCleanup(stop.set)

        def drip():
            conn, _ = server.accept()
            with conn:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n")
                try:
                    while not stop.wait(0.05):
                        conn.sendall(b" ")
                except OSError:
                    pass
        threading.Thread(target=drip, daemon=True).start()
        url = "http://127.0.0.1:%d" % server.getsockname()[1]
        started = time.monotonic()
        with mock.patch.object(lapi, "read_deadline", lambda: 0.5), self.assertRaisesRegex(lapi.LapiUnavailable, "took too long"):
            lapi.fetch_stream(url, _crowdsec.KEY, startup=True, origins=ORIGINS)
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(_worker_gone(), "shutting the socket down must end the blocked read")


class ParseTest(unittest.TestCase):
    def body(self, new=None, deleted=None):
        return json.dumps({"new": new, "deleted": deleted}).encode()

    def item(self, **kw):
        base = {"id": 2266, "origin": "CAPI", "scenario": "crowdsecurity/http-sensitive-files", "scope": "ip",
                "type": "ban", "value": "91.241.19.122/32", "duration": "22h20m11.909761348s"}
        base.update(kw)
        return base

    def test_documented_example(self):
        stream = lapi.parse_stream(self.body([self.item()], [self.item(id=1, duration="-18897h25m52.809576151s")]))
        self.assertEqual(stream.new[0].id, "2266")
        self.assertAlmostEqual(stream.new[0].remaining, 80411.909761348)
        self.assertEqual(stream.deleted, ("1",))

    def test_any_bad_item_rejects_the_whole_response(self):
        bad_items = [{"id": "x"}, self.item(id=True), self.item(id=0), self.item(duration="4d"),
                     self.item(value=7), self.item(value="x" * 65), self.item(scope=None), "nope"]
        for item in bad_items:
            with self.subTest(item=item), self.assertRaises(lapi.LapiMalformed):
                lapi.parse_stream(self.body([self.item(), item]))
        for raw in (b"", b"[]", b"{", b'{"new": {}}', "ÿ".encode("latin-1"), b'{"new": []}'):
            with self.subTest(raw=raw), self.assertRaises(lapi.LapiMalformed):
                lapi.parse_stream(raw)

    def test_too_many_decisions(self):
        with mock.patch.object(lapi, "MAX_DECISIONS", 1), self.assertRaises(lapi.LapiMalformed):
            lapi.parse_stream(self.body([self.item(), self.item(id=2)]))

    def test_missing_scenario_is_empty(self):
        item = self.item()
        del item["scenario"]
        self.assertEqual(lapi.parse_stream(self.body([item])).new[0].scenario, "")


class ClassifyTest(unittest.TestCase):
    def test_ban_ip_and_range(self):
        a, reason = lapi.classify(d(), ORIGINS, NOW)
        self.assertIsNone(reason)
        self.assertEqual((a.decision_id, addr.token(a.net), a.expires_at), ("7", "203.0.113.7", NOW + timedelta(hours=1)))
        a, _ = lapi.classify(d(scope="Range", value="198.51.100.0/24"), ORIGINS, NOW)
        self.assertEqual(addr.token(a.net), "198.51.100.0/24")

    def test_ip_scope_accepts_host_prefix_case_and_mapped_ipv6(self):
        for scope, value in (("ip", "91.241.19.122/32"), ("IP", "91.241.19.122"), ("Ip", "::ffff:91.241.19.122")):
            with self.subTest(value=value):
                a, reason = lapi.classify(d(scope=scope, value=value), ORIGINS, NOW)
                self.assertEqual((reason, addr.token(a.net)), (None, "91.241.19.122"))

    def test_ignored_reasons(self):
        cases = (
            (d(type="captcha"), "not_ban"),
            (d(scope="Country", value="RO"), "scope"),
            (d(origin="CAPI"), "origin"),
            (d(remaining=0.9), "expired"),
            (d(remaining=-5), "expired"),
            (d(value="not-an-ip"), "invalid_value"),
            (d(scope="Ip", value="198.51.100.0/24"), "invalid_value"),
            (d(scope="Range", value="198.0.0.0/8"), "too_wide"),
            (d(scope="Range", value="2001:db8::/32"), "too_wide"),
        )
        for decision, reason in cases:
            with self.subTest(reason=reason, value=decision.value):
                self.assertEqual(lapi.classify(decision, ORIGINS, NOW), (None, reason))

    def test_origin_compare_is_case_insensitive(self):
        a, reason = lapi.classify(d(origin="CAPI"), ("capi",), NOW)
        self.assertIsNone(reason)
        self.assertEqual(a.origin, "CAPI")


if __name__ == "__main__":
    unittest.main()
