"""Decision stream client and classification (spec 2.4).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_lapi -v
"""
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import tests._env  # noqa: F401
from tests import _bans, _crowdsec

from src.bans import addr, lapi

NOW = datetime(2026, 11, 24, 12, 0, 0, tzinfo=timezone.utc)
ORIGINS = ("crowdsec", "cscli")


def d(**kw):
    base = {"id": "7", "scope": "Ip", "value": "203.0.113.7", "type": "ban", "origin": "crowdsec",
            "scenario": "crowdsecurity/http-probing", "remaining": 3600.0}
    base.update(kw)
    return lapi.Decision(**base)


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

    def test_oversized_response_is_malformed(self):
        self.lapi.mode, self.lapi.raw = "raw", b" " * 64
        with mock.patch.object(lapi, "MAX_BYTES", 32), self.assertRaises(lapi.LapiMalformed):
            lapi.fetch_stream(_crowdsec.URL, _crowdsec.KEY, startup=True, origins=ORIGINS)


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
