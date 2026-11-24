"""Per-site country policy status and the Phase 4 blocks of GET /api/security.

Run with:  uv run --frozen python -m unittest tests.test_security_status -v
"""
import unittest
from unittest import mock

from tests import _bans
from tests.test_country_policy import SITE, URL, install_dataset, remove_dataset

from src import config
from src.bans import detect, profile, service

MARK = "caddy_console_country_policy"


def denial():
    return {"match": [{"not": [{"client_ip": {"ranges": ["192.0.2.0/24"]}}]}],
            "handle": [{"handler": "subroute", "routes": [{"handle": [
                {"handler": "static_response", "status_code": 403}]}]}]}


def live(shape, *, before=(), with_denial=True):
    routes = [{"handle": [*before, {"handler": "vars", MARK: shape}]}]
    if with_denial:
        routes.append(denial())
    return {"apps": {"http": {"servers": {"srv0": {"listen": [":443"], "routes": [
        {"match": [{"host": ["example.com"]}], "handle": [{"handler": "subroute", "routes": routes}]}]}}}}}


def one(config_, **kw):
    (row,) = detect.country_site_statuses(config_, **kw)
    return row


class DetectTest(unittest.TestCase):
    def test_marker_and_denial_are_enforced(self):
        self.assertEqual(one(live("direct"), expected_shape="direct").status, "enforced")
        self.assertEqual(one(live("cloudflare")).status, "enforced")

    def test_off_marker_is_imported_empty_and_no_marker_is_not_imported(self):
        self.assertEqual(one(live("off", with_denial=False), expected_shape="off").status, "imported_empty")
        self.assertEqual(one({"apps": {"http": {"servers": {"s": {"routes": [{"handle": []}]}}}}}).status,
                         "not_imported")

    def test_marker_without_its_denial_is_unknown(self):
        row = one(live("direct", with_denial=False))
        self.assertEqual(row.status, "unknown")
        self.assertIn("denial", row.detail)

    def test_a_shape_the_settings_no_longer_render_is_unknown(self):
        row = one(live("direct"), expected_shape="cloudflare")
        self.assertEqual(row.status, "unknown")
        self.assertIn("render", row.detail)

    def test_handlers_before_the_marker_are_reported(self):
        self.assertEqual(one(live("direct", before=[{"handler": "headers", "request": {"set": {"X": ["1"]}}}])).status,
                         "enforced_pre_handler")
        row = one(live("direct", before=[{"handler": "static_response", "body": "x"}]))
        self.assertEqual((row.status, row.pre_handlers), ("unknown", ["respond"]))


class StatusTest(_bans.ApiCase):
    def setUp(self):
        super().setUp()
        service.reset_caches()
        self.addCleanup(service.reset_caches)
        install_dataset()
        self.addCleanup(remove_dataset)
        _bans.write_caddyfile(SITE)

    def status(self):
        return self.get("/api/security").get_json()

    def test_country_row_follows_the_live_marker_and_its_denial(self):
        self.assertEqual(self.put(URL, {"enabled": True, "countries": ["RO"]}).status_code, 200)
        body = self.status()
        row = body["sites"][0]["policies"]["country"]
        self.assertEqual((row["status"], row["import"]["present"]), ("unknown", True))
        self.assertIn("denial", row["detail"])
        self.caddy.live = live("direct")
        body = self.status()
        self.assertEqual(body["sites"][0]["policies"]["country"]["status"], "enforced")
        summary = body["country_policy"]["summary"]
        self.assertEqual((summary["mode"], summary["countries"], summary["healthy"], summary["live_ok"]),
                         ("direct", ["RO"], True, True))
        self.assertEqual(summary["prefixes"], {"v4": 1, "v6": 1, "total": 2})
        self.assertEqual((summary["cap"], summary["warn"]), (20000, 10000))

    def test_live_shape_mismatch_makes_the_summary_unhealthy(self):
        self.put(URL, {"enabled": True, "countries": ["RO"]})
        self.caddy.live = live("off", with_denial=False)
        body = self.status()
        self.assertEqual(body["sites"][0]["policies"]["country"]["status"], "unknown")
        self.assertFalse(body["country_policy"]["summary"]["healthy"])

    def test_cloudflare_mode_needs_the_geolocation_confirmation(self):
        self.assertEqual(self.put("/api/security/client-ip-profile", {"mode": "cloudflare-proxied"}).status_code, 200)
        self.put(URL, {"enabled": True, "countries": ["RO"]})
        self.caddy.live = live("cloudflare")
        self.assertFalse(self.status()["country_policy"]["summary"]["healthy"])
        self.put(URL, {"enabled": True, "countries": ["RO"], "cloudflare_geolocation_confirmed": True})
        self.caddy.live = live("cloudflare")
        self.assertFalse(self.status()["country_policy"]["summary"]["healthy"],
                         "Caddy does not run the profile's trusted proxies")
        self.caddy.live = live("cloudflare")
        srv = self.caddy.live["apps"]["http"]["servers"]["srv0"]
        srv["trusted_proxies"] = {"source": "static", "ranges": profile.load_or_default().peers()}
        srv["client_ip_headers"] = ["CF-Connecting-IP"]
        self.assertTrue(self.status()["country_policy"]["summary"]["healthy"])

    def test_no_country_row_while_the_policy_was_never_used(self):
        self.assertNotIn("country", self.status()["sites"][0]["policies"])

    def test_profile_block_reports_ranges_age_and_dependencies(self):
        self.put("/api/security/client-ip-profile", {"mode": "cloudflare-proxied"})
        block = self.status()["client_ip_profile"]
        self.assertEqual(block["mode"], "cloudflare-proxied")
        self.assertIn("source", block["ranges"])
        self.assertIn("age_seconds", block["ranges"])
        self.assertIn("cloudflare-trusted-proxies.caddy", [d["file"] for d in block["dependencies"]])


class SnippetTest(_bans.ApiCase):
    def snippets(self):
        body = self.get("/api/snippets").get_json()
        return {s.get("id") or s["name"]: s for s in body["snippets"]}, body["context"]

    def test_cloudflare_snippets_replace_the_ambiguous_one(self):
        by_id, ctx = self.snippets()
        self.assertNotIn("Cloudflare Only", by_id)
        self.assertEqual(by_id["cloudflare-proxied-real-ip"]["name"], "Cloudflare proxied DNS: real client IP")
        self.assertEqual(by_id["cloudflare-tunnel-real-ip"]["name"], "Cloudflare Tunnel: real client IP")
        self.assertEqual(by_id["country-policy-site"]["code"], f"import {config.BANS_DIR}/geo*.caddy\n")
        self.assertIn(f"import {config.BANS_DIR}/cloudflare-trusted-proxies*.caddy\n",
                      by_id["cloudflare-proxied-real-ip"]["code"])
        self.assertEqual((ctx["client_ip"]["mode"], ctx["client_ip"]["peers"]), ("direct", []))

    def test_origin_guard_carries_the_current_edge_ranges_and_never_a_header(self):
        self.assertEqual(self.put("/api/security/client-ip-profile", {"mode": "cloudflare-proxied"}).status_code, 200)
        by_id, ctx = self.snippets()
        guard = by_id["cloudflare-origin-guard"]["code"]
        self.assertEqual(ctx["client_ip"]["mode"], "cloudflare-proxied")
        self.assertTrue(ctx["client_ip"]["current"])
        for net in ctx["client_ip"]["ranges"]:
            self.assertIn(net, guard)
        self.assertIn("remote_ip", guard)
        self.assertNotRegex(guard, r"(?i)header|client_ip|X-Forwarded")


if __name__ == "__main__":
    unittest.main()
