"""Client-IP trust profiles and cloudflare-trusted-proxies.caddy (spec 4.1).

Run with:  uv run --frozen python -m unittest tests.test_client_ip_profile -v
"""
import json
import os
import unittest
from unittest import mock

import tests._env as env
from tests import _bans

from src import audit, config
from src.bans import cfranges, fsio, profile, render, scan, service, store

D = env.BANS_DIR
GLOBAL = ("{{\n\tservers {{\n\t\timport {d}/cloudflare-trusted-proxies*.caddy\n"
          "\t\tclient_ip_headers CF-Connecting-IP\n\t}}\n}}\n\n").format(d=D)
SITE = GLOBAL + _bans.MANUAL_SITE.format(bans_dir=D)
HEADER = "# Managed by Caddy Console. Do not edit; changes are overwritten.\n"


def read(path):
    return (fsio.read_bytes(path) or b"").decode()


class RenderTest(unittest.TestCase):
    def test_direct_is_comment_only(self):
        text = profile.render(profile.Profile(mode="direct")).decode()
        self.assertTrue(text.startswith(HEADER))
        self.assertNotIn("trusted_proxies", text.replace("# Direct mode: no trusted proxies", ""))
        self.assertTrue(all(line.startswith("#") for line in text.splitlines()))

    def test_proxied_lists_every_ipv4_and_ipv6_edge_range(self):
        text = profile.render(profile.Profile(mode="cloudflare-proxied")).decode()
        line = text.splitlines()[1]
        self.assertTrue(line.startswith("trusted_proxies static 103.21.244.0/22 "))
        for net in cfranges.BUNDLED["v4"] + cfranges.BUNDLED["v6"]:
            self.assertIn(" " + net, line)
        self.assertNotIn("private_ranges", text)

    def test_tunnel_trusts_the_fixed_cloudflared_address_only(self):
        p = profile.Profile(mode="cloudflare-tunnel", tunnel_peers=profile.validate_peers(
            ["172.31.0.2"], "cloudflare-tunnel", False))
        self.assertEqual(profile.render(p).decode(), HEADER + "trusted_proxies static 172.31.0.2/32\n")
        self.assertEqual(p.protected_networks(), [], "tunnel mode adds no edge ranges")


class PeerValidationTest(unittest.TestCase):
    def check(self, values, code, tunnel_only=False):
        with self.assertRaises(profile.InputError) as cm:
            profile.validate_peers(values, "cloudflare-tunnel", tunnel_only)
        self.assertEqual(cm.exception.code, code)

    def test_private_ranges_needs_a_confirmed_tunnel_only_listener(self):
        self.check(["private_ranges"], "broad_trust_refused")
        self.assertEqual(profile.validate_peers(["private_ranges"], "cloudflare-tunnel", True), ["private_ranges"])

    def test_peers_must_be_narrow_private_networks(self):
        self.check([], "tunnel_peer_required")
        self.check(["203.0.113.5"], "invalid_peer")
        self.check(["172.16.0.0/12"], "broad_trust_refused")
        self.check(["fd00::/48"], "broad_trust_refused")
        self.check(["not-an-ip"], "invalid_peer")
        self.check(["10.0.0.1"] * 5, "too_many_peers")
        self.assertEqual(profile.validate_peers(["172.31.0.0/29", "fd00:cf::2"], "cloudflare-tunnel", False),
                         ["172.31.0.0/29", "fd00:cf::2/128"])

    def test_other_modes_ignore_peers(self):
        self.assertEqual(profile.validate_peers(["private_ranges"], "cloudflare-proxied", False), [])

    def test_startup_rejects_an_unknown_mode(self):
        with mock.patch.object(config, "CLIENT_IP_MODE", "cloudflare"):
            with self.assertRaisesRegex(RuntimeError, "CLIENT_IP_MODE"):
                service.init_config()


class TrustWarningTest(unittest.TestCase):
    TEXT = "{\n\tservers {\n\t\ttrusted_proxies static private_ranges\n\t}\n}\n"

    def test_broad_trust_warns_unless_tunnel_only(self):
        self.assertIn("Line 3: trusted_proxies private_ranges", scan.trust_warnings(self.TEXT, "direct")[0])
        self.assertTrue(scan.trust_warnings(self.TEXT, "cloudflare-tunnel", False))
        self.assertEqual(scan.trust_warnings(self.TEXT, "cloudflare-tunnel", True), [])
        self.assertEqual(scan.trust_warnings(self.TEXT.replace("private_ranges", "172.31.0.2/32"), "direct"), [])


class ProfileApiTest(_bans.ApiCase):
    def setUp(self):
        super().setUp()
        service.reset_caches()
        self.addCleanup(service.reset_caches)
        _bans.write_caddyfile(SITE)

    def put(self, payload, **kw):
        return super().put("/api/security/client-ip-profile", payload, **kw)

    def test_put_needs_login_and_csrf(self):
        url = "/api/security/client-ip-profile"
        self.assertEqual(self.client.put(url, json={"mode": "direct"}, headers=_bans.AUTH).status_code, 403)
        self.assertEqual(self.client.put(url, json={"mode": "direct"}, headers={"X-CSRF-Token": self.csrf}).status_code, 401)
        self.assertEqual(self.client.get(url).status_code, 401)

    def test_direct_default_writes_nothing(self):
        self.assertEqual(service.expire_tick(), "idle")
        self.assertFalse(os.path.exists(render.PROFILE.path))
        self.assertFalse(os.path.exists(profile.PATH))
        info = self.get("/api/security/client-ip-profile").get_json()
        self.assertEqual((info["mode"], info["stored"], info["present"]), ("direct", False, False))

    def test_proxied_regenerates_trust_and_the_protected_set_in_one_transaction(self):
        self.post("/api/bans", {"value": "203.0.113.7", "duration": "4h", "reason": ""})
        before = read(render.SOURCES["manual"].path)
        self.assertNotIn("173.245.48.0/20", before)
        self.caddy.calls.clear()
        r = self.put({"mode": "cloudflare-proxied"})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(r.get_json()["reload_status"], "applied")
        self.assertEqual([k for k, _ in self.caddy.calls].count("load"), 1, "one /load for the whole set")
        self.assertIn(" 173.245.48.0/20", read(render.PROFILE.path))
        manual = read(render.SOURCES["manual"].path)
        self.assertIn("173.245.48.0/20", manual.split("not client_ip", 1)[1])
        self.assertIn("2400:cb00::/32", manual.split("not client_ip", 1)[1])
        doc = json.loads(read(profile.PATH))
        self.assertEqual(doc["mode"], "cloudflare-proxied")
        self.assertEqual(doc["last_rendered_hashes"]["cloudflare-trusted-proxies.caddy"],
                         fsio.sha256_tag(fsio.read_bytes(render.PROFILE.path)))
        self.assertEqual(store.load().last_rendered_hashes["bans-manual.caddy"],
                         fsio.sha256_tag(fsio.read_bytes(render.SOURCES["manual"].path)))
        self.assertEqual(oct(os.stat(render.PROFILE.path).st_mode & 0o777), "0o644")
        self.assertEqual(oct(os.stat(profile.PATH).st_mode & 0o777), "0o600")
        self.assertIn(("client_ip_profile_changed", "cloudflare-proxied"),
                      [(e["action"], e["detail"]) for e in audit.iter_entries()])

    def test_edge_ranges_cannot_be_banned_in_proxied_mode(self):
        self.put({"mode": "cloudflare-proxied"})
        r = self.post("/api/bans", {"value": "173.245.48.10", "duration": "4h", "reason": ""})
        self.assertEqual(r.status_code, 400)
        self.assertEqual((r.get_json()["code"], r.get_json()["category"]), ("protected_overlap", "profile"))
        self.put({"mode": "direct"})
        r = self.post("/api/bans", {"value": "173.245.48.10", "duration": "4h", "reason": ""})
        self.assertEqual(r.status_code, 201, "direct mode is independent of Cloudflare")

    def test_tunnel_needs_valid_peers_and_writes_nothing_on_error(self):
        for payload, code in (({"mode": "cloudflare-tunnel"}, "tunnel_peer_required"),
                              ({"mode": "cloudflare-tunnel", "tunnel_peers": ["private_ranges"]}, "broad_trust_refused"),
                              ({"mode": "cloudflare"}, "invalid_mode"), (["x"], "invalid_request")):
            r = self.put(payload)
            self.assertEqual((r.status_code, r.get_json()["code"]), (400, code), payload)
        self.assertFalse(os.path.exists(render.PROFILE.path))
        self.assertFalse(os.path.exists(profile.PATH))
        r = self.put({"mode": "cloudflare-tunnel", "tunnel_peers": ["172.31.0.2"]})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(read(render.PROFILE.path), HEADER + "trusted_proxies static 172.31.0.2/32\n")
        r = self.put({"mode": "cloudflare-tunnel", "tunnel_peers": ["private_ranges"], "tunnel_only": True})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(read(render.PROFILE.path), HEADER + "trusted_proxies static private_ranges\n")

    def test_env_default_profile_is_rendered_by_the_tick(self):
        with mock.patch.object(config, "CLIENT_IP_MODE", "cloudflare-proxied"):
            self.assertEqual(service.expire_tick(), "applied")
            self.assertIn("trusted_proxies static", read(render.PROFILE.path))
            self.assertEqual(json.loads(read(profile.PATH))["mode"], "cloudflare-proxied")
            self.assertEqual(service.expire_tick(), "idle")

    def test_out_of_band_truncation_holds_until_reapply(self):
        self.put({"mode": "cloudflare-proxied"})
        with open(render.PROFILE.path, "w") as f:
            f.write("")
        body = self.get("/api/security").get_json()
        self.assertEqual(body["client_ip_profile"]["hold"], "differs")
        self.assertIn("cloudflare-trusted-proxies.caddy", body["recovery"]["files"])
        self.assertEqual(service.expire_tick(), "idle", "a held file is not regenerated")
        self.assertEqual(read(render.PROFILE.path), "")
        r = self.post("/api/security/reapply", {"source": "cloudflare"})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertIn("trusted_proxies static", read(render.PROFILE.path))
        self.assertFalse(self.get("/api/security").get_json()["recovery"]["required"])

    def test_reset_returns_to_direct(self):
        self.put({"mode": "cloudflare-tunnel", "tunnel_peers": ["172.31.0.2"]})
        self.assertEqual(self.post("/api/security/reset", {"source": "cloudflare"}).get_json()["code"],
                         "confirmation_required")
        r = self.post("/api/security/reset", {"source": "cloudflare", "confirm": True})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(json.loads(read(profile.PATH))["mode"], "direct")
        self.assertNotIn("trusted_proxies static", read(render.PROFILE.path).replace("no trusted proxies", ""))

    def test_status_compares_the_live_servers(self):
        self.put({"mode": "cloudflare-tunnel", "tunnel_peers": ["172.31.0.2"]})
        self.caddy.live = {"apps": {"http": {"servers": {"srv0": {
            "listen": [":443"], "trusted_proxies": {"source": "static", "ranges": ["172.31.0.2/32"]},
            "client_ip_headers": ["CF-Connecting-IP"]}}}}}
        p = self.get("/api/security").get_json()["client_ip_profile"]
        self.assertEqual((p["mode"], p["imported"], p["current"]), ("cloudflare-tunnel", True, True))
        self.assertEqual(p["live"][0]["matches"], True)
        self.caddy.live["apps"]["http"]["servers"]["srv0"]["trusted_proxies"]["ranges"] = ["192.168.0.0/16"]
        self.assertFalse(self.get("/api/security").get_json()["client_ip_profile"]["live"][0]["matches"])

    def test_validate_warns_about_broad_trust(self):
        text = "{\n\tservers {\n\t\ttrusted_proxies static private_ranges\n\t}\n}\nexample.com {\n\trespond 200\n}\n"
        warnings = self.post("/api/validate", {"content": text}).get_json()["warnings"]
        self.assertTrue(any("forge the client IP" in w for w in warnings), warnings)


if __name__ == "__main__":
    unittest.main()
