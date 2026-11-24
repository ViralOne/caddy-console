"""Cloudflare range refresh and its dependency-expanded transaction (spec 4.2).

Run with:  uv run --frozen python -m unittest tests.test_cloudflare_ranges -v
"""
import json
import os
import unittest
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import audit, config
from src.bans import cfranges, fsio, plugin, pluginpolicy, profile, render, service, store, txn

D = env.BANS_DIR
V4 = "\n".join(cfranges.BUNDLED["v4"]) + "\n"
V6 = "\n".join(cfranges.BUNDLED["v6"]) + "\n"
DROPPED = "131.0.72.0/22"
V4_LESS = V4.replace(DROPPED + "\n", "")
SITE = ("{{\n\tservers {{\n\t\timport {d}/cloudflare-trusted-proxies*.caddy\n\t\tclient_ip_headers CF-Connecting-IP\n"
        "\t}}\n}}\n\nexample.com {{\n\timport {d}/bans-manual*.caddy\n\trespond 200\n}}\n").format(d=D)


class FakeResp:
    def __init__(self, status, body):
        self.status_code, self.body = status, body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_content(self, n):
        for i in range(0, len(self.body), n):
            yield self.body[i:i + n]


class FakeSession:
    def __init__(self, v4=V4, v6=V6, status=200):
        self.bodies = {cfranges.URLS["v4"]: v4, cfranges.URLS["v6"]: v6}
        self.status, self.calls = status, []

    def get(self, url, **kw):
        self.calls.append(url)
        body = self.bodies[url]
        return FakeResp(self.status, body.encode() if isinstance(body, str) else body)


class ParseTest(unittest.TestCase):
    def test_canonical_ipv4_and_ipv6(self):
        self.assertEqual(cfranges.parse_list("104.16.0.0/13\n\n 103.21.244.0/22 \n", "v4"),
                         ["103.21.244.0/22", "104.16.0.0/13"])
        self.assertEqual(cfranges.parse_list("2400:cb00::/32\n", "v6"), ["2400:cb00::/32"])

    def test_rejects_malformed_empty_wrong_family_private_and_oversize(self):
        for text, fam in (("", "v4"), ("<html>", "v4"), ("2400:cb00::/32", "v4"), ("10.0.0.0/8", "v4"),
                          ("0.0.0.0/0", "v4"), ("104.16.0.1/13", "v4"), ("x" * (cfranges.MAX_BYTES + 1), "v4"),
                          ("\n".join(f"198.18.{i}.0/24" for i in range(65)), "v4")):
            with self.subTest(text=text[:30]):
                with self.assertRaises(cfranges.RangeError):
                    cfranges.parse_list(text, fam)

    def test_implausible_diff(self):
        old = cfranges.bundled()
        self.assertIsNone(cfranges.plausible(old, old))
        small = {"v4": ["173.245.48.0/20"], "v6": old["v6"]}
        self.assertIn("less than 50%", cfranges.plausible(old, small))
        grown = {"v4": old["v4"] + ["198.51.100.0/24"], "v6": old["v6"]}
        self.assertIsNone(cfranges.plausible(old, grown))

    def test_implausible_growth_is_refused(self):
        old = cfranges.bundled()
        wide4 = {"v4": old["v4"] + ["8.0.0.0/11"], "v6": old["v6"]}
        self.assertIn("wider than /12", cfranges.plausible(old, wide4))
        wide6 = {"v4": old["v4"], "v6": old["v6"] + ["2001:4800::/28"]}
        self.assertIn("wider than /29", cfranges.plausible(old, wide6))
        edge = {"v4": old["v4"] + ["8.0.0.0/12"], "v6": old["v6"] + ["2001:4800::/29"]}
        self.assertIsNone(cfranges.plausible(old, edge), "/12 and /29 are the widest accepted")
        many = {"v4": old["v4"] + [f"{o}.0.0.0/13" for o in range(20, 32)], "v6": old["v6"]}
        self.assertIn("grows", cfranges.plausible(old, many))
        many6 = {"v4": old["v4"], "v6": old["v6"] + ["2001:4800::/29", "2001:5800::/29", "2001:6800::/29"]}
        self.assertIn("grows", cfranges.plausible(old, many6))


    def test_growth_cannot_ratchet_past_the_bundled_list(self):
        import ipaddress
        base = cfranges.bundled()
        size = sum(ipaddress.ip_network(x).num_addresses for x in base["v4"])
        blocks = iter(f"{o}.0.0.0/13" for o in range(20, 120))

        def grow_to(prev, factor):
            nets = list(prev["v4"])
            while sum(ipaddress.ip_network(x).num_addresses for x in nets) < factor * size:
                nets.append(next(blocks))
            return {"v4": nets, "v6": base["v6"]}
        step1 = grow_to(base, 1.6)
        self.assertIsNone(cfranges.plausible(base, step1))
        step2 = grow_to(step1, 2.4)               # under 2x the previous list, over 2x the bundled one
        self.assertIn("grows", cfranges.plausible(step1, step2))


class RefreshTest(_bans.ApiCase):
    def setUp(self):
        super().setUp()
        service.reset_caches()
        plugin.reset_cache()
        self.addCleanup(plugin.reset_cache)
        _bans.write_caddyfile(SITE)
        self.put("/api/security/client-ip-profile", {"mode": "cloudflare-proxied"})

    def refresh(self, session, manual=False):
        return service.refresh_cloudflare_ranges("t@example.com", manual=manual, session=session)

    def test_first_refresh_marks_the_source_and_changes_nothing_else(self):
        body, status = self.refresh(FakeSession())
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(fsio.read_bytes(profile.PATH))["ranges_source"], "cloudflare")

    def test_changed_list_regenerates_every_dependent_file_in_one_journal(self):
        _crowdsec.enable(self)
        self.caddy.plugin = True
        self.assertIs(plugin.module_available(force=True), True)
        self.post("/api/bans", {"value": "203.0.113.7", "duration": "4h", "reason": ""})
        _crowdsec.FakeLapi().install(self)
        self.assertEqual(service.expire_tick(), "idle")
        self.assertTrue(os.path.exists(render.PLUGIN.path))
        seen = []
        real = txn.apply_locked

        def spy(changes, **kw):
            seen.append(sorted(os.path.basename(c.path) for c in changes))
            return real(changes, **kw)
        self.caddy.calls.clear()
        with mock.patch.object(txn, "apply_locked", spy):
            body, status = self.refresh(FakeSession(v4=V4_LESS))
        self.assertEqual(status, 200, body)
        self.assertEqual(len(seen), 1, "one transaction")
        self.assertEqual(seen[0], sorted(["bans-crowdsec.caddy", "bans-manual.caddy", "bans.json",
                                          "cloudflare-ranges.json", "cloudflare-trusted-proxies.caddy",
                                          "crowdsec-plugin-protect.caddy", "plugin-policy.json"]))
        self.assertEqual([k for k, _ in self.caddy.calls].count("load"), 1)
        self.assertNotIn(DROPPED, fsio.read_bytes(render.PROFILE.path).decode())
        self.assertIn("173.245.48.0/20", fsio.read_bytes(render.PROFILE.path).decode())
        for path in (render.SOURCES["manual"].path, render.PLUGIN.path):
            self.assertNotIn("173.245.48.0/20", fsio.read_bytes(path).decode(), "the edge is never an exclusion")
        st = store.load()
        for name in ("bans-manual.caddy", "bans-crowdsec.caddy"):
            self.assertEqual(st.last_rendered_hashes[name], fsio.sha256_tag(fsio.read_bytes(os.path.join(D, name))))
        self.assertEqual(pluginpolicy.recorded_hash(), fsio.sha256_tag(fsio.read_bytes(render.PLUGIN.path)))
        self.assertEqual(profile.recorded_hash(), fsio.sha256_tag(fsio.read_bytes(render.PROFILE.path)))
        self.assertIn("cloudflare_ranges_updated", [e["action"] for e in audit.iter_entries()])

    def test_crash_mid_transaction_recovers_every_dependent_hash(self):
        self.post("/api/bans", {"value": "203.0.113.7", "duration": "4h", "reason": ""})
        before = {p: fsio.read_bytes(p) for p in (render.PROFILE.path, render.SOURCES["manual"].path,
                                                  profile.PATH, store.STATE_PATH)}
        with _bans.crash_at("replaced:cloudflare-trusted-proxies.caddy"):
            with self.assertRaises(_bans.SimulatedCrash):
                self.refresh(FakeSession(v4=V4_LESS))
        self.assertIsNone(txn.resolve_pending(), "live still runs the previous config: restored")
        self.assertEqual({p: fsio.read_bytes(p) for p in before}, before)

    def test_bad_responses_keep_the_last_good_list(self):
        before = fsio.read_bytes(render.PROFILE.path)
        for session in (FakeSession(v4=""), FakeSession(status=503), FakeSession(v4="not a network\n"),
                        FakeSession(v4="173.245.48.0/20\n"), FakeSession(v6=b"\xff" * 10),
                        FakeSession(v4="198.18.0.0/24\n" * 2000),
                        FakeSession(v4=V4 + "8.0.0.0/11\n")):
            with self.subTest(session=session.bodies):
                body, status = self.refresh(session)
                self.assertEqual((status, body["code"]), (502, "ranges_refused"))
                self.assertEqual(fsio.read_bytes(render.PROFILE.path), before)
                self.assertEqual(json.loads(fsio.read_bytes(profile.PATH))["ranges_source"], "bundled")
        self.assertTrue(service._ranges_check_meta()["last_error"])

    def test_manual_refresh_is_rate_limited(self):
        session = FakeSession()
        with mock.patch("src.bans.service.http_client.Session", lambda: session):
            r = self.post("/api/security/cloudflare-ranges/refresh")
            self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
            r = self.post("/api/security/cloudflare-ranges/refresh")
            self.assertEqual((r.status_code, r.get_json()["code"]), (429, "rate_limited"))
        self.assertEqual(len(session.calls), 2, "one fetch of each list")

    def test_daily_tick_only_in_proxied_mode_and_once_a_day(self):
        session = FakeSession()
        self.assertEqual(service.ranges_tick(session=session), "updated", "bundled -> fetched")
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(service.ranges_tick(session=session), "current")
        self.assertEqual(len(session.calls), 2, "not due again for a day")
        self.put("/api/security/client-ip-profile", {"mode": "direct"})
        os.remove(service.RANGES_CHECK_PATH)
        self.assertEqual(service.ranges_tick(session=session), "not_needed")
        self.assertEqual(len(session.calls), 2, "direct mode never contacts Cloudflare")
        with mock.patch.object(config, "CLOUDFLARE_RANGES_AUTO_UPDATE", False):
            self.assertEqual(service.ranges_tick(session=session), "disabled")

    def test_concurrent_mode_change_between_fetch_and_commit_wins(self):
        real = cfranges.fetch

        def fetch_then_switch(session):
            out = real(session)
            r = self.put("/api/security/client-ip-profile",
                         {"mode": "cloudflare-tunnel", "tunnel_peers": ["172.31.0.2"]})
            self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
            return out
        with mock.patch.object(cfranges, "fetch", fetch_then_switch):
            body, status = self.refresh(FakeSession(v4=V4_LESS))
        self.assertEqual((status, body["code"]), (409, "version_conflict"))
        doc = json.loads(fsio.read_bytes(profile.PATH))
        self.assertEqual((doc["mode"], doc["tunnel_peers"], doc["ranges_source"]),
                         ("cloudflare-tunnel", ["172.31.0.2/32"], "bundled"))
        self.assertIn(DROPPED, doc["ranges"]["v4"])
        self.assertIn("172.31.0.2/32", fsio.read_bytes(render.PROFILE.path).decode())

    def test_concurrent_peer_change_is_not_overwritten(self):
        self.put("/api/security/client-ip-profile", {"mode": "cloudflare-tunnel", "tunnel_peers": ["172.31.0.2"]})
        real = cfranges.fetch

        def fetch_then_edit(session):
            out = real(session)
            self.put("/api/security/client-ip-profile", {"mode": "cloudflare-tunnel", "tunnel_peers": ["172.31.0.3"]})
            return out
        with mock.patch.object(cfranges, "fetch", fetch_then_edit):
            body, status = self.refresh(FakeSession(v4=V4_LESS), manual=True)
        self.assertEqual((status, body["code"]), (409, "version_conflict"))
        self.assertEqual(json.loads(fsio.read_bytes(profile.PATH))["tunnel_peers"], ["172.31.0.3/32"])

    def test_failed_check_retries_after_an_hour(self):
        self.assertEqual(service.ranges_tick(session=FakeSession(status=500)), "failed")
        self.assertFalse(service.ranges_due())
        meta = service._ranges_check_meta()
        meta["checked_at"] = "2000-01-01T00:00:00Z"
        with open(service.RANGES_CHECK_PATH, "w") as f:
            json.dump(meta, f)
        self.assertTrue(service.ranges_due())


if __name__ == "__main__":
    unittest.main()
