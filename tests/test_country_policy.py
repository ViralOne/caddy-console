"""Country allowlist policy: state, geo.caddy rendering and the API (spec 4.3).

Run with:  uv run --frozen python -m unittest tests.test_country_policy -v
"""
import json
import os
import unittest
from unittest import mock

import tests._env as env
from tests import _bans

from src import audit, config
from src.bans import cfranges, country, countrydata, detect, fsio, jobs, profile, render, service, store

D = env.BANS_DIR
HEADER = "# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
BASE = "private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10"
CSV = ("192.0.2.0,192.0.2.255,RO\n198.51.100.0,198.51.100.255,DE\n203.0.113.0,203.0.113.255,FR\n"
       "2001:db8:1::,2001:db8:1:ffff:ffff:ffff:ffff:ffff,RO\n")
SITE = ("{{\n\tservers {{\n\t\timport {d}/cloudflare-trusted-proxies*.caddy\n\t\tclient_ip_headers CF-Connecting-IP\n"
        "\t}}\n}}\n\nexample.com {{\n\timport {d}/bans-manual*.caddy\n\timport {d}/geo*.caddy\n\trespond 200\n}}\n"
        ).format(d=D)
URL = "/api/security/country-policy"


def read(path):
    return (fsio.read_bytes(path) or b"").decode()


def install_dataset(csv=CSV, month="2026-11"):
    os.makedirs(env.GEOIP_DIR, exist_ok=True)
    with open(countrydata.path(env.GEOIP_DIR), "wb") as f:
        f.write(countrydata.dumps(countrydata.parse_csv(csv.splitlines()), month))


def remove_dataset():
    try:
        os.remove(countrydata.path(env.GEOIP_DIR))
    except FileNotFoundError:
        pass


class RenderTest(unittest.TestCase):
    def setUp(self):
        install_dataset()
        self.addCleanup(remove_dataset)
        p = mock.patch.object(config, "COUNTRY_POLICY_ENABLED", True)
        p.start()
        self.addCleanup(p.stop)

    def render(self, policy, mode="direct", peers=(), tokens=BASE.split()):
        return country.render(policy, mode, list(peers), tokens)

    def test_disabled_is_a_comment_and_the_off_marker_only(self):
        data, facts = self.render(country.Policy())
        self.assertEqual(data.decode(), HEADER + "# Country policy is off: no matcher or handler is generated.\n"
                         "vars caddy_console_country_policy off\n")
        self.assertEqual(facts["prefixes"]["total"], 0)

    def test_env_flag_off_renders_off_even_for_an_enabled_policy(self):
        with mock.patch.object(config, "COUNTRY_POLICY_ENABLED", False):
            data, _ = self.render(country.Policy(enabled=True, countries=["RO"]))
        self.assertIn("vars caddy_console_country_policy off", data.decode())
        self.assertNotIn("respond", data.decode())

    def test_direct_allows_the_selected_ranges_and_the_protected_set(self):
        data, facts = self.render(country.Policy(enabled=True, countries=["DE", "RO"]),
                                  tokens=BASE.split() + ["203.0.113.250/32"])
        self.assertEqual(data.decode(), HEADER + "vars caddy_console_country_policy direct\n"
                         "@caddy_console_country_denied {\n"
                         f"\tnot client_ip 192.0.2.0/24 198.51.100.0/24 2001:db8:1::/48 {BASE} 203.0.113.250/32\n}}\n"
                         "handle @caddy_console_country_denied {\n\trespond 403\n}\n")
        self.assertEqual((facts["prefixes"], facts["month"]), ({"v4": 2, "v6": 1, "total": 3}, "2026-11"))

    def test_cloudflare_trusts_the_header_only_from_the_selected_peers(self):
        peers = ["172.31.0.2/32"]
        data, facts = self.render(country.Policy(enabled=True, countries=["DE", "RO"]), "cloudflare-tunnel", peers)
        self.assertEqual(data.decode(), HEADER + "vars caddy_console_country_policy cloudflare\n"
                         "@caddy_console_country_denied {\n"
                         f"\tnot client_ip {BASE}\n\tnot {{\n\t\tremote_ip 172.31.0.2/32\n"
                         "\t\theader_regexp CF-IPCountry ^(?:DE|RO)$\n\t}\n}\n"
                         "handle @caddy_console_country_denied {\n\trespond 403\n}\n")
        self.assertEqual(facts["profile"], "cloudflare")

    def test_cloudflare_without_a_peer_is_refused(self):
        with self.assertRaises(country.CountryError) as cm:
            self.render(country.Policy(enabled=True, countries=["RO"]), "cloudflare-tunnel", [])
        self.assertEqual(cm.exception.code, "cloudflare_peers_required")

    def test_cap_rejects_and_warning_threshold_warns(self):
        policy = country.Policy(enabled=True, countries=["DE", "RO", "FR"])
        with mock.patch.object(config, "COUNTRY_MAX_PREFIXES", 3):
            with self.assertRaises(country.CountryError) as cm:
                self.render(policy)
            self.assertEqual((cm.exception.code, cm.exception.extra["count"], cm.exception.extra["limit"]),
                            ("country_prefix_cap_exceeded", 4, 3))
        with mock.patch.object(config, "COUNTRY_MAX_PREFIXES", 6):      # warning at 3
            _, facts = self.render(policy)
            self.assertTrue(facts["warnings"])
        _, facts = self.render(policy)
        self.assertEqual(facts["warnings"], [])
        self.assertEqual((country.max_prefixes(), country.warn_prefixes()), (20000, 10000))

    def test_missing_dataset_or_no_ranges_is_refused(self):
        with self.assertRaises(country.CountryError) as cm:
            self.render(country.Policy(enabled=True, countries=["BR"]))
        self.assertEqual(cm.exception.code, "country_no_ranges")
        remove_dataset()
        with self.assertRaises(country.CountryError) as cm:
            self.render(country.Policy(enabled=True, countries=["RO"]))
        self.assertEqual(cm.exception.code, "country_dataset_unavailable")


class ValidationTest(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(config, "COUNTRY_POLICY_ENABLED", True)
        p.start()
        self.addCleanup(p.stop)

    def err(self, payload):
        with self.assertRaises(country.CountryError) as cm:
            country.from_payload(payload, country.Policy())
        return cm.exception.code

    def test_codes_come_from_the_server_owned_list(self):
        self.assertEqual(self.err({"enabled": True, "countries": ["RO", "ZZ"]}), "invalid_country")
        self.assertEqual(self.err({"enabled": True, "countries": ["ROU"]}), "invalid_country")
        self.assertEqual(self.err({"enabled": True, "countries": "RO"}), "invalid_country")
        self.assertEqual(self.err({"enabled": True, "countries": [5]}), "invalid_country")
        c = country.from_payload({"enabled": True, "countries": [" ro ", "DE", "RO"]}, country.Policy())
        self.assertEqual(c.countries, ["DE", "RO"])

    def test_xx_and_t1_only_when_named(self):
        c = country.from_payload({"enabled": True, "countries": ["RO", "T1", "XX"]}, country.Policy())
        self.assertEqual(c.countries, ["RO", "T1", "XX"])
        c = country.from_payload({"enabled": True, "countries": ["RO"]}, country.Policy())
        self.assertNotIn("T1", c.countries)
        self.assertNotIn("XX", c.countries)
        self.assertNotIn("XX", country.ISO)
        self.assertNotIn("T1", country.ISO)

    def test_enabling_needs_a_country_and_the_env_flag(self):
        self.assertEqual(self.err({"enabled": True, "countries": []}), "country_required")
        self.assertEqual(self.err({"enabled": "yes"}), "invalid_request")
        self.assertEqual(self.err(["x"]), "invalid_request")
        with mock.patch.object(config, "COUNTRY_POLICY_ENABLED", False):
            self.assertEqual(self.err({"enabled": True, "countries": ["RO"]}), "country_policy_disabled")
            self.assertFalse(country.from_payload({"enabled": False, "countries": []}, country.Policy()).enabled)

    def test_state_round_trip_and_corruption(self):
        p = country.Policy(enabled=True, countries=["RO"], stored=True, last_rendered_hashes={"geo.caddy": "sha256:x"})
        self.assertEqual(country._from_doc(json.loads(country.dumps(p))).last_rendered_hashes, p.last_rendered_hashes)
        for doc in ({"version": 2}, {"version": 1, "countries": ["ZZ"]}, {"version": 1, "countries": "RO"},
                    {"version": 1, "last_rendered_hashes": {"a": 1}}, []):
            with self.assertRaises(country.Corrupt):
                country._from_doc(doc)


class MarkerTest(unittest.TestCase):
    def live(self, value):
        return {"apps": {"http": {"servers": {"s": {"routes": [{"handle": [
            {"handler": "vars", "caddy_console_country_policy": value}]}]}}}}}

    def test_any_known_shape_counts_as_the_marker(self):
        for shape in ("off", "direct", "cloudflare"):
            self.assertTrue(detect.marker_present(self.live(shape), "caddy_console_country_policy"))
            self.assertEqual(detect.country_shapes(self.live(shape)), [shape])
        self.assertFalse(detect.marker_present(self.live("1"), "caddy_console_country_policy"))
        self.assertFalse(detect.marker_present({"apps": {}}, "caddy_console_country_policy"))
        self.assertTrue(detect.marker_present(self.live("1"), "caddy_console_manual_policy") is False)


class CountryApiTest(_bans.ApiCase):
    def setUp(self):
        super().setUp()
        service.reset_caches()
        self.addCleanup(service.reset_caches)
        install_dataset()
        self.addCleanup(remove_dataset)
        p = mock.patch.object(config, "COUNTRY_POLICY_ENABLED", True)
        p.start()
        self.addCleanup(p.stop)
        _bans.write_caddyfile(SITE)

    def put(self, payload, **kw):
        return super().put(URL, payload, **kw)

    def test_login_and_csrf_are_required(self):
        body = {"enabled": False}
        self.assertEqual(self.client.put(URL, json=body, headers=_bans.AUTH).status_code, 403)
        self.assertEqual(self.client.put(URL, json=body, headers={"X-CSRF-Token": self.csrf}).status_code, 401)
        self.assertEqual(self.client.get(URL).status_code, 401)

    def test_default_get_reports_off_and_the_measured_limits(self):
        info = self.get(URL).get_json()
        self.assertEqual((info["enabled"], info["stored"], info["present"]), (False, False, False))
        self.assertEqual(info["limits"], {"max": 20000, "warn": 10000})
        self.assertIn("RO", info["iso_codes"])
        self.assertEqual(info["dataset"]["month"], "2026-11")

    def test_enabling_direct_writes_state_hash_and_file_in_one_transaction(self):
        self.caddy.calls.clear()
        r = self.put({"enabled": True, "countries": ["RO", "DE"]})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual([k for k, _ in self.caddy.calls].count("load"), 1)
        text = read(render.COUNTRY.path)
        self.assertIn("vars caddy_console_country_policy direct", text)
        self.assertIn("not client_ip 192.0.2.0/24 198.51.100.0/24 2001:db8:1::/48 " + BASE, text)
        doc = json.loads(read(country.PATH))
        self.assertEqual(doc["last_rendered_hashes"]["geo.caddy"], fsio.sha256_tag(fsio.read_bytes(render.COUNTRY.path)))
        self.assertEqual((doc["countries"], doc["profile"], doc["dataset"]["month"]), (["DE", "RO"], "direct", "2026-11"))
        self.assertEqual(oct(os.stat(country.PATH).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(render.COUNTRY.path).st_mode & 0o777), "0o644")
        info = self.get(URL).get_json()
        self.assertEqual((info["current"], info["healthy"], info["prefixes"]["total"]), (True, True, 3))
        self.assertIn(("country_policy_changed", "enabled=true countries=DE RO"),
                      [(e["action"], e["detail"]) for e in audit.iter_entries()])

    def test_refused_policies_leave_live_and_last_good_files_untouched(self):
        self.assertEqual(self.put({"enabled": True, "countries": ["RO"]}).status_code, 200)
        files = (render.COUNTRY.path, country.PATH)
        before = [fsio.read_bytes(p) for p in files]
        self.caddy.calls.clear()
        for payload, code, status in (({"enabled": True, "countries": []}, "country_required", 400),
                                      ({"enabled": True, "countries": ["ZZ"]}, "invalid_country", 400),
                                      ({"enabled": True, "countries": ["BR"]}, "country_no_ranges", 409)):
            r = self.put(payload)
            self.assertEqual((r.status_code, r.get_json()["code"]), (status, code), payload)
        with mock.patch.object(config, "COUNTRY_MAX_PREFIXES", 1):
            r = self.put({"enabled": True, "countries": ["RO", "DE"]})
        self.assertEqual((r.status_code, r.get_json()["code"]), (409, "country_prefix_cap_exceeded"))
        self.assertEqual(r.get_json()["limit"], 1)
        self.assertEqual([fsio.read_bytes(p) for p in files], before)
        self.assertEqual(self.caddy.calls, [])
        self.assertFalse(os.path.exists(os.path.join(env.BACKUP_DIR, ".policy-transactions", "journal.json")))

    def test_disabling_returns_to_the_off_shape(self):
        self.put({"enabled": True, "countries": ["RO"]})
        r = self.put({"enabled": False})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(read(render.COUNTRY.path), HEADER + "# Country policy is off: no matcher or handler is "
                         "generated.\nvars caddy_console_country_policy off\n")
        self.assertEqual(json.loads(read(country.PATH))["countries"], ["RO"], "the selection is kept")

    def test_env_flag_gates_enforcement(self):
        with mock.patch.object(config, "COUNTRY_POLICY_ENABLED", False):
            r = self.put({"enabled": True, "countries": ["RO"]})
            self.assertEqual((r.status_code, r.get_json()["code"]), (409, "country_policy_disabled"))
            self.assertEqual(service.expire_tick(), "idle")
            self.assertFalse(os.path.exists(render.COUNTRY.path))

    def test_bans_disabled_means_no_country_files(self):
        with mock.patch.object(config, "BANS_ENABLED", False):
            self.assertFalse(service._country_active())

    def test_cloudflare_profile_switches_the_shape_in_the_same_transaction(self):
        self.put({"enabled": True, "countries": ["RO", "DE"]})
        r = super().put("/api/security/client-ip-profile", {"mode": "cloudflare-tunnel", "tunnel_peers": ["172.31.0.2"]})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        text = read(render.COUNTRY.path)
        self.assertIn("vars caddy_console_country_policy cloudflare", text)
        self.assertIn("\t\tremote_ip 172.31.0.2/32\n\t\theader_regexp CF-IPCountry ^(?:DE|RO)$\n", text)
        self.assertNotIn("2001:db8", text)
        self.assertEqual(json.loads(read(country.PATH))["profile"], "cloudflare-tunnel")
        info = self.get(URL).get_json()
        self.assertEqual((info["shape"], info["current"], info["healthy"]), ("cloudflare", True, False),
                         "healthy needs the Cloudflare IP Geolocation confirmation")
        self.put({"enabled": True, "countries": ["RO", "DE"], "cloudflare_geolocation_confirmed": True})
        self.assertTrue(self.get(URL).get_json()["healthy"])

    def test_proxied_mode_puts_the_edge_ranges_in_remote_ip(self):
        self.put({"enabled": True, "countries": ["RO"]})
        super().put("/api/security/client-ip-profile", {"mode": "cloudflare-proxied"})
        line = next(l for l in read(render.COUNTRY.path).splitlines() if "remote_ip" in l)
        for net in cfranges.BUNDLED["v4"] + cfranges.BUNDLED["v6"]:
            self.assertIn(" " + net, line)

    def test_edge_ranges_are_never_exempt_from_the_country_policy(self):
        self.put({"enabled": True, "countries": ["RO"]})
        super().put("/api/security/client-ip-profile", {"mode": "cloudflare-proxied"})
        line = next(l for l in read(render.COUNTRY.path).splitlines() if "not client_ip" in l)
        for net in cfranges.BUNDLED["v4"] + cfranges.BUNDLED["v6"]:
            self.assertNotIn(net, line)
        self.assertIn("private_ranges", line)

    def test_cloudflare_health_needs_the_live_trusted_proxies_to_match_the_profile(self):
        self.put({"enabled": True, "countries": ["RO"], "cloudflare_geolocation_confirmed": True})
        super().put("/api/security/client-ip-profile", {"mode": "cloudflare-tunnel", "tunnel_peers": ["172.31.0.2"]})
        summary = lambda: self.get("/api/security").get_json()["country_policy"]["summary"]
        self.assertFalse(summary()["healthy"], "the trusted proxies file is not imported: client_ip is the peer")
        srv = self.caddy.live["apps"]["http"]["servers"]["srv0"]
        srv["trusted_proxies"] = {"source": "static", "ranges": ["172.31.0.2/32"]}
        srv["client_ip_headers"] = ["CF-Connecting-IP"]
        self.assertTrue(summary()["healthy"])
        srv["trusted_proxies"]["ranges"] = ["172.31.0.9/32"]
        self.assertFalse(summary()["healthy"])

    def test_cloudflare_policy_cannot_be_enabled_without_a_peer(self):
        super().put("/api/security/client-ip-profile", {"mode": "cloudflare-tunnel", "tunnel_peers": ["172.31.0.2"]})
        self.assertEqual(self.put({"enabled": True, "countries": ["RO"]}).status_code, 200)
        before = read(render.COUNTRY.path)
        with mock.patch.object(profile.Profile, "peers", lambda self: []):
            r = self.put({"enabled": True, "countries": ["DE"]})
        self.assertEqual((r.status_code, r.get_json()["code"]), (409, "cloudflare_peers_required"))
        self.assertEqual(read(render.COUNTRY.path), before)

    def test_protected_set_changes_regenerate_the_file(self):
        self.put({"enabled": True, "countries": ["RO"]})
        with mock.patch.object(config, "BANS_NEVER", "203.0.113.250"):
            service.reset_caches()
            self.assertEqual(service.expire_tick(), "applied")
        self.assertIn(" 203.0.113.250\n", read(render.COUNTRY.path))

    def test_ban_transactions_carry_the_country_file(self):
        self.put({"enabled": True, "countries": ["RO"]})
        with mock.patch.object(config, "BANS_NEVER", "203.0.113.250"):
            service.reset_caches()
            r = self.post("/api/bans", {"value": "203.0.113.7", "duration": "4h", "reason": ""})
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        self.assertIn(" 203.0.113.250\n", read(render.COUNTRY.path))
        self.assertEqual(json.loads(read(country.PATH))["last_rendered_hashes"]["geo.caddy"],
                         fsio.sha256_tag(fsio.read_bytes(render.COUNTRY.path)))

    def test_an_unrenderable_policy_keeps_the_last_good_file_during_other_changes(self):
        self.put({"enabled": True, "countries": ["RO"]})
        before = read(render.COUNTRY.path)
        remove_dataset()
        r = self.post("/api/bans", {"value": "203.0.113.7", "duration": "4h", "reason": ""})
        self.assertEqual(r.status_code, 201, "a ban is not blocked by a missing dataset")
        self.assertEqual(read(render.COUNTRY.path), before)
        info = self.get(URL).get_json()
        self.assertEqual((info["error"]["code"], info["current"], info["healthy"]),
                         ("country_dataset_unavailable", False, False))

    def test_dataset_update_regenerates_only_when_the_selected_output_changes(self):
        self.put({"enabled": True, "countries": ["RO"]})
        self.assertEqual(service.country_tick(), "current")
        install_dataset(CSV.replace("203.0.113.0,203.0.113.255,FR", "203.0.113.0,203.0.113.255,US"), "2026-12")
        self.caddy.calls.clear()
        self.assertEqual(service.country_tick(), "current", "RO ranges are unchanged")
        self.assertEqual(self.caddy.calls, [])
        install_dataset(CSV.replace("192.0.2.0,192.0.2.255,RO", "192.0.2.0,192.0.2.127,RO"), "2027-01")
        self.assertEqual(service.country_tick(), "applied")
        self.assertIn("192.0.2.0/25", read(render.COUNTRY.path))
        self.assertEqual(json.loads(read(country.PATH))["dataset"]["month"], "2027-01")

    def test_dataset_tick_never_overwrites_a_policy_changed_after_it_read_it(self):
        self.put({"enabled": True, "countries": ["RO"]})
        install_dataset(CSV.replace("192.0.2.0,192.0.2.255,RO", "192.0.2.0,192.0.2.127,RO"), "2027-01")
        real = service._policy_transaction

        def racing(*a, **kw):
            with mock.patch.object(service, "_policy_transaction", real):
                self.assertEqual(self.put({"enabled": True, "countries": ["RO", "DE"]}).status_code, 200)
            return real(*a, **kw)
        with mock.patch.object(service, "_policy_transaction", racing):
            self.assertEqual(service.country_tick(), "version_conflict")
        self.assertEqual(json.loads(read(country.PATH))["countries"], ["DE", "RO"])
        self.assertIn("198.51.100.0/24", read(render.COUNTRY.path))

    def test_dataset_update_over_the_cap_keeps_the_last_good_file(self):
        self.put({"enabled": True, "countries": ["RO"]})
        before = read(render.COUNTRY.path)
        install_dataset(CSV.replace("192.0.2.0,192.0.2.255,RO", "192.0.2.1,192.0.2.6,RO"), "2026-12")
        with mock.patch.object(config, "COUNTRY_MAX_PREFIXES", 3):
            self.assertEqual(service.country_tick(), "country_prefix_cap_exceeded")
        self.assertEqual(read(render.COUNTRY.path), before)

    def test_out_of_band_edit_holds_until_reapply(self):
        self.put({"enabled": True, "countries": ["RO"]})
        with open(render.COUNTRY.path, "w") as f:
            f.write("")
        self.assertEqual(self.get("/api/security").get_json()["country_policy"]["hold"], "differs")
        self.assertEqual(service.expire_tick(), "idle")
        self.assertEqual(read(render.COUNTRY.path), "")
        r = self.post("/api/security/reapply", {"source": "country"})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertIn("vars caddy_console_country_policy direct", read(render.COUNTRY.path))

    def test_reset_returns_to_off(self):
        self.put({"enabled": True, "countries": ["RO"]})
        self.assertEqual(self.post("/api/security/reset", {"source": "country"}).get_json()["code"],
                         "confirmation_required")
        r = self.post("/api/security/reset", {"source": "country", "confirm": True})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertIn("vars caddy_console_country_policy off", read(render.COUNTRY.path))
        self.assertFalse(json.loads(read(country.PATH))["enabled"])

    def test_status_shows_live_shapes(self):
        self.put({"enabled": True, "countries": ["RO"]})
        body = self.get("/api/security").get_json()["country_policy"]
        self.assertEqual(body["live_shapes"], ["direct"])


class CountryTickJobTest(unittest.TestCase):
    def test_background_loop_only_starts_with_the_policy_flag(self):
        self.assertEqual(jobs.COUNTRY_TICK_SECONDS, 3600)
        self.assertEqual(service.country_tick(), "disabled")


if __name__ == "__main__":
    unittest.main()
