"""The never-ban list: allowlist.json, validation, the shared transaction,
the rendered exclusions, input refusal and the corrupt-file gate.

Run with:  uv run --frozen python -m unittest tests.test_bans_allowlist -v
"""
import json
import os
import unittest
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec
from tests.test_country_policy import install_dataset, remove_dataset

from src import audit
from src.bans import addr, allowlist, fsio, profile, protected, render, service, store

D = env.BANS_DIR
SITE = ("example.com {{\n\timport {d}/bans-manual*.caddy\n\timport {d}/bans-crowdsec*.caddy\n"
        "\timport {d}/geo*.caddy\n\trespond 200\n}}\n").format(d=D)
ACTOR = "admin@example.com"


def exclusion(path):
    text = (fsio.read_bytes(path) or b"").decode()
    line = next((l for l in text.splitlines() if l.strip().startswith("not client_ip ")), "")
    return line.split()[2:]


class ValidationTest(unittest.TestCase):
    def test_canonical_and_width(self):
        self.assertEqual(addr.token(allowlist.validate_value(" 203.0.113.9 ")), "203.0.113.9")
        self.assertEqual(addr.token(allowlist.validate_value("10.1.2.3/8")), "10.0.0.0/8")
        self.assertEqual(addr.token(allowlist.validate_value("::ffff:198.51.100.1")), "198.51.100.1")
        self.assertEqual(addr.token(allowlist.validate_value("2001:db8::/32")), "2001:db8::/32")
        for bad in ("0.0.0.0/0", "::/0", "8.0.0.0/7", "2001::/31"):
            with self.assertRaises(allowlist.InputError, msg=bad) as e:
                allowlist.validate_value(bad)
            self.assertEqual(e.exception.code, "range_too_wide")
        with self.assertRaises(addr.AddressError):
            allowlist.validate_value("nope")

    def test_note_and_duplicates(self):
        self.assertEqual(allowlist.validate_note(None), "")
        self.assertEqual(allowlist.validate_note("  home  "), "home")
        for bad in ("x" * 201, "a\nb", 5):
            with self.assertRaises(allowlist.InputError):
                allowlist.validate_note(bad)
        entries, _ = allowlist.add([], allowlist.validate_value("203.0.113.9"), "", ACTOR, "t")
        with self.assertRaises(allowlist.InputError) as e:
            allowlist.add(entries, allowlist.validate_value("203.0.113.9/32"), "", ACTOR, "t")
        self.assertEqual(e.exception.code, "duplicate")
        full = [allowlist.Entry(str(i), f"10.0.{i // 256}.{i % 256}", "", ACTOR, "t") for i in range(500)]
        with self.assertRaises(allowlist.InputError) as e:
            allowlist.add(full, allowlist.validate_value("203.0.113.1"), "", ACTOR, "t")
        self.assertEqual(e.exception.code, "allowlist_full")


class StoreTest(unittest.TestCase):
    def setUp(self):
        _bans.reset()

    def test_round_trip_and_corrupt_shapes(self):
        self.assertEqual(allowlist.load(), [])
        entries, entry = allowlist.add([], allowlist.validate_value("198.51.100.0/24"), "office", ACTOR, "2026-01-01")
        fsio.atomic_write(allowlist.PATH, allowlist.dumps(entries), 0o600)
        self.assertEqual(allowlist.load(), [entry])
        doc = json.loads(allowlist.dumps(entries))
        for broken in (b"{", json.dumps({"version": 2, "entries": []}).encode(),
                       json.dumps({**doc, "entries": [{**doc["entries"][0], "value": "198.51.100.1/24"}]}).encode(),
                       json.dumps({**doc, "entries": doc["entries"] * 2}).encode()):
            with self.subTest(broken=broken[:40]):
                fsio.atomic_write(allowlist.PATH, broken, 0o600)
                with self.assertRaises(allowlist.Corrupt):
                    allowlist.load()
                self.assertEqual(allowlist.load_or_default(), [])


class ServiceTest(unittest.TestCase):
    def setUp(self):
        _bans.reset(SITE)
        _bans.fresh_audit(self)
        service.reset_caches()
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)
        _crowdsec.enable(self)
        self.addCleanup(service.reset_caches)

    def ban(self, value):
        return service.add_ban({"value": value, "duration": "24h", "reason": "x"}, ACTOR, None)

    def test_add_regenerates_every_policy_in_one_transaction(self):
        install_dataset()
        self.addCleanup(remove_dataset)
        self.assertEqual(self.ban("198.51.100.0/24")[1], 201)
        service.apply_crowdsec([_crowdsec.accepted("192.0.2.0/24", 1)], snapshot=True)
        body, status = service.set_country_policy({"enabled": True, "countries": ["DE"]}, ACTOR)
        self.assertEqual(status, 200, body)
        active = mock.patch.object(service, "_plugin_active", lambda: True)  # the plugin route is in use
        active.start()
        self.addCleanup(active.stop)
        loads = lambda: sum(1 for c in self.caddy.calls if c[0] == "load")
        posts = loads()
        body, status = service.add_allowlist({"value": "198.51.100.7", "note": "home"}, ACTOR)
        self.assertEqual(status, 201, body)
        self.assertEqual(body["entry"]["value"], "198.51.100.7")
        for path in (render.SOURCES["manual"].path, render.SOURCES["crowdsec"].path, render.PLUGIN.path,
                     render.COUNTRY.path):
            self.assertIn("198.51.100.7", exclusion(path), path)
        self.assertEqual(loads(), posts + 1)
        self.assertEqual([e.value for e in allowlist.load()], ["198.51.100.7"])
        listed = service.list_bans()[0]["records"]
        self.assertEqual(next(r for r in listed if r["value"] == "198.51.100.0/24")["protected"], "allowlist")
        self.assertIn(("allowlist_added", ACTOR, "198.51.100.7"),
                      [(e.get("action"), e.get("user"), e.get("detail")) for e in audit.iter_entries()])
        entry_id = body["entry"]["id"]
        body, status = service.remove_allowlist(entry_id, ACTOR)
        self.assertEqual(status, 200, body)
        for path in (render.SOURCES["manual"].path, render.PLUGIN.path, render.COUNTRY.path):
            self.assertNotIn("198.51.100.7", exclusion(path), path)
        self.assertEqual(service.remove_allowlist(entry_id, ACTOR)[1], 404)

    def test_input_refusal_for_manual_and_crowdsec(self):
        service.add_allowlist({"value": "203.0.113.0/24"}, ACTOR)
        body, status = self.ban("203.0.113.9")
        self.assertEqual((status, body["code"], body.get("category")), (400, "protected_overlap", "allowlist"))
        r = service.apply_crowdsec([_crowdsec.accepted("203.0.113.0/25", 1)], snapshot=True)
        self.assertEqual(r.protected, {"allowlist": 1})
        self.assertEqual(service.add_allowlist({"value": "203.0.113.0/24"}, ACTOR)[1], 409)
        self.assertEqual(service.add_allowlist({"value": "0.0.0.0/0"}, ACTOR)[0]["code"], "range_too_wide")

    def test_cloudflare_edge_overlap_is_accepted_but_never_rendered(self):
        prof = profile.Profile(mode="cloudflare-proxied", stored=True)
        with mock.patch.object(profile, "load_or_default", lambda: prof):
            edge = addr.token(prof.protected_networks()[0])
            self.ban("198.51.100.9")
            body, status = service.add_allowlist({"value": edge}, ACTOR)
            self.assertEqual(status, 201, body)
            self.assertNotIn(edge, exclusion(render.SOURCES["manual"].path))

    def test_corrupt_file_keeps_policies_and_refuses_writes(self):
        self.ban("198.51.100.9")
        before = fsio.read_bytes(render.SOURCES["manual"].path)
        fsio.atomic_write(allowlist.PATH, b"not json", 0o600)
        info = service.allowlist_info()
        self.assertTrue(info["corrupt"])
        self.assertEqual(info["entries"], [])
        for call in (lambda: service.add_allowlist({"value": "203.0.113.1"}, ACTOR),
                     lambda: service.remove_allowlist("x", ACTOR), lambda: self.ban("203.0.113.2")):
            body, status = call()
            self.assertEqual((status, body["code"]), (503, "allowlist_degraded"))
        self.assertEqual(fsio.read_bytes(render.SOURCES["manual"].path), before)
        self.assertEqual(fsio.read_bytes(allowlist.PATH), b"not json")
        self.assertEqual(service.expire_tick(), "allowlist_corrupt")


class ApiTest(_bans.ApiCase):
    def test_round_trip_auth_and_csrf(self):
        self.assertEqual(self.client.get("/api/security/allowlist").status_code, 401)
        self.assertEqual(self.client.post("/api/security/allowlist", json={}, headers=_bans.AUTH).status_code, 403)
        r = self.post("/api/security/allowlist", {"value": "203.0.113.5", "note": "vpn"})
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        entry = r.get_json()["entry"]
        self.assertEqual((entry["note"], entry["actor"]), ("vpn", ACTOR))
        got = self.get("/api/security/allowlist").get_json()
        self.assertEqual([e["value"] for e in got["entries"]], ["203.0.113.5"])
        self.assertEqual(self.get("/api/security").get_json()["allowlist"]["entries"][0]["id"], entry["id"])
        bad = self.post("/api/security/allowlist", {"value": "x"})
        self.assertEqual((bad.status_code, bad.get_json()["code"]), (400, "invalid_ip"))
        self.assertEqual(self.delete(f"/api/security/allowlist/{entry['id']}").status_code, 200)
        self.assertEqual(self.get("/api/security/allowlist").get_json()["entries"], [])


if __name__ == "__main__":
    unittest.main()
