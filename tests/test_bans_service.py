"""Ban operations end to end against the fake admin API (spec 1.2-1.7).

Run with:  uv run --frozen python -m unittest tests.test_bans_service -v
"""
import fcntl
import json
import os
import tempfile
import threading
import unittest
from datetime import timedelta
from unittest import mock

import requests

import tests._env as env
from tests import _bans

from src import audit, config
from src.bans import fsio, protected, render, service, store, txn
from src.routes.editor import caddyfile_lock

MANUAL = render.SOURCES["manual"]
with open(os.path.join(os.path.dirname(__file__), "fixtures", "bans", "adapted-layouts.json"), encoding="utf-8") as f:
    FIXTURES = json.load(f)


def actions():
    return [e["action"] for e in audit.iter_entries()]


def policy():
    return fsio.read_bytes(MANUAL.path) or b""


class ServiceCase(unittest.TestCase):
    def setUp(self):
        _bans.reset()
        _bans.fresh_audit(self)
        service.reset_caches()
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)

    def tearDown(self):
        service.reset_caches()

    def ban(self, value="203.0.113.7", duration="24h", reason="", remote="127.0.0.1"):
        return service.add_ban({"value": value, "duration": duration, "reason": reason}, "admin@example.com", remote)

    def patch_config(self, **values):
        for name, value in values.items():
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)
        service.reset_caches()


class AddRemoveTest(ServiceCase):
    def test_ban_renders_policy_with_embedded_hash_and_audits(self):
        body, status = self.ban(" 203.0.113.7 ", reason="Repeated login attempts")
        self.assertEqual(status, 201, body)
        self.assertEqual((body["ok"], body["enforcement"], body["reload_status"]), (True, "enforced", "applied"))
        self.assertEqual((body["record"]["value"], body["record"]["scope"]), ("203.0.113.7", "ip"))
        self.assertIn(b"\tclient_ip 203.0.113.7\n", policy())
        self.assertIn(b"\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10\n", policy())
        state = store.load()
        self.assertEqual(state.last_rendered_hashes[MANUAL.filename], fsio.sha256_tag(policy()))
        self.assertEqual(state.records[0].reason, "Repeated login attempts")
        self.assertIn("ban_created", actions())

    def test_protected_and_wide_targets_are_refused_and_audited(self):
        for value, code in (("10.1.2.3", "protected_overlap"), ("192.168.0.0/16", "protected_overlap"),
                            ("fe80::1", "protected_overlap"), ("203.0.0.0/15", "range_too_wide"),
                            ("2001:db8::/47", "range_too_wide"), ("nope", "invalid_ip")):
            with self.subTest(value=value):
                body, status = self.ban(value)
                self.assertEqual((status, body["code"]), (400, code))
        self.assertFalse(os.path.exists(MANUAL.path))
        self.assertEqual(actions().count("ban_refused"), 5)

    def test_own_verified_address_is_protected_immediately(self):
        body, status = self.ban("198.51.100.0/24", remote="198.51.100.20")
        self.assertEqual((status, body["code"], body["category"]), (400, "protected_overlap", "operator"))
        body, status = self.ban("203.0.113.7", remote="198.51.100.20")
        self.assertEqual(status, 201)
        self.assertEqual([m["value"] for m in store.load().management_addresses], ["198.51.100.20"])
        self.assertIn(b" 198.51.100.20\n", policy())

    def test_private_peer_is_not_registered(self):
        self.ban(remote="172.18.0.5")
        self.assertEqual(store.load().management_addresses, [])

    def test_bans_never_in_both_directions(self):
        self.patch_config(BANS_NEVER="203.0.113.9")
        for value in ("203.0.113.0/24", "203.0.113.9"):
            body, status = self.ban(value)
            self.assertEqual((status, body["code"], body["category"]), (400, "protected_overlap", "never"))

    def test_capacity_never_drops_an_active_ban(self):
        self.patch_config(BANS_MAX=2)
        self.assertEqual(self.ban("203.0.113.1")[1], 201)
        self.assertEqual(self.ban("203.0.113.3")[1], 201)
        body, status = self.ban("203.0.113.5")
        self.assertEqual((status, body["code"], body["count"], body["limit"]), (409, "capacity_exceeded", 3, 2))
        self.assertEqual(len(store.load().records), 2)
        self.assertIn(b"client_ip 203.0.113.1 203.0.113.3\n", policy())

    def test_overlapping_records_are_independent(self):
        first = self.ban("203.0.113.7", "4h")[0]["record"]["id"]
        second = self.ban("203.0.113.7", "permanent")[0]["record"]["id"]
        body, status = service.remove_ban(first, "admin@example.com", "127.0.0.1")
        self.assertEqual((status, body["still_covered_by"]), (200, ["203.0.113.7"]))
        self.assertIn(b"client_ip 203.0.113.7", policy())
        service.remove_ban(second, "admin@example.com", "127.0.0.1")
        self.assertNotIn(b"client_ip", policy())
        self.assertIn(b"vars caddy_console_manual_policy 1\n", policy())
        self.assertIn("ban_removed", actions())

    def test_remove_errors(self):
        self.assertEqual(service.remove_ban("nope", "a@example.com", None)[1], 404)
        self.ban()
        state = store.load()
        state.records.append(store.Record(id="cs-1", source="crowdsec", source_id="42", scope="ip",
                                          value="192.0.2.1", reason="", scenario="crowdsecurity/http-probing",
                                          origin="crowdsec", actor="system", created_at=state.records[0].created_at,
                                          expires_at=None))
        fsio.atomic_write(store.STATE_PATH, store.dumps(state), 0o600)
        body, status = service.remove_ban("cs-1", "a@example.com", None)
        self.assertEqual((status, body["code"]), (403, "not_manual"))

    def test_mutations_hold_the_cross_process_lock_through_load(self):
        real, seen = requests.post, []

        def checking(url, *a, **kw):
            if url.endswith("/load"):
                fd = os.open(os.path.join(env.BACKUP_DIR, ".lock"), os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    seen.append(True)
                finally:
                    os.close(fd)
            return real(url, *a, **kw)
        service.availability()                     # warm the probe outside the patch
        with mock.patch.object(requests, "post", checking):
            self.assertEqual(self.ban()[1], 201)
        self.assertEqual(seen, [True])

    def test_concurrent_bans_are_serialized(self):
        service.availability()
        threads = [threading.Thread(target=self.ban, args=(f"203.0.113.{i}",)) for i in (1, 3, 5, 7)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(r.value for r in store.load().records),
                         ["203.0.113.1", "203.0.113.3", "203.0.113.5", "203.0.113.7"])
        self.assertIn(b"client_ip 203.0.113.1 203.0.113.3 203.0.113.5 203.0.113.7\n", policy())


class LookupTest(ServiceCase):
    def test_covering_lookup_accepts_mapped_ipv6(self):
        self.ban("203.0.113.7/24")
        exact = self.ban("::ffff:203.0.113.8")[0]["record"]
        self.assertEqual(exact["value"], "203.0.113.8")
        body, status = service.list_bans("::ffff:203.0.113.8")
        self.assertEqual((status, body["ip"], body["protected"]), (200, "203.0.113.8", None))
        self.assertEqual(sorted(r["value"] for r in body["records"]), ["203.0.113.0/24", "203.0.113.8"])
        self.assertEqual(body["exact_ids"], [exact["id"]])
        self.assertEqual(service.list_bans("203.0.113.0/24")[0]["code"], "invalid_ip")
        self.assertEqual(service.list_bans("10.0.0.1")[0]["protected"], "private")

    def test_record_overlapping_new_never_is_flagged_and_excluded(self):
        self.ban("203.0.113.0/24")
        self.patch_config(BANS_NEVER="203.0.113.9")
        body, _ = service.list_bans()
        self.assertEqual(body["records"][0]["protected"], "never")
        self.assertEqual(self.ban("192.0.2.1")[1], 201)
        self.assertIn(b" 203.0.113.9\n", policy())


class CorruptStateTest(ServiceCase):
    def corrupt(self):
        with open(store.STATE_PATH, "wb") as f:
            f.write(b"{broken")

    def test_corrupt_state_is_read_only_and_keeps_the_policy(self):
        self.ban()
        before = policy()
        self.corrupt()
        body, status = self.ban("192.0.2.1")
        self.assertEqual((status, body["code"], body["recovery"]), (503, "state_degraded", True))
        self.assertEqual(policy(), before)
        self.assertTrue(any(n.startswith("bans.json.quarantine-") for n in os.listdir(env.BACKUP_DIR)))
        self.assertIsNotNone(store.read_error())
        self.assertEqual(service.status("127.0.0.1")["degraded"]["kind"], "state_corrupt")
        self.assertEqual(service.expire_tick(), "corrupt")
        self.assertEqual(service.list_bans()[1], 503)
        self.assertEqual(policy(), before)

    def restore(self, backup_id):
        info = service.recovery_info()
        self.assertEqual((info["kind"], info["actions"]), ("state_corrupt", ["restore_backup"]))
        return service.recovery_post({"recovery_id": info["recovery_id"], "action": "restore_backup",
                                      "backup_id": backup_id}, "op@example.com")

    def test_restoring_the_newest_backup_keeps_every_committed_ban(self):
        self.ban("203.0.113.7")
        self.ban("192.0.2.1")
        before = policy()
        self.corrupt()
        backups = service.recovery_info()["backups"]
        self.assertEqual([b["records"] for b in backups], [2, 1])     # newest first; the older one is offered too
        body, status = self.restore(backups[0]["id"])
        self.assertEqual(status, 200, body)
        self.assertIsNone(store.read_error())
        self.assertEqual(sorted(r.value for r in store.load().records), ["192.0.2.1", "203.0.113.7"])
        self.assertFalse(service.recovery_info()["required"])        # matches the enforced policy: no hold
        self.assertEqual(policy(), before)
        self.assertIn("bans_recovered", actions())

    def test_restoring_an_older_backup_then_reapply(self):
        self.ban("203.0.113.7")
        self.ban("192.0.2.1")
        self.corrupt()
        body, status = self.restore(service.recovery_info()["backups"][1]["id"])
        self.assertEqual(status, 200, body)
        self.assertEqual([r.value for r in store.load().records], ["203.0.113.7"])
        self.assertEqual(service.recovery_info()["kind"], "policy_hold")
        body, status = service.reapply({"source": "manual"}, "op@example.com", None)
        self.assertEqual(status, 200, body)
        self.assertFalse(service.recovery_info()["required"])
        self.assertNotIn(b"192.0.2.1", policy())

    def test_restore_rejects_unknown_backup_ids(self):
        self.ban()
        self.ban("192.0.2.1")
        self.corrupt()
        self.assertEqual(self.restore("../../bans.json")[0]["code"], "invalid_backup")

    def test_recovery_stays_reachable_when_bans_are_unavailable(self):
        self.ban()
        self.ban("192.0.2.1")
        self.corrupt()
        self.caddy.hide_imports = True
        self.assertEqual(service.availability(force=True).code, "caddy_cannot_see_bans_dir")
        body, status = self.restore(service.recovery_info()["backups"][0]["id"])
        self.assertEqual(status, 200, body)

    def test_reset_contract(self):
        self.ban()
        self.corrupt()
        version = service.recovery_info()["state_version"]
        self.assertEqual(service.reset({"source": "manual", "version": version}, "op", None)[0]["code"], "confirmation_required")
        self.assertEqual(service.reset({"source": "manual", "version": "x", "confirm": True}, "op", None)[1], 409)
        self.assertEqual(service.reset({"source": "crowdsec", "version": version, "confirm": True}, "op", None)[0]["code"], "source_not_enabled")
        self.assertEqual(service.reset({"source": "everything", "version": version, "confirm": True}, "op", None)[0]["code"], "invalid_source")
        body, status = service.reset({"source": "manual", "version": version, "confirm": True}, "op", None)
        self.assertEqual(status, 200, body)
        self.assertEqual(store.load().records, [])
        self.assertNotIn(b"client_ip", policy())
        self.assertIsNone(store.read_error())
        self.assertIn("bans_reset", actions())


class JournalRecoveryTest(ServiceCase):
    def test_unverified_reload_degrades_until_the_operator_chooses(self):
        self.ban("203.0.113.7")
        before = policy()
        self.caddy.live_after_load = {"apps": {"unexpected": {}}}
        body, status = self.ban("192.0.2.1")
        self.assertEqual((status, body["code"], body["enforcement"]), (504, "reload_unknown", "unknown"))
        self.assertFalse(any(e["action"] == "ban_created" and e["detail"].startswith("192.0.2.1 ")
                             for e in audit.iter_entries()))      # never audited as made
        body, status = self.ban("198.51.100.7")
        self.assertEqual((status, body["code"], body["recovery"]), (503, "state_degraded", True))
        self.assertEqual(service.expire_tick(), "degraded")
        info = service.recovery_info()
        self.assertEqual((info["kind"], info["reason"], info["actions"]),
                         ("journal", "live_mismatch", ["use_candidate", "use_previous"]))
        self.assertEqual(service.status(None)["degraded"]["kind"], "journal")
        self.assertEqual(service.recovery_post({"recovery_id": "stale", "action": "use_previous"}, "op")[1], 409)
        self.caddy.live_after_load = None
        body, status = service.recovery_post({"recovery_id": info["recovery_id"], "action": "use_previous"}, "op")
        self.assertEqual(status, 200, body)
        self.assertEqual(policy(), before)
        self.assertFalse(service.recovery_info()["required"])
        self.assertIn("bans_recovered", actions())
        self.assertEqual(self.ban("192.0.2.1")[1], 201)


class HoldTest(ServiceCase):
    def test_truncated_policy_enters_hold_until_reapply(self):
        self.ban("203.0.113.7")
        with open(MANUAL.path, "wb"):
            pass                                    # host recovery: ": > bans-manual.caddy"
        status = service.status("127.0.0.1")
        self.assertEqual((status["sources"]["manual"]["hold"], status["recovery"]["kind"]), (True, "policy_hold"))
        body, code = self.ban("192.0.2.1")
        self.assertEqual((code, body["enforcement"]), (201, "held"))
        self.assertEqual(policy(), b"")
        self.assertEqual(service.expire_tick(now=store.utc_now() + timedelta(days=2)), "idle")
        self.assertEqual(policy(), b"")
        body, code = service.reapply({"source": "manual"}, "op@example.com", None)
        self.assertEqual(code, 200, body)
        self.assertIn(b"client_ip 192.0.2.1 203.0.113.7", policy())
        self.assertFalse(service.status("127.0.0.1")["sources"]["manual"]["hold"])

    def test_reapply_reloads_caddy_even_when_the_files_are_unchanged(self):
        # The site lives in an included file; Caddy last loaded it before the
        # policy existed, so its running config has no ban route.
        _bans.write_caddyfile(_bans.write_included_site())
        self.ban("203.0.113.7")
        self.caddy.live = {"apps": {}}
        self.caddy.calls.clear()
        body, code = service.reapply({"source": "manual"}, "op@example.com", None)
        self.assertEqual((code, body["reload_status"]), (200, "applied"), body)
        self.assertIn("load", [c[0] for c in self.caddy.calls])
        self.assertTrue(txn.marker_present(self.caddy.live, MANUAL.marker))

    def test_missing_state_with_an_existing_policy_is_a_hold(self):
        fsio.atomic_write(MANUAL.path, b"vars caddy_console_manual_policy 1\n", 0o644)
        self.assertEqual(service.recovery_info()["kind"], "policy_hold")


class ExpiryTest(ServiceCase):
    def test_expiry_regenerates_and_reloads_keeping_the_registry(self):
        self.ban("203.0.113.7", "4h", remote="198.51.100.20")
        self.ban("203.0.113.8", "permanent")
        self.caddy.calls.clear()
        self.assertEqual(service.expire_tick(now=store.utc_now() + timedelta(hours=5)), "applied")
        self.assertNotIn(b"203.0.113.7", policy())
        self.assertIn(b"client_ip 203.0.113.8\n", policy())
        self.assertIn(b" 198.51.100.20\n", policy())
        self.assertIn("load", [c[0] for c in self.caddy.calls])
        self.assertIn("ban_expired", actions())

    def test_idle_tick_does_nothing(self):
        self.ban("203.0.113.8", "permanent")
        self.caddy.calls.clear()
        self.assertEqual(service.expire_tick(), "idle")
        self.assertNotIn("load", [c[0] for c in self.caddy.calls])


class ConfigTest(ServiceCase):
    def test_invalid_bans_never_fails_startup(self):
        self.patch_config(BANS_NEVER="203.0.113.9, not-an-ip")
        with self.assertRaises(RuntimeError) as cm:
            service.init_config()
        self.assertIn("not-an-ip", str(cm.exception))
        self.patch_config(BANS_NEVER="203.0.113.9 2001:db8::/48")
        service.init_config()
        self.assertEqual([str(n) for n in service.never_networks()], ["203.0.113.9/32", "2001:db8::/48"])


class AvailabilityTest(ServiceCase):
    def test_bans_dir_must_be_inside_the_caddyfile_dir(self):
        self.patch_config(BANS_DIR=tempfile.mkdtemp())
        self.assertEqual(service.availability().code, "bans_dir_outside")
        body, status = self.ban()
        self.assertEqual((status, body["code"]), (503, "bans_unavailable"))
        self.assertFalse(service.status("127.0.0.1")["available"])

    def test_bans_dir_must_not_traverse_a_symlink(self):
        link = os.path.join(env.ROOT, "linked")
        if not os.path.islink(link):
            os.symlink(tempfile.mkdtemp(), link)
        self.patch_config(BANS_DIR=os.path.join(link, "console"))
        self.assertEqual(service.availability().code, "bans_dir_symlink")

    def test_caddy_must_see_the_managed_directory(self):
        self.caddy.hide_imports = True
        self.assertEqual(service.availability(force=True).code, "caddy_cannot_see_bans_dir")
        self.assertEqual([n for n in os.listdir(env.BANS_DIR) if "probe" in n], [])
        self.caddy.hide_imports = False
        self.caddy.down = True
        self.assertEqual(service.availability(force=True).code, "caddy_unreachable")
        self.caddy.down = False
        self.assertTrue(service.availability(force=True).ok)
        self.assertEqual([n for n in os.listdir(env.BANS_DIR) if "probe" in n], [])

    def test_probe_is_hidden_and_never_a_caddy_file(self):
        seen = []
        real = self.caddy.adapt_text

        def spy(text):
            seen.append((text, sorted(os.listdir(env.BANS_DIR))))
            return real(text)
        self.caddy.adapt_text = spy
        self.assertTrue(service.availability(force=True).ok)
        text, names = seen[0]
        self.assertRegex(text, r"import " + env.BANS_DIR + r"/\.console-probe-p[0-9a-f]+\*\.probe\n")
        self.assertEqual(len(names), 1)
        self.assertRegex(names[0], r"^\.console-probe-p[0-9a-f]+\.probe$")

    def test_a_leftover_probe_is_swept(self):
        leftover = os.path.join(env.BANS_DIR, ".console-probe-p0123abcd.probe")
        with open(leftover, "w") as f:
            f.write("vars caddy_console_probe p0123abcd\n")
        with caddyfile_lock():
            self.assertIsNone(txn.resolve_pending())
        self.assertFalse(os.path.exists(leftover))


class StatusTest(ServiceCase):
    def test_sites_merge_live_detection_with_the_file(self):
        self.ban()
        self.ban("198.51.100.0/24")                # the fixture's ban route covers exactly these two
        self.caddy.live = FIXTURES["simple_proxy"]
        _bans.write_caddyfile(f"a.example.com {{\n\timport {env.BANS_DIR}/bans-manual*.caddy\n\treverse_proxy 127.0.0.1:9\n}}\n"
                              "b.example.com {\n\trespond 200\n}\n")
        status = service.status("127.0.0.1")
        sites = {s["label"]: s for s in status["sites"]}
        self.assertEqual((sites["a.example.com"]["status"], sites["a.example.com"]["source"],
                          sites["a.example.com"]["import"]["first_child"]), ("enforced", "main", True))
        self.assertEqual(sites["b.example.com"]["status"], "not_loaded")
        self.assertEqual(status["sources"]["manual"]["active_records"], 2)
        self.assertIn("loopback", [p["category"] for p in status["protected"]])
        self.assertEqual(status["last_apply"]["user"], "admin@example.com")

    def test_external_and_management_sites(self):
        self.caddy.live = FIXTURES["simple_proxy"]
        _bans.write_caddyfile("other.example.com {\n\trespond 200\n}\n")
        self.assertEqual(service.status(None)["sites"][0]["source"], "external")
        self.caddy.live = FIXTURES["not_imported"]
        _bans.write_caddyfile("a.example.com { # caddy-console: management\n\treverse_proxy 127.0.0.1:9\n}\n")
        self.assertEqual(service.status(None)["sites"][0]["status"], "management")

    def test_console_site_that_imports_the_ban_list_is_a_lockout_risk(self):
        # Live: the console host's route carries the ban list (hand-typed import).
        self.ban()
        self.ban("198.51.100.0/24")
        self.caddy.live = FIXTURES["simple_proxy"]
        _bans.write_caddyfile(f"a.example.com {{ # caddy-console: management\n"
                              f"\timport {env.BANS_DIR}/bans-manual*.caddy\n\treverse_proxy 127.0.0.1:9\n}}\n")
        self.assertEqual(service.status(None)["sites"][0]["status"], "management_imported")

    def test_unloaded_console_site_with_the_import_on_disk_is_a_lockout_risk(self):
        self.caddy.live = {"apps": {}}
        _bans.write_caddyfile(f"a.example.com {{ # caddy-console: management\n"
                              f"\timport {env.BANS_DIR}/bans-manual*.caddy\n\treverse_proxy 127.0.0.1:9\n}}\n")
        self.assertEqual(service.status(None)["sites"][0]["status"], "management_imported")
        _bans.write_caddyfile("a.example.com { # caddy-console: management\n\treverse_proxy 127.0.0.1:9\n}\n")
        self.assertEqual(service.status(None)["sites"][0]["status"], "management")


if __name__ == "__main__":
    unittest.main()
