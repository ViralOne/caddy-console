"""The crowdsec source beside manual: records, rendering, capacity, expiry,
holds, Re-apply and Reset (spec 2.4, 2.5, 1.6).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_sources -v
"""
import os
import unittest
from datetime import timedelta
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import audit, config
from src.bans import addr, fsio, lapi, protected, render, service, store

CS = render.SOURCES["crowdsec"]
MANUAL = render.SOURCES["manual"]
BOTH = ("example.com {{\n\timport {d}/bans-manual*.caddy\n\timport {d}/bans-crowdsec*.caddy\n"
        "\trespond 200\n}}\n").format(d=env.BANS_DIR)


def cs_record(value, decision_id, hours=4, now=None):
    now = now or store.utc_now()
    return store.new_crowdsec_record(str(decision_id), addr.canonical(value), "crowdsec",
                                     "crowdsecurity/http-probing", now, now + timedelta(hours=hours))


def put_records(*records):
    state = store.load()
    state.records.extend(records)
    fsio.atomic_write(store.STATE_PATH, store.dumps(state), 0o600)


class SourcesCase(unittest.TestCase):
    def setUp(self):
        _bans.reset(BOTH)
        _bans.fresh_audit(self)
        service.reset_caches()
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)

    def tearDown(self):
        service.reset_caches()

    def ban(self, value="203.0.113.7"):
        return service.add_ban({"value": value, "duration": "24h", "reason": ""}, "admin@example.com", None)


class RecordTest(SourcesCase):
    def test_crowdsec_record_round_trip_and_rules(self):
        r = cs_record("203.0.113.9", 42)
        self.assertEqual((r.id, r.source, r.source_id, r.actor, r.reason, r.origin), (
            "crowdsec-42", "crowdsec", "42", "system", "", "crowdsec"))
        state = store.State(records=[r])
        self.assertEqual(store.parse(store.dumps(state)).records[0], r)
        for field, bad in (("source_id", None), ("source_id", "4x"), ("source_id", "1" * 21),
                           ("origin", None), ("origin", ""), ("reason", "manual note")):
            broken = store.Record(**{**r.__dict__, field: bad})
            with self.subTest(field=field, bad=bad), self.assertRaises(store.StateCorrupt):
                store.parse(store.dumps(store.State(records=[broken])))


class RenderTest(SourcesCase):
    def test_crowdsec_policy_shape(self):
        data = render.render_policy(CS, [addr.canonical("203.0.113.9")], ["private_ranges"], 10)
        self.assertEqual(data.decode(), render.HEADER + "vars caddy_console_crowdsec_policy 1\n"
                         "@caddy_console_crowdsec_banned {\n\tclient_ip 203.0.113.9\n\tnot client_ip private_ranges\n}\n"
                         "handle @caddy_console_crowdsec_banned {\n\trespond 403\n}\n")
        self.assertEqual(render.render_policy(CS, [], ["private_ranges"], 10).decode(),
                         render.HEADER + "vars caddy_console_crowdsec_policy 1\n")
        self.assertEqual((CS.glob, CS.import_line), ("bans-crowdsec*.caddy", f"import {env.BANS_DIR}/bans-crowdsec*.caddy"))

    def test_active_sources(self):
        self.assertEqual(list(render.active_sources(store.State())), ["manual"])
        self.assertEqual(list(render.active_sources(None)), ["manual"])
        self.assertIn("crowdsec", render.active_sources(store.State(records=[cs_record("203.0.113.9", 1)])))
        self.assertIn("crowdsec", render.active_sources(store.State(last_rendered_hashes={CS.filename: "sha256:" + "0" * 64})))
        with mock.patch.object(config, "CROWDSEC_URL", _crowdsec.URL):
            self.assertEqual(list(render.active_sources(store.State())), ["manual", "crowdsec"])

    def test_whitespace_url_is_disabled_like_lapi_enabled(self):
        with mock.patch.object(config, "CROWDSEC_URL", "   "):
            self.assertFalse(lapi.enabled())
            self.assertEqual(list(render.active_sources(store.State())), ["manual"])

    def test_a_crowdsec_file_on_disk_keeps_the_source_active(self):
        fsio.atomic_write(CS.path, b"# left behind\n", 0o644)
        self.assertIn("crowdsec", render.active_sources(store.State()))
        self.assertIn("crowdsec", render.active_sources(None))

    def test_check_capacity_counts_the_total(self):
        render.check_capacity({"manual": 2, "crowdsec": 1}, 3)
        with self.assertRaises(render.CapacityError) as cm:
            render.check_capacity({"manual": 2, "crowdsec": 2}, 3)
        self.assertEqual((cm.exception.count, cm.exception.limit, cm.exception.by_source),
                         (4, 3, {"manual": 2, "crowdsec": 2}))


class ServiceSourcesTest(SourcesCase):
    def test_unconfigured_install_never_creates_the_crowdsec_file(self):
        self.assertEqual(self.ban()[1], 201)
        self.assertFalse(os.path.exists(CS.path))
        self.assertNotIn(CS.filename, store.load().last_rendered_hashes)

    def test_configured_crowdsec_renders_an_empty_policy_beside_manual(self):
        _crowdsec.enable(self)
        self.assertEqual(self.ban()[1], 201)
        state = store.load()
        self.assertEqual(fsio.read_bytes(CS.path), render.HEADER.encode() + b"vars caddy_console_crowdsec_policy 1\n")
        self.assertEqual(state.last_rendered_hashes[CS.filename], fsio.sha256_tag(fsio.read_bytes(CS.path)))
        self.assertIn(b"203.0.113.7", fsio.read_bytes(MANUAL.path))

    def test_capacity_counts_both_sources(self):
        _crowdsec.enable(self)
        put_records(cs_record("198.51.100.9", 1))
        with mock.patch.object(config, "BANS_MAX", 2):
            self.assertEqual(self.ban("203.0.113.7")[1], 201)
            body, status = self.ban("203.0.113.8")
        self.assertEqual((status, body["code"]), (409, "capacity_exceeded"))
        self.assertEqual([r.value for r in store.load().records if r.source == "manual"], ["203.0.113.7"])

    def test_crowdsec_records_expire_through_the_tick(self):
        _crowdsec.enable(self)
        now = store.utc_now()
        put_records(cs_record("198.51.100.9", 1, hours=1, now=now))
        self.assertEqual(service.reapply({"source": "crowdsec"}, "op", None)[1], 200)   # render it once
        self.assertIn(b"198.51.100.9", fsio.read_bytes(CS.path))
        self.assertEqual(service.expire_tick(now + timedelta(hours=2)), "applied")
        self.assertNotIn(b"198.51.100.9", fsio.read_bytes(CS.path))
        self.assertIn("ban_expired", [e["action"] for e in audit.iter_entries()])

    def test_crowdsec_turned_off_keeps_expiring_and_resettable(self):
        _crowdsec.enable(self)
        now = store.utc_now()
        put_records(cs_record("198.51.100.9", 1, hours=1, now=now))
        self.assertEqual(service.reapply({"source": "crowdsec"}, "op", None)[1], 200)
        with mock.patch.object(config, "CROWDSEC_URL", ""):
            self.assertIn("crowdsec", render.active_sources(store.load()))
            version = store.load().version
            body, status = service.reset({"source": "crowdsec", "version": version, "confirm": True}, "op", None)
            self.assertEqual(status, 200, body)
            self.assertNotIn(b"198.51.100.9", fsio.read_bytes(CS.path))
            self.assertIn("unless", body["message"])

    def test_reset_crowdsec_is_not_enabled_without_crowdsec_state(self):
        version = store.load().version
        body, _ = service.reset({"source": "crowdsec", "version": version, "confirm": True}, "op", None)
        self.assertEqual(body["code"], "source_not_enabled")

    def test_corrupt_state_reset_never_strands_crowdsec_bans_when_disabled(self):
        # CrowdSec on, a decision rendered, then CrowdSec off and bans.json corrupt:
        # the store no longer says crowdsec was used, but its file still enforces.
        _crowdsec.enable(self)
        put_records(cs_record("198.51.100.9", 1))
        self.assertEqual(service.reapply({"source": "crowdsec"}, "op", None)[1], 200)
        self.assertIn(b"198.51.100.9", fsio.read_bytes(CS.path))
        with mock.patch.object(config, "CROWDSEC_URL", ""):
            with open(store.STATE_PATH, "wb") as f:
                f.write(b"{broken")
            status = service.status("127.0.0.1")
            self.assertIn("crowdsec", status["sources"])             # shown, so the UI offers its Reset
            self.assertFalse(status["sources"]["crowdsec"]["enabled"])
            version = status["recovery"]["state_version"]
            body, code = service.reset({"source": "crowdsec", "version": version, "confirm": True}, "op", None)
            self.assertEqual(code, 200, body)
            self.assertNotIn(b"198.51.100.9", fsio.read_bytes(CS.path))
            self.assertIn(CS.filename, store.load().last_rendered_hashes)

    def test_corrupt_state_manual_reset_also_clears_a_stale_crowdsec_file(self):
        _crowdsec.enable(self)
        put_records(cs_record("198.51.100.9", 1))
        self.assertEqual(service.reapply({"source": "crowdsec"}, "op", None)[1], 200)
        with mock.patch.object(config, "CROWDSEC_URL", ""):
            with open(store.STATE_PATH, "wb") as f:
                f.write(b"{broken")
            version = service.recovery_info()["state_version"]
            body, code = service.reset({"source": "manual", "version": version, "confirm": True}, "op", None)
            self.assertEqual(code, 200, body)
            self.assertNotIn(b"198.51.100.9", fsio.read_bytes(CS.path))

    def test_held_crowdsec_file_does_not_mark_a_manual_ban_held(self):
        _crowdsec.enable(self)
        self.ban("203.0.113.7")
        fsio.atomic_write(CS.path, b"", 0o644)            # host recovery truncated it
        body, status = self.ban("203.0.113.8")
        self.assertEqual(status, 201)
        self.assertEqual(body["enforcement"], "enforced")
        self.assertEqual(fsio.read_bytes(CS.path), b"")    # held: not regenerated
        body, status = service.reapply({"source": "crowdsec"}, "op", None)
        self.assertEqual(status, 200, body)
        self.assertIn(b"vars caddy_console_crowdsec_policy 1", fsio.read_bytes(CS.path))

    def test_crowdsec_records_cannot_be_removed_and_list_reports_both_sources(self):
        _crowdsec.enable(self)
        self.ban()
        put_records(cs_record("198.51.100.9", 1))
        body, status = service.list_bans()
        self.assertEqual(body["rendered_by_source"], {"manual": 1, "crowdsec": 1})
        cs = next(r for r in body["records"] if r["source"] == "crowdsec")
        self.assertEqual(cs["source_id"], "1")
        self.assertEqual(service.remove_ban(cs["id"], "op", None)[1], 403)


class CapacityPriorityTest(SourcesCase):
    def test_after_constant(self):
        self.assertEqual(render.AFTER, {"crowdsec": ("manual",)})

    def test_local_count_ignores_non_local_origins(self):
        now = store.utc_now()
        recs = [cs_record("198.51.100.1", 1), cs_record("198.51.100.2", 2),
                store.new_crowdsec_record("3", addr.canonical("198.51.100.3"), "CAPI", "x", now, now + timedelta(hours=1)),
                store.new_crowdsec_record("4", addr.canonical("198.51.100.4"), "lists:foo", "x", now, now + timedelta(hours=1)),
                store.new_crowdsec_record("5", addr.canonical("198.51.100.5"), "CsCli", "x", now, now + timedelta(hours=1)),
                store.new_manual_record(addr.canonical("203.0.113.1"), "24h", "", "a", now)]
        self.assertEqual(render.capacity_counts(recs, now), {"manual": 1, "crowdsec": 3})

    def _capi_flood(self):
        """Four non-collapsible non-local prefixes: more than BANS_MAX=2 on their own."""
        _crowdsec.enable(self)
        now = store.utc_now()
        put_records(*[store.new_crowdsec_record(str(i), addr.canonical(f"198.51.100.{i}"), "CAPI", "x",
                                                now, now + timedelta(hours=1)) for i in (4, 8, 12, 16)])
        return now

    def test_non_local_crowdsec_origins_never_refuse_a_manual_ban(self):
        self._capi_flood()
        with mock.patch.object(config, "BANS_MAX", 2):
            self.assertEqual(self.ban("203.0.113.7")[1], 201)
            self.assertEqual(self.ban("203.0.113.20")[1], 201)
            body, status = self.ban("203.0.113.40")
        self.assertEqual((status, body["code"]), (409, "capacity_exceeded"))
        self.assertEqual(body["by_source"], {"manual": 3, "crowdsec": 0})

    def test_non_local_origins_never_block_remove_or_expiry(self):
        now = self._capi_flood()
        with mock.patch.object(config, "BANS_MAX", 2):
            body, status = self.ban("203.0.113.7")
            self.assertEqual(status, 201)
            self.assertEqual(service.remove_ban(body["record"]["id"], "op", None)[1], 200)
            self.assertEqual(self.ban("203.0.113.8")[1], 201)
            self.assertEqual(service.expire_tick(now + timedelta(days=2)), "applied")
            self.assertEqual(service.reset({"source": "manual", "version": store.load().version,
                                            "confirm": True}, "op", None)[1], 200)


if __name__ == "__main__":
    unittest.main()
