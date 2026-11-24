"""Per-site plugin detection and the plugin part of GET /api/security (spec 3.5,
"Mode detection and health").

Run with:  uv run --frozen python -m unittest tests.test_plugin_status -v
"""
import copy
import json
import os
import unittest
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import config
from src.bans import addr, detect, fsio, plugin, protected, render, scan, service, store

HERE = os.path.dirname(__file__)
with open(os.path.join(HERE, "fixtures", "bans", "adapted-plugin-layouts.json"), encoding="utf-8") as f:
    FX = json.load(f)
CURRENT = detect.expand_tokens(["private_ranges", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"])
MANUAL = render.SOURCES["manual"]
SECRET = "3f9a1c0b7e6d5a4f3e2d1c0b9a8f7e6d"
FIXED = "172.30.250.2:2019"


def plugin_status(name, expected=CURRENT):
    return detect.plugin_site_statuses(FX[name], expected_exclusions=expected)[0]


class DetectTest(unittest.TestCase):
    def test_expand_tokens(self):
        self.assertEqual(detect.expand_tokens(["private_ranges", "203.0.113.5"]),
                         ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "127.0.0.1/8", "fd00::/8", "::1",
                          "203.0.113.5"])

    def test_protected_route_is_enforced(self):
        for name in ("plugin_only", "manual_and_plugin", "plugin_redir", "plugin_strict_route"):
            s = plugin_status(name)
            self.assertEqual((s.status, s.pre_handlers), ("enforced", []), name)
        self.assertEqual(plugin_status("plugin_only", expected=None).status, "enforced")

    def test_bare_handler_is_plugin_unprotected(self):
        s = plugin_status("bare_handler")
        self.assertEqual(s.status, "plugin_unprotected")
        self.assertIn("import protect_crowdsec", s.detail)

    def test_a_global_app_without_a_site_handler_is_not_enforcement(self):
        self.assertIn("crowdsec", FX["app_without_handler"]["apps"])
        self.assertEqual(plugin_status("app_without_handler").status, "not_imported")
        self.assertEqual(plugin_status("manual_and_crowdsec_file").status, "not_imported")

    def test_an_outdated_protected_set_is_unknown(self):
        s = plugin_status("plugin_outdated")
        self.assertEqual(s.status, "unknown")
        self.assertIn("Re-apply", s.detail)

    def test_plugin_route_is_not_a_pre_handler_for_manual_bans(self):
        for name in ("manual_and_plugin", "manual_crowdsec_and_plugin", "bare_handler", "plugin_strict_route"):
            s = detect.site_statuses(FX[name], MANUAL, True,
                                     expected_ranges=["198.51.100.0/24", "203.0.113.7"])[0]
            self.assertEqual((s.status, s.pre_handlers), ("enforced", []), name)

    def test_rows_align_with_the_file_detection(self):
        for name, cfg in FX.items():
            self.assertEqual([s.label for s in detect.plugin_site_statuses(cfg)],
                             [s.label for s in detect.site_statuses(cfg, MANUAL, False)], name)


class ImportStateTest(unittest.TestCase):
    def test_snippet_import_position(self):
        d = env.BANS_DIR
        text = (f"a.example.com {{\n\timport {d}/bans-manual*.caddy\n\timport {d}/bans-crowdsec*.caddy\n"
                "\timport protect_crowdsec\n\trespond 200\n}\n")
        block = scan.site_blocks(text)[0]
        after = (render.SOURCES["manual"].path, render.SOURCES["crowdsec"].path)
        st = scan.block_import_state(text, block, None, after=after, snippet="protect_crowdsec")
        self.assertEqual((st["present"], st["line"], st["first_child"], st["layout"]), (True, 4, True, "site"))
        late = text.replace("\timport protect_crowdsec\n\trespond 200\n", "\trespond 200\n\timport protect_crowdsec\n")
        st = scan.block_import_state(late, scan.site_blocks(late)[0], None, after=after, snippet="protect_crowdsec")
        self.assertEqual((st["present"], st["first_child"]), (True, False))
        none = scan.block_import_state("a.example.com {\n\trespond 200\n}\n", scan.site_blocks("a.example.com {\n\trespond 200\n}\n")[0],
                                       None, snippet="protect_crowdsec")
        self.assertFalse(none["present"])


class StatusCase(unittest.TestCase):
    SITE = ("{{\n\tadmin 172.30.250.2:2019 {{\n\t\torigins caddy:2019 172.30.250.2:2019\n\t}}\n}}\n"
            "import {d}/crowdsec-plugin-protect*.caddy\n\n"
            "a.example.com {{\n\timport {d}/bans-manual*.caddy\n\timport protect_crowdsec\n"
            "\treverse_proxy 127.0.0.1:9\n}}\n")

    def setUp(self):
        _bans.reset(self.SITE.format(d=env.BANS_DIR))
        service.reset_caches()
        plugin.reset_cache()
        self.addCleanup(service.reset_caches)
        self.addCleanup(plugin.reset_cache)
        for name, value in (("CADDY_ADMIN_ADDRESS", FIXED),):
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)
        self.caddy.plugin = True
        _crowdsec.FakeLapi().install(self)
        _crowdsec.enable(self)
        p = mock.patch.object(plugin, "_lapi_addresses", lambda: [])
        p.start()
        self.addCleanup(p.stop)
        now = store.utc_now()
        state = store.State()
        for v in ("198.51.100.0/24", "203.0.113.7"):
            state.records.append(store.new_manual_record(addr.canonical(v), "24h", "", "a@example.com", now))
        fsio.atomic_write(store.STATE_PATH, store.dumps(state), 0o600)
        plugin.module_available(force=True)
        self.assertEqual(service.expire_tick(), "applied")   # writes the route for the current protected set
        # Only now install the real adapted layout: FakeCaddy's /load replaced live above.
        live = copy.deepcopy(FX["manual_and_plugin"])
        live["admin"] = {"listen": "tcp/" + FIXED, "origins": ["caddy:2019", FIXED]}
        self.caddy.live = live

    def status(self):
        return service.status("203.0.113.200")


class StatusTest(StatusCase):
    def test_rows_report_the_plugin_path_per_site(self):
        row = next(r for r in self.status()["sites"] if r["label"] == "a.example.com")
        p = row["policies"]["plugin"]
        self.assertEqual(p["status"], "enforced")
        self.assertEqual((p["import"]["present"], p["import"]["first_child"]), (True, True))
        self.assertNotIn("plugin", self.status()["sources"], "plugin is not a ban source")

    def test_plugin_block(self):
        s = self.status()["plugin"]
        self.assertEqual((s["enabled"], s["module"], s["refused"], s["admin"]), (True, True, False, None))
        self.assertEqual((s["key_mode"], s["placeholder"], s["ticker_interval"]),
                         ("env", "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}", "10s"))
        d = s["definition"]
        self.assertEqual((d["present"], d["current"], d["hold"], d["imported"]), (True, True, False, True))
        self.assertEqual(d["import_line"], render.PLUGIN.import_line)
        self.assertEqual(len(d["hash"]), 12)
        self.assertIn("cscli allowlists add caddy_console_protected", s["allowlist"])
        self.assertIn("crowdsec/check-plugin-isolation.sh", s["check_command"])

    def test_a_wildcard_admin_refuses_activation(self):
        self.caddy.live["admin"] = {"listen": "tcp/0.0.0.0:2019"}
        s = self.status()["plugin"]
        self.assertEqual((s["refused"], s["admin"]["code"]), (True, "admin_wildcard"))

    def test_an_outdated_running_route_is_unknown(self):
        with mock.patch.object(config, "BANS_NEVER", "192.0.2.10"):
            service.reset_caches()
            row = next(r for r in self.status()["sites"] if r["label"] == "a.example.com")
        self.assertEqual(row["policies"]["plugin"]["status"], "unknown")

    def test_the_key_never_appears_in_status(self):
        self.caddy.live["apps"]["crowdsec"]["api_key"] = SECRET
        body = json.dumps(self.status())
        self.assertNotIn(SECRET, body)
        self.assertIn('"key_form": "literal"', body)

    def test_unreachable_caddy_marks_the_plugin_unknown_too(self):
        self.caddy.down = True
        row = next(r for r in self.status()["sites"] if r["label"] == "a.example.com")
        self.assertEqual(row["policies"]["plugin"]["status"], "caddy_unreachable")
        self.assertIsNone(self.status()["plugin"]["admin"])


class StockStatusTest(unittest.TestCase):
    def test_stock_caddy_has_no_plugin_block_or_rows(self):
        _bans.reset()
        service.reset_caches()
        plugin.reset_cache()
        self.addCleanup(plugin.reset_cache)
        _bans.FakeCaddy().install(self)
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        s = service.status(None)
        self.assertEqual(s["plugin"], {"enabled": False})
        self.assertTrue(all("plugin" not in r["policies"] for r in s["sites"]))
