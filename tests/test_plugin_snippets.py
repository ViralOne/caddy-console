"""Plugin snippets, their context, validator warnings and the admin save guard (spec 3.1, 3.6).

Run with:  uv run --frozen python -m unittest tests.test_plugin_snippets -v
"""
import json
import os
import unittest
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import config
from src.bans import plugin, protected, render, scan, service

HERE = os.path.dirname(__file__)
FIX = os.path.join(HERE, "fixtures", "plugin")
FIXED = "172.30.250.2:2019"
IDS = ("crowdsec-plugin-global-env", "crowdsec-plugin-global-file", "crowdsec-plugin-definition",
       "crowdsec-plugin-site", "crowdsec-plugin-allowlist")


def fixture(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return f.read()


def shipped():
    with open(os.path.join(HERE, "..", "src", "snippets.json"), encoding="utf-8") as f:
        return {s["id"]: s for s in json.load(f) if "id" in s}


class ShippedTest(unittest.TestCase):
    def test_every_plugin_snippet_line_is_in_the_adapted_fixtures(self):
        s = shipped()
        for sid, name in (("crowdsec-plugin-global-env", "env.Caddyfile"), ("crowdsec-plugin-global-file", "file.Caddyfile")):
            text = fixture(name)
            for code_id in (sid, "crowdsec-plugin-definition", "crowdsec-plugin-site"):
                for line in s[code_id]["code"].splitlines():
                    self.assertIn(line, text, (name, code_id, line))
        self.assertNotIn("{file.", fixture("env.Caddyfile"))
        self.assertNotIn("{env.", fixture("file.Caddyfile"))

    def test_route_fixture_is_the_rendered_definition(self):
        with open(os.path.join(FIX, "crowdsec-plugin-protect.caddy"), "rb") as f:
            self.assertEqual(f.read(), render.render_plugin_route(protected.RENDER_BASE))

    def test_allowlist_snippet_is_the_core_set(self):
        self.assertEqual(shipped()["crowdsec-plugin-allowlist"]["code"], plugin.allowlist_commands(protected.build()))

    def test_plugin_snippets_declare_scope_and_prerequisites(self):
        s = shipped()
        self.assertEqual([s[i]["insert"] for i in IDS],
                         ["global-options", "global-options", "top-level", "site-first", "copy-only"])
        for i in IDS:
            self.assertEqual(s[i]["prerequisites"], ["BANS_ENABLED", "CROWDSEC_URL", "CROWDSEC_PLUGIN"])
            self.assertEqual(s[i]["phase"], "plugin")


class SnippetApiTest(_bans.ApiCase):
    def setUp(self):
        super().setUp()
        plugin.reset_cache()
        self.addCleanup(plugin.reset_cache)
        _crowdsec.enable(self)
        for name, value in (("CADDY_ADMIN_ADDRESS", FIXED), ("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", "")):
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(plugin, "_lapi_addresses", lambda: [])
        p.start()
        self.addCleanup(p.stop)
        self.caddy.live = {"admin": {"listen": "tcp/" + FIXED, "origins": ["caddy:2019", FIXED]}, "apps": {}}

    def snippets(self):
        r = self.get("/api/snippets")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        return {s.get("id"): s for s in body["snippets"]}, body["context"]

    def test_stock_caddy_offers_no_plugin_snippet(self):
        found, ctx = self.snippets()
        self.assertFalse(set(IDS) & set(found))
        self.assertIsNone(ctx["plugin"])

    def test_env_mode_offers_only_the_env_global(self):
        self.caddy.plugin = True
        found, ctx = self.snippets()
        self.assertEqual(sorted(set(IDS) & set(found)), sorted(set(IDS) - {"crowdsec-plugin-global-file"}))
        self.assertEqual(found["crowdsec-plugin-definition"]["code"], f"import {env.BANS_DIR}/crowdsec-plugin-protect*.caddy\n")
        p = ctx["plugin"]
        self.assertEqual((p["module"], p["blocked"], p["key_mode"], p["app_live"], p["snippet"]),
                         (True, "", "env", False, "protect_crowdsec"))
        self.assertEqual(p["definition_target"], f"{env.BANS_DIR}/crowdsec-plugin-protect.caddy")

    def test_file_mode_uses_the_configured_path(self):
        self.caddy.plugin = True
        with mock.patch.object(config, "CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", "/run/secrets/my_key"):
            found, ctx = self.snippets()
        self.assertNotIn("crowdsec-plugin-global-env", found)
        self.assertIn("api_key {file./run/secrets/my_key}\n", found["crowdsec-plugin-global-file"]["code"])
        self.assertEqual(ctx["plugin"]["key_mode"], "file")

    def test_an_exposed_admin_blocks_plugin_insertion(self):
        self.caddy.plugin = True
        self.caddy.live["admin"] = {"listen": "tcp/0.0.0.0:2019"}
        _, ctx = self.snippets()
        self.assertIn("every interface", ctx["plugin"]["blocked"])

    def test_context_tracks_the_live_app_and_the_definition(self):
        self.caddy.plugin = True
        _bans.write_caddyfile(fixture("env.Caddyfile").replace("/etc/caddy/console", env.BANS_DIR))
        self.caddy.live["apps"]["crowdsec"] = {"api_key": "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"}
        _, ctx = self.snippets()
        p = ctx["plugin"]
        self.assertEqual((p["app_live"], p["app_on_disk"], p["definition_import"], p["definition_current"]),
                         (True, True, True, False))
        service.expire_tick()
        _, ctx = self.snippets()
        self.assertTrue(ctx["plugin"]["definition_current"])
        self.assertEqual(len(ctx["plugin"]["definition_hash"]), 12)

    def test_served_allowlist_uses_the_deployment_set(self):
        self.caddy.plugin = True
        with mock.patch.object(config, "BANS_NEVER", "192.0.2.10"):
            service.reset_caches()
            found, _ = self.snippets()
        self.assertIn(" 192.0.2.10", found["crowdsec-plugin-allowlist"]["code"])


class SaveGuardTest(_bans.ApiCase):
    GOOD = "{\n\tadmin 172.30.250.2:2019 {\n\t\torigins caddy:2019 172.30.250.2:2019\n\t}\n}\nexample.com {\n\trespond 200\n}\n"

    def setUp(self):
        super().setUp()
        p = mock.patch.object(plugin, "_lapi_addresses", lambda: [])
        p.start()
        self.addCleanup(p.stop)

    def save(self, content):
        return self.post("/api/save", {"content": content})

    def test_save_refuses_an_admin_bind_other_than_the_fixed_one(self):
        with mock.patch.object(config, "CADDY_ADMIN_ADDRESS", FIXED):
            self.assertEqual(self.save(self.GOOD).status_code, 200)
            for bad in (self.GOOD.replace("admin 172.30.250.2:2019 {\n\t\torigins caddy:2019 172.30.250.2:2019\n\t}",
                                          "admin 0.0.0.0:2019"),
                        "example.com {\n\trespond 200\n}\n",
                        self.GOOD.replace("origins caddy:2019 172.30.250.2:2019", "origins caddy:2019")):
                r = self.save(bad)
                self.assertEqual(r.status_code, 409, bad)
                self.assertEqual(r.get_json()["code"], "admin_exposed")
                self.assertTrue(r.get_json()["message"].startswith("Not saved: "))
        self.assertFalse(any(k == "load" and "0.0.0.0" in t for k, t in self.caddy.calls))

    def test_the_guard_applies_with_bans_disabled(self):
        bad = "{\n\tadmin 0.0.0.0:2019\n}\nexample.com {\n\trespond 200\n}\n"
        with mock.patch.object(config, "CADDY_ADMIN_ADDRESS", FIXED), mock.patch.object(config, "BANS_ENABLED", False):
            r = self.save(bad)
            self.assertEqual(r.status_code, 409)
            self.assertEqual(r.get_json()["code"], "admin_exposed")
            self.assertEqual(self.save(self.GOOD).status_code, 200)

    def test_the_guard_is_off_without_a_fixed_admin_address(self):
        self.assertEqual(self.save("{\n\tadmin 0.0.0.0:2019\n}\nexample.com {\n\trespond 200\n}\n").status_code, 200)


class WarningTest(unittest.TestCase):
    D = env.BANS_DIR

    def warn(self, text, management=frozenset(), placeholder="{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"):
        return scan.plugin_warnings(text, render.PLUGIN.path, management, placeholder=placeholder,
                                    crowdsec_path=render.SOURCES["crowdsec"].path)

    def test_the_fixture_is_clean(self):
        self.assertEqual(self.warn(fixture("env.Caddyfile").replace("/etc/caddy/console", self.D)), [])

    def test_bare_crowdsec_directive_warns(self):
        text = f"import {self.D}/crowdsec-plugin-protect*.caddy\na.example.com {{\n\tcrowdsec\n\trespond 200\n}}\n"
        self.assertEqual(len([w for w in self.warn(text) if w.startswith("Line 3:") and "import protect_crowdsec" in w]), 1)

    def test_site_import_needs_the_top_level_definition(self):
        w = self.warn("a.example.com {\n\timport protect_crowdsec\n}\n")
        self.assertTrue(any(x.startswith("Line 2:") and "top level" in x for x in w), w)
        inside = f"a.example.com {{\n\timport {self.D}/crowdsec-plugin-protect*.caddy\n\timport protect_crowdsec\n}}\n"
        self.assertTrue(any(x.startswith("Line 2:") and "outside every site" in x for x in self.warn(inside)))

    def test_redundant_file_and_plugin_paths_warn(self):
        text = (f"import {self.D}/crowdsec-plugin-protect*.caddy\na.example.com {{\n"
                f"\timport {self.D}/bans-crowdsec*.caddy\n\timport protect_crowdsec\n}}\n")
        self.assertTrue(any("twice" in x for x in self.warn(text)))

    def test_console_site_import_is_a_lockout_risk(self):
        text = f"import {self.D}/crowdsec-plugin-protect*.caddy\nconsole.example.com {{\n\timport protect_crowdsec\n}}\n"
        self.assertTrue(any("lock you out" in x for x in self.warn(text, {"console.example.com"})))

    def test_literal_or_mismatched_key_warns_without_echoing(self):
        g = "{\n\tcrowdsec {\n\t\tapi_url http://crowdsec:8080\n\t\tapi_key %s\n\t}\n\torder crowdsec first\n}\n"
        w = self.warn(g % "3f9a1c0b7e6d5a4f3e2d1c0b9a8f7e6d")
        self.assertTrue(any(x.startswith("Line 4:") and "written into the Caddyfile" in x for x in w), w)
        self.assertFalse(any("3f9a1c0b7e6d" in x for x in w))
        w = self.warn(g % "{file./run/secrets/k}")
        self.assertTrue(any("{env.CROWDSEC_PLUGIN_BOUNCER_KEY}" in x for x in w), w)

    def test_a_placeholder_mixed_with_a_literal_is_not_echoed(self):
        g = "{\n\tcrowdsec {\n\t\tapi_key {env.X}3f9a1c0b7e6d5a4f\n\t}\n\torder crowdsec first\n}\n"
        w = self.warn(g)
        self.assertTrue(any(x.startswith("Line 3:") and "written into the Caddyfile" in x for x in w), w)
        self.assertFalse(any("3f9a1c0b7e6d" in x for x in w), w)

    def test_global_app_without_order_warns(self):
        w = self.warn("{\n\tcrowdsec {\n\t\tapi_key {env.CROWDSEC_PLUGIN_BOUNCER_KEY}\n\t}\n}\n")
        self.assertTrue(any("order crowdsec first" in x for x in w), w)


class ValidateApiTest(_bans.ApiCase):
    def test_validate_reports_plugin_warnings(self):
        text = f"import {env.BANS_DIR}/crowdsec-plugin-protect*.caddy\na.example.com {{\n\tcrowdsec\n}}\n"
        body = self.post("/api/validate", {"content": text}).get_json()
        self.assertTrue(any("import protect_crowdsec" in w for w in body["warnings"]), body)
