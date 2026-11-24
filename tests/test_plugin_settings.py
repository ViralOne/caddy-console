"""Plugin-mode settings, the module probe and the admin exposure check (spec 3.1, 3.3).

Run with:  uv run --frozen python -m unittest tests.test_plugin_settings -v
"""
import glob
import ipaddress
import json
import os
import re
import unittest
from unittest import mock

import tests._env  # noqa: F401
from tests import _bans, _crowdsec

from src import config
from src.bans import plugin, protected, service

SECRET = "3f9a1c0b7e6d5a4f3e2d1c0b9a8f7e6d"
FIXED = "172.30.250.2:2019"


def live(listen="tcp/" + FIXED, origins=("caddy:2019", FIXED), app=None, **admin):
    doc = {"admin": {"listen": listen, "origins": list(origins), **admin}, "apps": {}}
    if listen is None:
        doc.pop("admin")
    if app is not None:
        doc["apps"]["crowdsec"] = app
    return doc


class SettingsTest(unittest.TestCase):
    def test_key_file_paths(self):
        self.assertEqual(plugin.parse_key_file(""), "")
        self.assertEqual(plugin.parse_key_file("  /run/secrets/crowdsec_plugin_bouncer_key "),
                         "/run/secrets/crowdsec_plugin_bouncer_key")
        for bad in ("run/secrets/k", "/run/secrets/../k", "/run/./k", "/run/secrets/k b", "/run/{k}",
                    "/" + "a" * 300, "/run/secrets/", "/run//k"):
            with self.assertRaises(plugin.ConfigError, msg=bad) as cm:
                plugin.parse_key_file(bad)
            self.assertIn("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", str(cm.exception))

    def test_admin_addresses(self):
        cases = {"0.0.0.0:2019": ("0.0.0.0", False), ":2019": ("", False), "localhost:2019": ("localhost", False),
                 "127.0.0.1:2019": ("127.0.0.1", False), "172.30.250.2:2019": ("172.30.250.2", True),
                 "[2001:db8::2]:2019": ("2001:db8::2", True), "[::]:2019": ("::", False),
                 "caddy:2019": ("caddy", False)}
        for raw, (host, fixed) in cases.items():
            a = plugin.parse_admin_address(raw)
            self.assertEqual((a.host, a.port, a.fixed), (host, 2019, fixed), raw)
        self.assertEqual(str(plugin.parse_admin_address("[2001:db8::2]:2019")), "[2001:db8::2]:2019")
        self.assertEqual(str(plugin.parse_admin_address("")), "0.0.0.0:2019")
        for bad in ("172.30.250.2", "172.30.250.2:0", "172.30.250.2:70000", "http://x:2019", "999.1.1.1:2019", "a b:1"):
            with self.assertRaises(plugin.ConfigError, msg=bad):
                plugin.parse_admin_address(bad)

    def test_invalid_settings_refuse_startup(self):
        for name, value in (("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", "relative/path"), ("CADDY_ADMIN_ADDRESS", "nope")):
            with mock.patch.object(config, name, value), self.assertRaisesRegex(RuntimeError, name):
                service.init_config()

    def test_placeholder_follows_the_key_mode(self):
        with mock.patch.object(config, "CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", ""):
            self.assertEqual((plugin.key_mode(), plugin.api_key_placeholder()),
                             ("env", "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"))
        with mock.patch.object(config, "CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", "/run/secrets/k"):
            self.assertEqual((plugin.key_mode(), plugin.api_key_placeholder()), ("file", "{file./run/secrets/k}"))

    def test_console_never_reads_the_plugin_key(self):
        root = os.path.join(os.path.dirname(__file__), "..", "src")
        reads = re.compile(r"""environ(?:\.get)?\s*[\[(]\s*["']CROWDSEC_PLUGIN_BOUNCER_KEY["']|getenv\(\s*["']CROWDSEC_PLUGIN_BOUNCER_KEY["']""")
        for path in glob.glob(os.path.join(root, "**", "*.py"), recursive=True):
            with open(path, encoding="utf-8") as f:
                self.assertIsNone(reads.search(f.read()), path)
        self.assertFalse(hasattr(config, "CROWDSEC_PLUGIN_BOUNCER_KEY"))


class ModuleProbeTest(unittest.TestCase):
    def setUp(self):
        plugin.reset_cache()
        self.addCleanup(plugin.reset_cache)
        self.caddy = _bans.FakeCaddy().install(self)
        self.lapi = _crowdsec.FakeLapi().install(self)

    def test_probe_tells_the_build(self):
        self.assertIs(plugin.module_available(), False)
        self.caddy.plugin = True
        self.assertIs(plugin.module_available(), False, "cached")
        self.assertIs(plugin.module_available(force=True), True)
        self.assertIs(plugin.cached_module(), True)
        self.assertEqual(self.lapi.calls, [], "the probe only adapts; it never contacts LAPI")
        probes = [t for k, t in self.caddy.calls if k == "adapt"]
        self.assertTrue(all("caddy-console-module-probe" in t for t in probes))
        self.assertFalse(any(k == "load" for k, _ in self.caddy.calls))

    def test_unreachable_or_unrelated_errors_are_unknown(self):
        self.caddy.down = True
        self.assertIsNone(plugin.module_available(force=True))
        self.caddy.down = False
        self.caddy.adapt_status = 500
        self.assertIsNone(plugin.module_available(force=True))

    def test_cached_module_never_probes(self):
        self.assertIsNone(plugin.cached_module())
        self.assertEqual(self.caddy.calls, [])


class AdminProblemTest(unittest.TestCase):
    def setUp(self):
        for name, value in (("CADDY_ADMIN_ADDRESS", FIXED), ("CROWDSEC_URL", _crowdsec.URL)):
            p = mock.patch.object(config, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(protected, "read_docker_networks",
                              lambda: [ipaddress.ip_network("172.30.250.0/29"), ipaddress.ip_network("172.31.0.0/24")])
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(plugin, "_lapi_addresses", lambda: [ipaddress.ip_address("172.31.0.5")])
        p.start()
        self.addCleanup(p.stop)

    def code(self, doc):
        problem = plugin.admin_problem(doc)
        return problem.code if problem else None

    def test_the_fixed_bind_is_fine(self):
        self.assertIsNone(plugin.admin_problem(live()))
        self.assertIsNone(plugin.admin_problem(live(listen=FIXED)))

    def test_each_exposure_is_named(self):
        self.assertEqual(self.code(live(listen=None)), "admin_missing")
        self.assertEqual(self.code(live(listen="")), "admin_missing")
        self.assertEqual(self.code(live(disabled=True)), "admin_off")
        self.assertEqual(self.code(live(listen="unix//run/a.sock")), "admin_unix")
        for listen in ("tcp/0.0.0.0:2019", ":2019", "tcp/[::]:2019"):
            self.assertEqual(self.code(live(listen=listen)), "admin_wildcard", listen)
        for listen in ("localhost:2019", "tcp/127.0.0.1:2019", "[::1]:2019"):
            self.assertEqual(self.code(live(listen=listen)), "admin_loopback", listen)
        self.assertEqual(self.code(live(listen="tcp/172.30.250.3:2019")), "admin_mismatch")
        self.assertEqual(self.code(live(origins=("caddy:2019",))), "admin_origins")

    def test_an_interface_shared_with_crowdsec_is_refused(self):
        with mock.patch.object(plugin, "_lapi_addresses", lambda: [ipaddress.ip_address("172.30.250.5")]):
            self.assertEqual(self.code(live()), "admin_shared")

    def test_the_console_must_use_the_fixed_address(self):
        with mock.patch.object(config, "CADDY_ADMIN_ADDRESS", "0.0.0.0:2019"):
            problem = plugin.admin_problem(live())
        self.assertEqual(problem.code, "admin_not_fixed")
        self.assertIn("docker-compose.crowdsec-plugin.yaml", problem.message)

    def test_messages_show_the_required_bind(self):
        problem = plugin.admin_problem(live(listen="tcp/0.0.0.0:2019"))
        self.assertIn("admin 172.30.250.2:2019 { origins caddy:2019 172.30.250.2:2019 }", problem.message)


class LiveAppTest(unittest.TestCase):
    def test_no_app(self):
        self.assertIsNone(plugin.live_app(live()))

    def test_expected_placeholder(self):
        with mock.patch.object(config, "CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", ""):
            app = plugin.live_app(live(app={"api_url": "http://crowdsec:8080", "api_key": "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}",
                                            "ticker_interval": "10s", "enable_streaming": True}))
        self.assertEqual(app, {"api_url": "http://crowdsec:8080", "ticker_interval": "10s", "streaming": True,
                               "hard_fails": False, "key_form": "expected", "key_placeholder": None})

    def test_other_placeholder_is_named(self):
        with mock.patch.object(config, "CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", "/run/secrets/k"):
            app = plugin.live_app(live(app={"api_key": "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"}))
        self.assertEqual((app["key_form"], app["key_placeholder"]), ("placeholder", "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"))
        self.assertEqual(app["ticker_interval"], "60s")

    def test_live_literal_key_is_reported_without_the_key(self):
        app = plugin.live_app(live(app={"api_key": SECRET, "disable_streaming": False}))
        self.assertEqual(app["key_form"], "literal")
        self.assertNotIn(SECRET, json.dumps(app))
        self.assertEqual(plugin.live_app(live(app={}))["key_form"], "missing")

    def test_a_placeholder_mixed_with_a_literal_is_literal(self):
        # Only a value that is exactly one placeholder is ever shown.
        for mixed in ("{env.X}" + SECRET, "{env.X} " + SECRET + "}", "{file./k}{env.Y}" + SECRET):
            app = plugin.live_app(live(app={"api_key": mixed}))
            self.assertEqual((app["key_form"], app["key_placeholder"]), ("literal", None), mixed)
            self.assertNotIn(SECRET, json.dumps(app))
