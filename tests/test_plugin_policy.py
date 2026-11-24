"""The protected plugin route and plugin-policy.json (spec 3.4).

Run with:  uv run --frozen python -m unittest tests.test_plugin_policy -v
"""
import json
import os
import unittest
from unittest import mock

import tests._env as env
from tests import _bans, _crowdsec

from src import audit, config
from src.bans import fsio, plugin, pluginpolicy, protected, render, service, store, txn

D = env.BANS_DIR
PLUGIN_SITES = (
    "{{\n\tadmin 172.30.250.2:2019 {{\n\t\torigins caddy:2019 172.30.250.2:2019\n\t}}\n}}\n"
    "import {d}/crowdsec-plugin-protect*.caddy\n\n"
    "example.com {{\n\timport {d}/bans-manual*.caddy\n\timport protect_crowdsec\n\trespond 200\n}}\n").format(d=D)
BASE_TOKENS = "private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10"


class PluginCase(unittest.TestCase):
    def setUp(self):
        _bans.reset(PLUGIN_SITES)
        _bans.fresh_audit(self)
        service.reset_caches()
        plugin.reset_cache()
        self.addCleanup(service.reset_caches)
        self.addCleanup(plugin.reset_cache)
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.caddy = _bans.FakeCaddy().install(self)
        self.caddy.plugin = True
        self.lapi = _crowdsec.FakeLapi().install(self)
        _crowdsec.enable(self)
        self.assertIs(plugin.module_available(force=True), True)

    def route(self):
        return (fsio.read_bytes(render.PLUGIN.path) or b"").decode()


class RenderTest(unittest.TestCase):
    def test_route_shape(self):
        data = render.render_plugin_route(["private_ranges", "100.64.0.0/10", "203.0.113.50"]).decode()
        self.assertEqual(data, (
            "# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
            "(protect_crowdsec) {\n"
            "\tvars caddy_console_plugin_protect 1\n"
            "\t@caddy_console_crowdsec_candidate {\n"
            "\t\tnot client_ip private_ranges 100.64.0.0/10 203.0.113.50\n"
            "\t}\n"
            "\tcrowdsec @caddy_console_crowdsec_candidate\n"
            "}\n"))
        self.assertEqual(render.PLUGIN.import_line, f"import {D}/crowdsec-plugin-protect*.caddy")
        self.assertEqual(render.PLUGIN.site_import, "import protect_crowdsec")

    def test_state_file_embeds_the_hash(self):
        doc = json.loads(pluginpolicy.dumps("sha256:" + "a" * 64))
        self.assertEqual(doc, {"version": 1, "schema": 1,
                               "last_rendered_hashes": {"crowdsec-plugin-protect.caddy": "sha256:" + "a" * 64}})


class TransactionTest(PluginCase):
    def test_fresh_install_gets_the_route_from_the_expiry_tick(self):
        self.assertEqual(service.expire_tick(), "applied")
        self.assertIn(f"not client_ip {BASE_TOKENS}\n", self.route())
        self.assertEqual(pluginpolicy.recorded_hash(), fsio.sha256_tag(fsio.read_bytes(render.PLUGIN.path)))
        self.assertFalse(os.path.exists(store.STATE_PATH), "a plugin-only render writes no ban state")
        self.assertFalse(os.path.exists(render.SOURCES["manual"].path))
        self.assertEqual(oct(os.stat(render.PLUGIN.path).st_mode & 0o777), "0o644")
        self.assertEqual(oct(os.stat(pluginpolicy.PATH).st_mode & 0o777), "0o600")
        self.assertIn("load", [k for k, _ in self.caddy.calls], "the Caddyfile imports the definition: reload")
        self.assertIn("plugin_route_rendered", [e["action"] for e in audit.iter_entries()])
        self.assertEqual(service.expire_tick(), "idle")

    def test_manual_ban_regenerates_the_plugin_route_in_the_same_transaction(self):
        service.expire_tick()
        seen = []
        real = txn.apply_locked

        def spy(changes, **kw):
            seen.append(sorted(os.path.basename(c.path) for c in changes))
            return real(changes, **kw)
        with mock.patch.object(txn, "apply_locked", spy):
            body, status = service.add_ban({"value": "198.51.100.7", "duration": "24h", "reason": ""},
                                           "a@example.com", "203.0.113.50")
        self.assertEqual(status, 201, body)
        self.assertEqual(len(seen), 1, "one journal for the ban and the route")
        self.assertLessEqual({"bans-manual.caddy", "bans.json", "crowdsec-plugin-protect.caddy", "plugin-policy.json"},
                             set(seen[0]))
        self.assertIn(" 203.0.113.50\n", self.route(), "the new verified console address is protected")
        self.assertEqual(pluginpolicy.recorded_hash(), fsio.sha256_tag(fsio.read_bytes(render.PLUGIN.path)))

    def test_bans_never_change_is_picked_up_by_the_tick(self):
        service.expire_tick()
        with mock.patch.object(config, "BANS_NEVER", "192.0.2.10"):
            service.reset_caches()
            self.assertEqual(service.expire_tick(), "applied")
        self.assertIn(" 192.0.2.10\n", self.route())

    def test_out_of_band_edit_holds_the_route_until_reapply(self):
        service.expire_tick()
        with open(render.PLUGIN.path, "a", encoding="ascii") as f:
            f.write("# edited\n")
        state = store.load()
        self.assertEqual(service._holds(state), {"plugin": "differs"})
        self.assertEqual(service.expire_tick(), "idle")
        self.assertTrue(self.route().endswith("# edited\n"))
        info = service.recovery_info()
        self.assertEqual((info["kind"], info["files"], info["held_sources"]),
                         ("policy_hold", ["crowdsec-plugin-protect.caddy"], ["plugin"]))
        body, status = service.reapply({"source": "plugin"}, "a@example.com", None)
        self.assertEqual(status, 200, body)
        self.assertFalse(self.route().endswith("# edited\n"))
        self.assertEqual(service._holds(store.load()), {})

    def test_a_corrupt_plugin_policy_holds_instead_of_regenerating(self):
        service.expire_tick()
        with open(pluginpolicy.PATH, "w", encoding="utf-8") as f:
            f.write("{not json")
        self.assertIsNone(pluginpolicy.recorded_hash())
        self.assertEqual(service._holds(store.load()), {"plugin": "differs"})

    def test_deleted_route_file_is_held_as_missing(self):
        service.expire_tick()
        os.remove(render.PLUGIN.path)
        self.assertEqual(service._holds(store.load()), {"plugin": "missing"})

    def test_crowdsec_sync_keeps_the_route_current(self):
        service.expire_tick()
        result = service.apply_crowdsec([_crowdsec.accepted("203.0.113.9")])
        self.assertTrue(result.ok, result.message)
        self.assertEqual(pluginpolicy.recorded_hash(), fsio.sha256_tag(fsio.read_bytes(render.PLUGIN.path)))

    def test_reapply_plugin_is_refused_when_not_in_use(self):
        self.caddy.plugin = False
        plugin.module_available(force=True)
        body, status = service.reapply({"source": "plugin"}, "a@example.com", None)
        self.assertEqual((status, body["code"]), (400, "source_not_enabled"))


class InactiveTest(unittest.TestCase):
    def test_stock_caddy_never_gets_the_route(self):
        _bans.reset()
        service.reset_caches()
        plugin.reset_cache()
        self.addCleanup(plugin.reset_cache)
        caddy = _bans.FakeCaddy().install(self)
        _crowdsec.FakeLapi().install(self)
        _crowdsec.enable(self)
        docker = mock.patch.object(protected, "read_docker_networks", lambda: [])
        docker.start()
        self.addCleanup(docker.stop)
        self.assertEqual(service.expire_tick(), "idle")
        self.assertFalse(os.path.exists(render.PLUGIN.path))
        self.assertFalse(os.path.exists(pluginpolicy.PATH))
        self.assertFalse(service._plugin_active())
        self.assertFalse(any(k == "load" for k, _ in caddy.calls))


class AllowlistTest(unittest.TestCase):
    def test_commands_use_the_static_protected_set_only(self):
        prot = protected.build(never=[protected.addr.canonical("192.0.2.10")],
                               management=[protected.addr.canonical("203.0.113.50")],
                               docker=["172.30.250.0/29"])
        text = plugin.allowlist_commands(prot)
        lines = text.splitlines()
        self.assertEqual(lines[0], "cscli allowlists delete caddy_console_protected || true")
        self.assertEqual(lines[1], "cscli allowlists create caddy_console_protected -d 'Caddy Console protected ranges'")
        self.assertTrue(lines[2].startswith("cscli allowlists add caddy_console_protected 127.0.0.0/8 ::1 10.0.0.0/8"))
        self.assertIn(" 192.0.2.10", lines[2])
        self.assertIn(" 172.30.250.0/29", lines[2])
        self.assertNotIn("203.0.113.50", text, "verified console addresses change at runtime: not in the static list")
        self.assertNotIn("private_ranges", text)
