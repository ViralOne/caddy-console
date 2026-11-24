"""Per-site enforcement from adapted JSON, and the on-disk Caddyfile scan.

Run with:  uv run --frozen python -m unittest tests.test_bans_detect -v
"""
import copy
import json
import os
import unittest

import tests._env  # noqa: F401

from src.bans import detect, render, scan

MANUAL = render.SOURCES["manual"]
with open(os.path.join(os.path.dirname(__file__), "fixtures", "bans", "adapted-layouts.json"), encoding="utf-8") as f:
    FIXTURES = json.load(f)

EXPECTED = {
    "simple_proxy": ("enforced", []),
    "handle_catchall": ("enforced", []),
    "handle_path_specific": ("enforced", []),
    "handle_before_import": ("unknown", ["respond"]),
    "handle_path": ("enforced", []),
    "route_strict": ("enforced", []),
    "redir_before": ("enforced_pre_handler", ["redir"]),
    "rewrite_before": ("enforced_pre_handler", ["rewrite"]),
    "basic_auth_before": ("enforced_pre_handler", ["basic_auth"]),
    "forward_auth_before": ("enforced_pre_handler", ["forward_auth"]),
    "request_header_before": ("enforced_pre_handler", ["request_header"]),
    "manual_and_crowdsec": ("enforced", []),
    "crowdsec_only": ("not_imported", []),
    "invoke_before": ("unknown", ["invoke"]),
    "custom_order_first": ("unknown", ["respond"]),
    "not_imported": ("not_imported", []),
}


class LiveDetectionTest(unittest.TestCase):
    def test_fixture_covers_every_layout(self):
        self.assertEqual(set(FIXTURES), set(EXPECTED) | {"empty_policy"})

    def test_each_layout_gets_the_expected_status(self):
        for name, (status, pre) in EXPECTED.items():
            with self.subTest(layout=name):
                sites = detect.site_statuses(FIXTURES[name], MANUAL, active=True)
                self.assertEqual([s.label for s in sites], ["a.example.com"])
                self.assertEqual((sites[0].status, sites[0].pre_handlers), (status, pre))

    def test_empty_policy_keeps_its_marker_without_a_matcher(self):
        config = FIXTURES["empty_policy"]
        self.assertTrue(detect.marker_present(config, MANUAL.marker))
        self.assertNotIn('"client_ip"', json.dumps(config))
        self.assertEqual(detect.site_statuses(config, MANUAL, active=False)[0].status, "imported_empty")
        # Bans exist but the live config has no matcher yet: not proven.
        self.assertEqual(detect.site_statuses(config, MANUAL, active=True)[0].status, "unknown")

    def _with_user_route(self):
        """empty_policy plus the user's own `@blocked client_ip 1.2.3.4` / `respond 403` sibling route."""
        config = copy.deepcopy(FIXTURES["empty_policy"])
        sub = config["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"]
        sub.append({"match": [{"client_ip": {"ranges": ["1.2.3.4"]}}],
                    "handle": [{"handler": "subroute", "routes": [{"handle": [{"handler": "static_response", "status_code": 403}]}]}]})
        return config

    def test_users_own_client_ip_403_route_is_not_the_ban_route(self):
        config = self._with_user_route()
        self.assertEqual(detect.site_statuses(config, MANUAL, active=False)[0].status, "imported_empty")
        self.assertEqual(detect.site_statuses(config, MANUAL, active=True)[0].status, "unknown")

    def test_expected_ranges_must_match_the_managed_route(self):
        config = FIXTURES["simple_proxy"]
        ok = ["198.51.100.0/24", "203.0.113.7"]
        self.assertEqual(detect.site_statuses(config, MANUAL, active=True, expected_ranges=ok)[0].status, "enforced")
        for wrong in (["198.51.100.0/24"], ok + ["192.0.2.1"]):
            self.assertEqual(detect.site_statuses(config, MANUAL, active=True, expected_ranges=wrong)[0].status, "unknown")
        self.assertEqual(detect.site_statuses(config, MANUAL, active=False, expected_ranges=["192.0.2.1"])[0].status, "imported_empty")

    def test_marker_values_and_missing_config(self):
        for value in ("1", 1):
            self.assertTrue(detect.marker_present({"x": [{"handler": "vars", MANUAL.marker: value}]}, MANUAL.marker))
        self.assertFalse(detect.marker_present({"x": [{"handler": "vars", MANUAL.marker: "0"}]}, MANUAL.marker))
        self.assertFalse(detect.marker_present(None, MANUAL.marker))
        self.assertEqual(detect.site_statuses(None, MANUAL, active=True), [])

    def test_handler_classes(self):
        self.assertEqual(detect.classify({"handler": "headers", "response": {"set": {}}}), ("benign", None))
        self.assertEqual(detect.classify({"handler": "headers", "request": {"set": {}}}), ("pre", "request_header"))
        self.assertEqual(detect.classify({"handler": "static_response", "status_code": 308, "headers": {"Location": ["/x"]}}), ("pre", "redir"))
        self.assertEqual(detect.classify({"handler": "static_response", "status_code": 200}), ("unknown", "respond"))
        self.assertEqual(detect.classify({"handler": "reverse_proxy"}), ("unknown", "reverse_proxy"))
        self.assertEqual(detect.classify({"handler": "mystery"}), ("unknown", "mystery"))

    def test_hostless_site_is_labelled_by_listener(self):
        config = {"apps": {"http": {"servers": {"srv0": {"listen": [":8080"], "routes": [{"handle": []}]}}}}}
        self.assertEqual(detect.site_statuses(config, MANUAL, active=False)[0].label, ":8080")


P = "/etc/caddy/console/bans-manual.caddy"
CF = "\n".join([
    "{", "\tadmin 0.0.0.0:2019", "}", "",                                                   # 1-4
    "(snip) {", "\theader -Server", "}", "",                                                # 5-8
    "&(app) {", "\trespond \"named\"", "}", "",                                             # 9-12
    "a.example.com {", "\timport /etc/caddy/console/bans-manual*.caddy",
    "\treverse_proxy 127.0.0.1:9", "}", "",                                                 # 13-17
    "b.example.com {", "\tencode gzip", "\timport /etc/caddy/console/*.caddy", "}", "",     # 18-22
    "c.example.com {", "\troute {", "\t\timport /etc/caddy/console/bans-manual.caddy",
    "\t\trespond 200", "\t}", "}", "",                                                      # 23-29
    "console.example.com { # caddy-console: management", "\treverse_proxy caddy-console:9090", "}", "",  # 30-33
    "d.example.com {", "\timport access_log", "\timport /etc/caddy/console/bans-manual*.caddy",
    "\timport /etc/caddy/console/bans-manual*.caddy", "\trespond 200", "}",                 # 34-39
])


class ScanTest(unittest.TestCase):
    def test_site_blocks_skip_globals_snippets_and_named_routes(self):
        self.assertEqual([(b.hosts, b.start, b.end, b.management) for b in scan.site_blocks(CF)], [
            (["a.example.com"], 13, 16, False), (["b.example.com"], 18, 21, False),
            (["c.example.com"], 23, 28, False), (["console.example.com"], 30, 32, True),
            (["d.example.com"], 34, 39, False)])

    def test_glob_matching_follows_caddy(self):
        self.assertTrue(scan.glob_matches("/etc/caddy/console/bans-manual*.caddy", P))
        self.assertTrue(scan.glob_matches("/etc/caddy/console/*.caddy", P))
        self.assertTrue(scan.glob_matches("/etc/caddy/*/bans-manual.caddy", P))
        self.assertFalse(scan.glob_matches("/etc/caddy/*.caddy", P))
        self.assertFalse(scan.glob_matches("access_log", P))
        self.assertTrue(scan.glob_matches("console/bans-manual*.caddy", P))   # relative: cannot resolve, assume yes
        self.assertFalse(scan.glob_matches("/etc/caddy/console/bans-manual*.caddy", "/etc/caddy/console/.bans-manual.caddy.ab12cd34.tmp"))

    def test_mentions_import(self):
        self.assertTrue(scan.mentions_import(CF, P))
        self.assertFalse(scan.mentions_import("x.example.com {\n\timport access_log\n}\n", P))

    def test_block_import_state(self):
        blocks = {b.hosts[0]: b for b in scan.site_blocks(CF)}
        state = lambda h: scan.block_import_state(CF, blocks[h], P)
        self.assertEqual(state("a.example.com"), {"present": True, "count": 1, "line": 14, "first_child": True, "layout": "site"})
        self.assertEqual(state("b.example.com"), {"present": True, "count": 1, "line": 20, "first_child": False, "layout": None})
        self.assertEqual(state("c.example.com"), {"present": True, "count": 1, "line": 25, "first_child": True, "layout": "strict"})
        self.assertEqual(state("console.example.com")["present"], False)
        self.assertEqual(state("d.example.com"), {"present": True, "count": 2, "line": 36, "first_child": False, "layout": None})

    def test_management_hosts(self):
        self.assertEqual(scan.management_hosts(CF), {"console.example.com"})
        self.assertEqual(scan.management_hosts(CF, "Admin.Example.com"), {"console.example.com", "admin.example.com"})

    def test_console_host_comes_from_an_explicit_server_url(self):
        from unittest import mock
        with mock.patch.object(scan.config, "SERVER_URL_CONFIGURED", True), \
                mock.patch.object(scan.config, "SERVER_URL", "https://Console.Example.com:8443"):
            self.assertEqual(scan.console_host(), "console.example.com")
        with mock.patch.object(scan.config, "SERVER_URL_CONFIGURED", False):
            self.assertIsNone(scan.console_host())

    def test_validator_warnings(self):
        warnings = scan.bans_warnings(CF, P, {"console.example.com"})
        self.assertEqual(warnings, [
            "Line 20: put the ban import first in the site block (or first inside its top-level route) so nothing runs before the ban check.",
            "Line 36: this site imports the manual ban list 2 times; keep one import.",
            "Line 36: put the ban import first in the site block (or first inside its top-level route) so nothing runs before the ban check.",
        ])
        own = "console.example.com {\n\timport /etc/caddy/console/bans-manual*.caddy\n}\n"
        self.assertIn("console's own site", scan.bans_warnings(own, P, {"console.example.com"})[0])
        custom = "x.example.com {\n\t@caddy_console_mine path /a\n\trespond @caddy_console_mine 404\n}\n"
        self.assertIn("reserved for Caddy Console", scan.bans_warnings(custom, P)[0])


if __name__ == "__main__":
    unittest.main()
