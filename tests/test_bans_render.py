"""Generated policy bytes (spec 1.3).

Run with:  uv run --frozen python -m unittest tests.test_bans_render -v
"""
import os
import unittest
from datetime import timedelta

import tests._env as env  # noqa: F401

from src.bans import addr, protected, render, store

NOW = store.parse_iso("2026-11-23T20:00:00Z")
MANUAL = render.SOURCES["manual"]
EXCL = protected.build().exclusion_tokens()


def rec(value, duration="permanent", reason="", source="manual"):
    r = store.new_manual_record(addr.canonical(value), duration, reason, "a@example.com", NOW)
    r.source = source
    return r


class RenderTest(unittest.TestCase):
    def test_source_paths_and_import_line(self):
        self.assertEqual(MANUAL.path, os.path.join(env.BANS_DIR, "bans-manual.caddy"))
        self.assertEqual(MANUAL.glob, "bans-manual*.caddy")
        self.assertEqual(MANUAL.import_line, f"import {env.BANS_DIR}/bans-manual*.caddy")

    def test_spec_shape_with_bans(self):
        prefixes = render.effective_prefixes([rec("203.0.113.7"), rec("198.51.100.0/24")], NOW, "manual")
        self.assertEqual(render.render_policy(MANUAL, prefixes, EXCL, 100).decode(), (
            "# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
            "vars caddy_console_manual_policy 1\n"
            "@caddy_console_manual_banned {\n"
            "\tclient_ip 198.51.100.0/24 203.0.113.7\n"
            "\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10\n"
            "}\n"
            "handle @caddy_console_manual_banned {\n"
            "\trespond 403\n"
            "}\n"))

    def test_empty_policy_keeps_only_the_marker(self):
        self.assertEqual(render.render_policy(MANUAL, [], EXCL, 100),
                         b"# Managed by Caddy Console. Do not edit; changes are overwritten.\n"
                         b"vars caddy_console_manual_policy 1\n")

    def test_overlaps_collapse_for_rendering_only(self):
        records = [rec("203.0.113.0/25"), rec("203.0.113.128/25"), rec("203.0.113.7"), rec("2001:db8::1")]
        self.assertEqual([addr.token(p) for p in render.effective_prefixes(records, NOW, "manual")],
                         ["203.0.113.0/24", "2001:db8::1"])
        self.assertEqual(len(records), 4)

    def test_expired_and_other_source_records_are_not_rendered(self):
        records = [rec("203.0.113.7", "4h"), rec("198.51.100.7", source="crowdsec"), rec("192.0.2.1")]
        self.assertEqual([addr.token(p) for p in render.effective_prefixes(records, NOW + timedelta(hours=5), "manual")],
                         ["192.0.2.1"])

    def test_reason_never_reaches_the_file(self):
        prefixes = render.effective_prefixes([rec("203.0.113.7", reason="<script>}\nrespond 200")], NOW, "manual")
        data = render.render_policy(MANUAL, prefixes, EXCL, 100)
        self.assertNotIn(b"script", data)
        self.assertNotIn(b"respond 200", data)

    def test_capacity_is_a_hard_limit(self):
        prefixes = render.effective_prefixes([rec("203.0.113.1"), rec("203.0.113.3"), rec("203.0.113.5")], NOW, "manual")
        with self.assertRaises(render.CapacityError) as cm:
            render.render_policy(MANUAL, prefixes, EXCL, 2)
        self.assertEqual((cm.exception.count, cm.exception.limit), (3, 2))


if __name__ == "__main__":
    unittest.main()
