"""Admin API calls with explicit outcomes, against the fake admin API.

Run with:  uv run --frozen python -m unittest tests.test_bans_caddy -v
"""
import unittest

import tests._env  # noqa: F401
from tests import _bans

from src.bans import caddy, detect


class NormalizeTest(unittest.TestCase):
    def test_hash_ignores_key_order_only(self):
        self.assertEqual(caddy.config_hash({"a": 1, "b": [1, 2]}), caddy.config_hash({"b": [1, 2], "a": 1}))
        self.assertNotEqual(caddy.config_hash({"b": [2, 1]}), caddy.config_hash({"b": [1, 2]}))
        self.assertTrue(caddy.config_hash(None).startswith("sha256:"))


class AdminClientTest(unittest.TestCase):
    def setUp(self):
        _bans.reset()
        self.fake = _bans.FakeCaddy({"apps": {"x": 1}}).install(self)

    def test_live_config(self):
        self.assertEqual(caddy.live_config(), {"apps": {"x": 1}})
        self.fake.down = True
        with self.assertRaises(caddy.CaddyUnavailable):
            caddy.live_config()

    def test_adapt_outcomes(self):
        result = caddy.adapt("example.com {\n\trespond 200\n}\n")
        self.assertTrue(result.ok)
        self.assertIn("apps", result.config)
        self.fake.adapt_status = 400
        result = caddy.adapt("x")
        self.assertEqual((result.ok, result.message), (False, "fake adapt rejection"))
        self.fake.down = True
        with self.assertRaises(caddy.CaddyUnavailable):
            caddy.adapt("x")

    def test_load_outcomes(self):
        for mode, status in (("ok", "applied"), ("reject", "rejected"),
                             ("connect_timeout", "failed"), ("read_timeout", "unknown")):
            with self.subTest(mode=mode):
                self.fake.load_mode = mode
                self.assertEqual(caddy.load("example.com {\n}\n").status, status)

    def test_fake_adapt_reflects_imported_files(self):
        with open(_bans.MANUAL_PATH(), "w") as f:
            f.write("vars caddy_console_manual_policy 1\n")
        with open(_bans.env.CADDYFILE) as f:
            text = f.read()
        self.assertTrue(detect.marker_present(self.fake.adapt_text(text), "caddy_console_manual_policy"))
        self.assertNotEqual(caddy.config_hash(self.fake.adapt_text(text)),
                            caddy.config_hash(self.fake.adapt_text(text + "\n")))


if __name__ == "__main__":
    unittest.main()
