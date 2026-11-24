"""CrowdSec settings, key handling and Go durations (spec 2.3, 2.4, Configuration).

Run with:  uv run --frozen python -m unittest tests.test_crowdsec_config -v
"""
import importlib
import os
import tempfile
import unittest
from unittest import mock

import tests._env  # noqa: F401

from src import config
from src.bans import lapi, service


class SettingsTest(unittest.TestCase):
    def test_defaults(self):
        self.assertEqual((config.BANS_SYNC_INTERVAL, config.CROWDSEC_POLL_INTERVAL), (30, 10))
        self.assertEqual(config.CROWDSEC_ORIGINS, "crowdsec,cscli")
        self.assertEqual(config.CROWDSEC_URL, "")          # tests/_env.py sets none: CrowdSec off
        self.assertFalse(lapi.enabled())

    def test_numeric_bounds(self):
        # Reload src.config under a patched environment so the real module-level
        # bounded_int call is exercised; restore the module afterwards.
        try:
            for name, low, high in (("BANS_SYNC_INTERVAL", 10, 3600), ("CROWDSEC_POLL_INTERVAL", 5, 300)):
                for bad in (str(low - 1), str(high + 1), "ten"):
                    with self.subTest(name=name, bad=bad), mock.patch.dict(os.environ, {name: bad}):
                        with self.assertRaises(RuntimeError) as cm:
                            importlib.reload(config)
                        self.assertIn(name, str(cm.exception))
                for good in (str(low), str(high)):
                    with self.subTest(name=name, good=good), mock.patch.dict(os.environ, {name: good}):
                        importlib.reload(config)
                        self.assertEqual(getattr(config, name), int(good))
        finally:
            importlib.reload(config)
        self.assertEqual((config.BANS_SYNC_INTERVAL, config.CROWDSEC_POLL_INTERVAL), (30, 10))

    def test_url(self):
        self.assertEqual(lapi.parse_url(""), "")
        self.assertEqual(lapi.parse_url(" http://crowdsec:8080/ "), "http://crowdsec:8080")
        self.assertEqual(lapi.parse_url("https://lapi.example.com"), "https://lapi.example.com")
        for bad in ("crowdsec:8080", "ftp://crowdsec", "http://user:pw@crowdsec:8080", "http://crowdsec:8080/v1",
                    "http://crowdsec:8080?x=1", "http://crowdsec:99999", "http://"):
            with self.subTest(bad=bad), self.assertRaises(lapi.ConfigError):
                lapi.parse_url(bad)

    def test_origins(self):
        self.assertEqual(lapi.parse_origins("crowdsec,cscli"), ("crowdsec", "cscli"))
        self.assertEqual(lapi.parse_origins(" CAPI, lists ,capi"), ("capi", "lists"))
        for bad in ("", " , ", "crowd sec", "a;b", "x" * 33):
            with self.subTest(bad=bad), self.assertRaises(lapi.ConfigError):
                lapi.parse_origins(bad)

    def test_wire_origins_keep_operator_case(self):
        self.assertEqual(lapi.wire_origins(" CAPI, lists ,capi,CAPI"), ("CAPI", "lists", "capi"))
        with self.assertRaises(lapi.ConfigError):
            lapi.wire_origins(" , ")

    def test_enabled_needs_bans_and_a_url(self):
        with mock.patch.object(config, "CROWDSEC_URL", "http://crowdsec:8080"):
            self.assertTrue(lapi.enabled())
            with mock.patch.object(config, "BANS_ENABLED", False):
                self.assertFalse(lapi.enabled())

    def test_invalid_url_or_origins_refuse_startup(self):
        for name, value in (("CROWDSEC_URL", "crowdsec:8080"), ("CROWDSEC_ORIGINS", "a b")):
            with self.subTest(name=name), mock.patch.object(config, name, value):
                service.reset_caches()
                with self.assertRaises(RuntimeError) as cm:
                    service.init_config()
                self.assertIn(name, str(cm.exception))
        service.reset_caches()


class KeyTest(unittest.TestCase):
    def test_env_key(self):
        with mock.patch.multiple(config, CROWDSEC_CONSOLE_BOUNCER_KEY=" k3y-0123 ", CROWDSEC_CONSOLE_BOUNCER_KEY_FILE=""):
            self.assertEqual(lapi.read_key(), ("k3y-0123", None))

    def test_file_key_wins_and_problems_never_echo_the_key(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("file-key-456\n")
        self.addCleanup(os.remove, f.name)
        with mock.patch.multiple(config, CROWDSEC_CONSOLE_BOUNCER_KEY="env-key", CROWDSEC_CONSOLE_BOUNCER_KEY_FILE=f.name):
            self.assertEqual(lapi.read_key(), ("file-key-456", None))
        with mock.patch.multiple(config, CROWDSEC_CONSOLE_BOUNCER_KEY="", CROWDSEC_CONSOLE_BOUNCER_KEY_FILE=f.name + ".missing"):
            key, problem = lapi.read_key()
            self.assertIsNone(key)
            self.assertIn("CROWDSEC_CONSOLE_BOUNCER_KEY_FILE", problem)
        for bad in ("", "has space", "x" * 257, "café"):
            with self.subTest(bad=bad), mock.patch.multiple(config, CROWDSEC_CONSOLE_BOUNCER_KEY=bad,
                                                            CROWDSEC_CONSOLE_BOUNCER_KEY_FILE=""):
                key, problem = lapi.read_key()
                self.assertIsNone(key)
                if bad.strip():
                    self.assertNotIn(bad, problem)


class GoDurationTest(unittest.TestCase):
    def test_valid(self):
        cases = {"4h": 14400, "1.5h": 5400, "22h20m11.909761348s": 80411.909761348, "300ms": 0.3,
                 ".5s": 0.5, "1µs": 1e-6, "1μs": 1e-6, "1us": 1e-6, "2ns": 2e-9, "0": 0, "+3m": 180,
                 "-18897h25m52.809576151s": -(18897 * 3600 + 25 * 60 + 52.809576151), "167h59m20.890999684s": 604760.890999684}
        for text, seconds in cases.items():
            with self.subTest(text=text):
                self.assertAlmostEqual(lapi.parse_go_duration(text), seconds, places=9)

    def test_invalid(self):
        for bad in ("", "h", "4", "4d", "4h ", " 4h", "--1s", "1e3s", "1h" * 33, "999999999h", "1.2.3s", None, 5):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                lapi.parse_go_duration(bad)


if __name__ == "__main__":
    unittest.main()