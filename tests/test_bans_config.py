"""BANS_* settings: defaults, bounds and the test environment they run in.

Run with:  uv run --frozen python -m unittest tests.test_bans_config -v
"""
import os
import re
import unittest
from unittest import mock

import tests._env as env  # noqa: F401  (sets env before src is imported)

from src import config


class BansConfigTest(unittest.TestCase):
    def test_test_environment_keeps_bans_dir_inside_the_caddyfile_dir(self):
        self.assertTrue(config.BANS_ENABLED)
        self.assertEqual(config.BANS_DIR, env.BANS_DIR)
        self.assertEqual(os.path.dirname(config.BANS_DIR), os.path.dirname(config.CADDYFILE))
        self.assertEqual(config.BANS_NEVER, "")

    def test_bans_max_has_a_bounded_default(self):
        self.assertTrue(1 <= config.BANS_MAX <= 100000)

    def test_bounded_int_rejects_out_of_range_and_garbage(self):
        with mock.patch.dict(os.environ, {"X_TEST": "0"}):
            with self.assertRaises(RuntimeError):
                config.bounded_int("X_TEST", 5, 1, 10)
        with mock.patch.dict(os.environ, {"X_TEST": "ten"}):
            with self.assertRaises(RuntimeError):
                config.bounded_int("X_TEST", 5, 1, 10)
        with mock.patch.dict(os.environ, {"X_TEST": " 7 "}):
            self.assertEqual(config.bounded_int("X_TEST", 5, 1, 10), 7)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("X_TEST", None)
            self.assertEqual(config.bounded_int("X_TEST", 5, 1, 10), 5)


if __name__ == "__main__":
    unittest.main()


class BansMaxDocumentedTest(unittest.TestCase):
    def test_default_matches_docs_security(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "docs", "security.md"), encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"\| `BANS_MAX` \| `(\d+)` \|", text)
        self.assertIsNotNone(m, "docs/security.md has no BANS_MAX row")
        self.assertEqual(config.BANS_MAX, int(m.group(1)))
