"""caddy fmt exits 1 when its input is not formatted (Caddy 2.11) but still
prints the formatted text; that text must be used, not thrown away."""
import unittest

import tests._env  # noqa: F401  (sets env before src is imported)
from src import validator


class FmtExitCodeTests(unittest.TestCase):
    def setUp(self):
        validator._cache.clear()
        self._real = validator.run_caddy

    def tearDown(self):
        validator.run_caddy = self._real
        validator._cache.clear()

    def _fake(self, result):
        validator.run_caddy = lambda argv, timeout=None: result

    def test_unformatted_input_returns_caddys_formatted_text(self):
        self._fake((1, "a {\n\trespond x\n}\n",
                    '{"level":"error","msg":"/tmp/C:2: Caddyfile input is not formatted; Tip: use \'--overwrite\'"}'))
        self.assertEqual(validator.caddy_fmt("a {\n    respond x\n}\n"), "a {\n\trespond x\n}\n")

    def test_other_failures_still_fall_back_to_the_input(self):
        self._fake((1, "partial", "Error: open /tmp/C: permission denied"))
        self.assertEqual(validator.caddy_fmt("original"), "original")


if __name__ == "__main__":
    unittest.main()
