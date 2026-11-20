"""/api/validate reports every "Line N" against the editor text (`content`),
not against what `caddy fmt` would make of it: formatting can collapse blank
lines and so shift every line after them."""
import unittest
from unittest import mock

import tests._env  # noqa: F401  (sets env before src is imported)

from src.routes import editor as editor_mod
from tests.test_app import AppTestCase

# Lines 2-4 are blank; the formatter collapses them to one, shifting line 6 to 4.
CONTENT = "a.example.com {\n\n\n\n}\nbadname {\n\treverse_proxy nope:80\n}\n"
FORMATTED = "a.example.com {\n}\n\nbadname {\n\treverse_proxy nope:80\n}\n"


class ValidateLineNumbersTest(AppTestCase):
    def test_warning_lines_point_into_the_editor_text(self):
        seen = {}

        def check(c):
            seen["check"] = c
            return True, "ok", "validated"

        def resolve(c):
            seen["resolve"] = c
            return []

        with mock.patch.object(editor_mod, "caddy_fmt", lambda c: FORMATTED), \
             mock.patch.object(editor_mod, "caddy_check", check), \
             mock.patch.object(editor_mod, "upstream_resolve_warnings", resolve):
            body = self.post("/api/validate", {"content": CONTENT}).get_json()
        self.assertTrue(body["valid"])
        self.assertIn("Line 6: 'badname' doesn't look like a valid domain", body["warnings"])
        self.assertEqual(seen["check"], CONTENT)
        self.assertEqual(seen["resolve"], CONTENT)
        self.assertEqual(body["formatted"], FORMATTED)


if __name__ == "__main__":
    unittest.main()
