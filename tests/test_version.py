"""The version is written in three files; this is what keeps them equal.

src/config.py is the one the app serves, pyproject.toml is what a build would
publish, and package.json is what the JS tooling reports. Nothing forces them to
agree at runtime, so a release that bumps one and forgets another ships a UI
claiming a version that was never tagged.
"""
import json
import pathlib
import re
import unittest

import tests._env as env  # noqa: F401  (sets env before src is imported)

from src.config import APP_VERSION

ROOT = pathlib.Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")


class VersionTest(unittest.TestCase):
    def test_app_version_is_semver(self):
        self.assertRegex(APP_VERSION, SEMVER)

    def test_pyproject_matches(self):
        text = (ROOT / "pyproject.toml").read_text()
        found = re.search(r'^version = "([^"]+)"', text, re.M)
        self.assertIsNotNone(found, "pyproject.toml has no version")
        self.assertEqual(found.group(1), APP_VERSION)

    def test_package_json_matches(self):
        data = json.loads((ROOT / "package.json").read_text())
        self.assertEqual(data["version"], APP_VERSION)
