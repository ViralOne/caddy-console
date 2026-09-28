"""Tests for the caddy subprocess wrapper, its cache, and the session key.

Run with:  python3 -m unittest discover -s tests -v
No caddy binary required.
"""
import os
import tempfile
import unittest

import tests._env  # noqa: F401  (sets env before src is imported)

from src import validator  # noqa: E402


class RunCaddyTest(unittest.TestCase):
    def test_timeout_is_reported_not_raised(self):
        rc, _, stderr = validator.run_caddy(["sleep", "5"], timeout=0.3)
        self.assertEqual(rc, validator.TIMED_OUT)
        self.assertIn("did not finish", stderr)

    def test_missing_binary_is_reported_not_raised(self):
        rc, _, stderr = validator.run_caddy(["caddy-does-not-exist-xyz"])
        self.assertEqual(rc, validator.NOT_FOUND)
        self.assertIn("not found", stderr)

    def test_successful_command_passes_through(self):
        rc, stdout, _ = validator.run_caddy(["echo", "hi"], timeout=5)
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.strip(), "hi")


class CacheTest(unittest.TestCase):
    def setUp(self):
        validator._cache.clear()
        self.calls = []
        self._real = validator.run_caddy

        def counting(argv, timeout=None):
            self.calls.append(argv)
            return self.next_result

        validator.run_caddy = counting
        self.next_result = (0, "formatted\n", "")

    def tearDown(self):
        validator.run_caddy = self._real
        validator._cache.clear()

    def test_validate_result_is_reused_for_identical_content(self):
        self.next_result = (0, "", "")
        first = validator.caddy_validate("a b c")
        second = validator.caddy_validate("a b c")
        self.assertEqual(first, (True, "Config is valid"))
        self.assertEqual(second, first)
        self.assertEqual(len(self.calls), 1, "second call should hit the cache")

    def test_different_content_is_not_shared(self):
        self.next_result = (0, "", "")
        validator.caddy_validate("one")
        validator.caddy_validate("two")
        self.assertEqual(len(self.calls), 2)

    def test_fmt_and_validate_do_not_share_a_cache_entry(self):
        self.next_result = (0, "formatted\n", "")
        validator.caddy_fmt("same")
        self.next_result = (0, "", "")
        validator.caddy_validate("same")
        self.assertEqual(len(self.calls), 2)

    def test_invalid_config_reports_stderr(self):
        self.next_result = (1, "", "line 3: unrecognized directive")
        ok, message = validator.caddy_validate("bad")
        self.assertFalse(ok)
        self.assertIn("unrecognized directive", message)

    def test_timeouts_are_not_cached(self):
        self.next_result = (validator.TIMED_OUT, "", "caddy did not finish within 20s")
        ok, message = validator.caddy_validate("slow")
        self.assertFalse(ok)
        self.assertIn("did not finish", message)
        validator.caddy_validate("slow")
        self.assertEqual(len(self.calls), 2, "a timeout must not be remembered")

    def test_fmt_falls_back_to_input_when_caddy_fails(self):
        self.next_result = (1, "", "boom")
        self.assertEqual(validator.caddy_fmt("original"), "original")

    def test_cache_is_bounded(self):
        self.next_result = (0, "", "")
        for i in range(validator._CACHE_MAX * 3):
            validator.caddy_validate(f"config {i}")
        self.assertLessEqual(len(validator._cache), validator._CACHE_MAX)


class SecretKeyTest(unittest.TestCase):
    def test_generated_key_is_stable_across_calls(self):
        """Each gunicorn worker calls create_app(); they must agree on the key."""
        import src

        with tempfile.TemporaryDirectory() as tmp:
            original = src.BACKUP_DIR
            src.BACKUP_DIR = tmp
            try:
                first = src._persisted_secret_key()
                second = src._persisted_secret_key()
                self.assertEqual(first, second)
                self.assertEqual(len(first), 64)
                mode = os.stat(os.path.join(tmp, ".secret_key")).st_mode & 0o777
                self.assertEqual(mode, 0o600)
            finally:
                src.BACKUP_DIR = original

    def test_unwritable_dir_still_yields_a_key(self):
        import src

        original = src.BACKUP_DIR
        src.BACKUP_DIR = "/proc/definitely/not/writable"
        try:
            self.assertEqual(len(src._persisted_secret_key()), 64)
        finally:
            src.BACKUP_DIR = original


class SmartValidateTest(unittest.TestCase):
    def test_flags_a_bare_hostname(self):
        warnings = validator.smart_validate("notadomain {\n\treverse_proxy localhost:80\n}\n")
        self.assertEqual(len(warnings), 1)
        self.assertIn("notadomain", warnings[0])

    def test_accepts_real_looking_sites_snippets_and_ports(self):
        config = (
            "{\n\tadmin off\n}\n\n"
            "(logme) {\n\tlog\n}\n\n"
            "http://a.example.com {\n\timport logme\n}\n\n"
            "*.wild.example.com {\n\trespond 200\n}\n\n"
            ":8080 {\n\trespond 200\n}\n"
        )
        self.assertEqual(validator.smart_validate(config), [])

    def test_accepts_localhost_and_ipv6_literals(self):
        config = (
            "localhost {\n\trespond 200\n}\n\n"
            "localhost:8443 {\n\trespond 200\n}\n\n"
            "app.localhost {\n\trespond 200\n}\n\n"
            "[::1]:9000 {\n\trespond 200\n}\n"
        )
        self.assertEqual(validator.smart_validate(config), [])


if __name__ == "__main__":
    unittest.main()


class AdaptValidationTest(unittest.TestCase):
    """Validation goes through the running Caddy, so plugins always match.

    Validating a `tls { dns cloudflare }` config with the bundled plain binary
    reports "module not registered" for a config that loads fine.
    """

    def setUp(self):
        validator._cache.clear()
        self._real_post = validator.http_client.post
        self._real_run = validator.run_caddy
        self.posts = []
        self.ran = []

        def fake_run(argv, timeout=None):
            self.ran.append(argv)
            return (0, "", "")

        validator.run_caddy = fake_run

    def tearDown(self):
        validator.http_client.post = self._real_post
        validator.run_caddy = self._real_run
        validator._cache.clear()

    def _respond(self, status, body=""):
        posts = self.posts

        class Resp:
            status_code = status
            text = body

        def fake_post(url, **kw):
            posts.append((url, kw))
            return Resp()

        validator.http_client.post = fake_post

    def test_adapt_success_is_valid_and_skips_the_local_binary(self):
        self._respond(200, '{"apps":{}}')
        ok, message = validator.caddy_validate("example.com {\n}\n")
        self.assertTrue(ok, message)
        self.assertTrue(self.posts, "should have asked the running Caddy")
        self.assertTrue(self.posts[0][0].endswith("/adapt"))
        self.assertEqual(self.posts[0][1]["headers"]["Content-Type"], "text/caddyfile")
        self.assertEqual(self.ran, [], "must not fall back when /adapt answered")

    def test_adapt_rejection_is_reported_verbatim(self):
        # What the user actually sees when a directive is wrong.
        self._respond(400, "getting module named 'dns.providers.cloudflare'")
        ok, message = validator.caddy_validate("x")
        self.assertFalse(ok)
        self.assertIn("dns.providers.cloudflare", message)

    def test_unreachable_admin_api_falls_back_to_the_local_binary(self):
        def boom(url, **kw):
            raise validator.http_client.RequestException("connection refused")

        validator.http_client.post = boom
        ok, _ = validator.caddy_validate("y")
        self.assertTrue(ok)
        self.assertTrue(self.ran, "should have fallen back to the binary")
        self.assertIn("validate", self.ran[0])

    def test_a_rejection_is_not_confused_with_an_outage(self):
        # A 400 is an answer about the config; only a transport failure is not.
        self._respond(400, "bad")
        validator.caddy_validate("z")
        self.assertEqual(self.ran, [])

    def test_adapt_results_are_cached_like_the_binary_path(self):
        self._respond(200, "{}")
        validator.caddy_validate("same")
        validator.caddy_validate("same")
        self.assertEqual(len(self.posts), 1)
