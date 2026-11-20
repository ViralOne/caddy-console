"""Tests for the caddy subprocess wrapper, its cache, and the session key.

Run with:  python3 -m unittest discover -s tests -v
No caddy binary required.
"""
import os
import socket
import tempfile
import time
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
        self.assertEqual(first, (True, "Config passed local Caddy validation"))
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
            "(logme) {\n\tlog {\n\t\tformat filter {\n\t\t\twrap json\n"
            "\t\t\trequest>headers delete\n\t\t\tresp_headers delete\n\t\t}\n\t}\n}\n\n"
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

    def test_warns_when_access_logs_are_not_filtered(self):
        warnings = validator.smart_validate(
            "example.com {\n\tlog {\n\t\toutput file /var/log/caddy/access.log\n\t}\n}\n"
        )
        self.assertEqual(len(warnings), 1)
        self.assertIn("format filter", warnings[0])

    def test_warns_when_filter_keeps_header_maps(self):
        config = (
            "example.com {\n\tlog {\n\t\tformat filter {\n\t\t\twrap json\n"
            "\t\t}\n\t}\n}\n"
        )
        warnings = validator.smart_validate(config)
        self.assertEqual(len(warnings), 2)
        self.assertTrue(any("request>headers" in w for w in warnings))
        self.assertTrue(any("resp_headers" in w for w in warnings))

    def test_warns_when_file_mode_blocks_non_root_console(self):
        config = (
            "example.com {\n\tlog {\n\t\toutput file /var/log/caddy/access.log {\n"
            "\t\t\troll_size 10mb\n\t\t}\n\t\tformat filter {\n\t\t\twrap json\n"
            "\t\t\trequest>headers delete\n\t\t\tresp_headers delete\n\t\t}\n\t}\n}\n"
        )
        warnings = validator.smart_validate(config)
        self.assertEqual(len(warnings), 1)
        self.assertIn("mode 0644", warnings[0])

    def test_global_runtime_log_is_not_mistaken_for_access_log(self):
        config = "{\n\tlog {\n\t\tlevel INFO\n\t}\n}\n\nexample.com {\n\trespond 200\n}\n"
        self.assertEqual(validator.smart_validate(config), [])

    def test_single_line_access_log_is_detected(self):
        warnings = validator.smart_validate("example.com { log }\n")
        self.assertEqual(len(warnings), 1)
        self.assertIn("format filter", warnings[0])

    def test_log_credentials_is_flagged_when_headers_remain(self):
        config = (
            "{\n\tservers {\n\t\tlog_credentials\n\t}\n}\n"
            "example.com {\n\tlog {\n\t\tformat filter {\n\t\t\twrap json\n"
            "\t\t}\n\t}\n}\n"
        )
        warnings = validator.smart_validate(config)
        self.assertTrue(any("log_credentials" in w for w in warnings))


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
        ok, message, level = validator.caddy_check("example.com {\n}\n")
        self.assertTrue(ok, message)
        self.assertEqual(level, "adapted")
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
        ok, _, level = validator.caddy_check("y")
        self.assertTrue(ok)
        self.assertEqual(level, "validated")
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


class FmtWarningTest(unittest.TestCase):
    def test_identical_is_none(self):
        self.assertIsNone(validator.fmt_warning("a {\n}\n", "a {\n}\n"))

    def test_points_at_the_first_changed_line_and_counts_lines(self):
        before = "a.example.com {\n    respond 200\n}\n\nb.example.com {\n  respond 201\n}\n"
        after = "a.example.com {\n\trespond 200\n}\n\nb.example.com {\n\trespond 201\n}\n"
        self.assertEqual(validator.fmt_warning(before, after),
                         "Line 2: not formatted — Check will fix whitespace on 2 lines")

    def test_singular(self):
        self.assertEqual(validator.fmt_warning("a {\n  x\n}\n", "a {\n\tx\n}\n"),
                         "Line 2: not formatted — Check will fix whitespace on 1 line")

    def test_change_past_the_end_is_clamped_to_the_last_line(self):
        self.assertEqual(validator.fmt_warning("a {\n}", "a {\n}\n"),
                         "Line 2: not formatted — Check will fix whitespace on 1 line")



class ResolveWarningTest(unittest.TestCase):
    def setUp(self):
        validator._dns_cache.clear()
        self.calls = []

    def tearDown(self):
        validator._dns_cache.clear()

    def lookup(self, answers):
        def fake(host, port):
            self.calls.append(host)
            outcome = answers.get(host, "ok")
            if outcome == "missing":
                raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
            if outcome == "again":
                raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure")
            if outcome == "slow":
                time.sleep(0.5)
            return [("ok",)]
        return fake

    def warn(self, content, answers=None, timeout=1.0):
        return validator.upstream_resolve_warnings(content, lookup=self.lookup(answers or {}), timeout=timeout)

    def test_resolvable_upstream_is_quiet(self):
        self.assertEqual(self.warn("a.example.com {\n\treverse_proxy web:8080\n}\n"), [])
        self.assertEqual(self.calls, ["web"])

    def test_unresolvable_upstream_is_warned_with_its_line(self):
        self.assertEqual(
            self.warn("a.example.com {\n\treverse_proxy radarr:7878\n}\n", {"radarr": "missing"}),
            ["Line 2: upstream radarr:7878 could not be resolved from the console container"])

    def test_ip_literals_placeholders_and_sockets_are_never_looked_up(self):
        content = ("a.example.com {\n\treverse_proxy 127.0.0.1:2283 [::1]:80 ::1\n"
                   "\treverse_proxy {$UPSTREAM} {http.request.host}:80\n"
                   "\treverse_proxy unix//run/app.sock :8080\n}\n")
        self.assertEqual(self.warn(content), [])
        self.assertEqual(self.calls, [])

    def test_matchers_schemes_and_to_lines(self):
        content = ("a.example.com {\n\treverse_proxy /api/* http://api:80 {\n\t\tto backup:80\n\t}\n"
                   "\treverse_proxy @ws ws-backend:9000\n}\n")
        warnings = self.warn(content, {"api": "missing", "backup": "missing", "ws-backend": "missing"})
        self.assertEqual(warnings, [
            "Line 2: upstream http://api:80 could not be resolved from the console container",
            "Line 3: upstream backup:80 could not be resolved from the console container",
            "Line 5: upstream ws-backend:9000 could not be resolved from the console container",
        ])

    def test_timeout_and_transient_errors_are_not_failures(self):
        started = time.monotonic()
        self.assertEqual(self.warn("a {\n\treverse_proxy slow:1 flaky:2\n}\n",
                                   {"slow": "slow", "flaky": "again"}, timeout=0.05), [])
        self.assertLess(time.monotonic() - started, 0.4, "must not wait for the slow lookup")

    def test_results_are_cached(self):
        content = "a {\n\treverse_proxy web:1\n}\nb {\n\treverse_proxy web:2\n}\n"
        self.warn(content)
        self.warn(content)
        self.assertEqual(self.calls, ["web"])


if __name__ == "__main__":
    unittest.main()
