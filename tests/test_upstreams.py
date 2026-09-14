"""Tests for mapping Caddy upstreams back to the sites that proxy to them.

Run with:  python3 -m unittest discover -s tests -t . -v
"""
import unittest

import tests._env  # noqa: F401  (sets env before src is imported)

from src.routes.ops import _walk_routes  # noqa: E402


def walk(routes):
    detail = {}
    _walk_routes(routes, [], detail)
    return {dial: {**info, "domains": sorted(info["domains"])} for dial, info in detail.items()}


def site(host, handler):
    """The shape the Caddyfile adapter produces: host match outside, subroute in."""
    return {
        "match": [{"host": [host]}],
        "handle": [{"handler": "subroute", "routes": [{"handle": [handler]}]}],
    }


def proxy(dial, health_checks=None):
    handler = {"handler": "reverse_proxy", "upstreams": [{"dial": dial}]}
    if health_checks:
        handler["health_checks"] = health_checks
    return handler


class WalkRoutesTest(unittest.TestCase):
    def test_finds_upstream_nested_under_subroute(self):
        result = walk([site("a.example.com", proxy("10.0.0.1:8080"))])
        self.assertEqual(result["10.0.0.1:8080"]["domains"], ["a.example.com"])

    def test_same_upstream_used_by_several_sites(self):
        result = walk([
            site("a.example.com", proxy("10.0.0.1:8080")),
            site("b.example.com", proxy("10.0.0.1:8080")),
        ])
        self.assertEqual(result["10.0.0.1:8080"]["domains"], ["a.example.com", "b.example.com"])

    def test_site_with_several_upstreams(self):
        handler = {
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "10.0.0.1:80"}, {"dial": "10.0.0.2:80"}],
        }
        result = walk([site("lb.example.com", handler)])
        self.assertEqual(sorted(result), ["10.0.0.1:80", "10.0.0.2:80"])
        self.assertEqual(result["10.0.0.2:80"]["domains"], ["lb.example.com"])

    def test_passive_health_requires_fail_duration(self):
        result = walk([
            site("off.example.com", proxy("10.0.0.1:80")),
            site("zero.example.com", proxy("10.0.0.2:80", {"passive": {"fail_duration": 0}})),
            site("on.example.com", proxy("10.0.0.3:80", {"passive": {"fail_duration": 30000000000}})),
        ])
        self.assertFalse(result["10.0.0.1:80"]["passive"], "no health_checks at all")
        self.assertFalse(result["10.0.0.2:80"]["passive"], "fail_duration 0 means off")
        self.assertTrue(result["10.0.0.3:80"]["passive"])

    def test_active_health_is_detected(self):
        result = walk([
            site("a.example.com", proxy("10.0.0.1:80", {"active": {"uri": "/", "interval": 30}})),
            site("b.example.com", proxy("10.0.0.2:80")),
        ])
        self.assertTrue(result["10.0.0.1:80"]["active"])
        self.assertFalse(result["10.0.0.2:80"]["active"])

    def test_flags_are_ored_across_sites_sharing_an_upstream(self):
        result = walk([
            site("plain.example.com", proxy("10.0.0.1:80")),
            site("checked.example.com", proxy("10.0.0.1:80", {"passive": {"fail_duration": 5}})),
        ])
        self.assertTrue(result["10.0.0.1:80"]["passive"])

    def test_deeply_nested_subroutes(self):
        inner = {"handler": "subroute", "routes": [{"handle": [proxy("10.0.0.9:99")]}]}
        result = walk([site("deep.example.com", inner)])
        self.assertEqual(result["10.0.0.9:99"]["domains"], ["deep.example.com"])

    def test_upstream_without_host_matcher(self):
        result = walk([{"handle": [proxy("10.0.0.1:80")]}])
        self.assertEqual(result["10.0.0.1:80"]["domains"], [])

    def test_ignores_non_proxy_handlers(self):
        result = walk([site("static.example.com", {"handler": "file_server", "root": "/srv"})])
        self.assertEqual(result, {})

    def test_tolerates_malformed_config(self):
        for bad in (None, {}, [], "nonsense", [None], [{"handle": None}], [{"handle": ["x"]}],
                    [{"handle": [{"handler": "reverse_proxy", "upstreams": [{}]}]}],
                    [{"match": ["bad"], "handle": [proxy("1.2.3.4:5")]}]):
            with self.subTest(bad=bad):
                walk(bad)  # must not raise


if __name__ == "__main__":
    unittest.main()
