"""Ban targets: canonical form, scope, width and the protected set.

Run with:  uv run --frozen python -m unittest tests.test_bans_addr -v
"""
import ipaddress
import unittest

import tests._env  # noqa: F401

from src.bans import addr, protected

net = ipaddress.ip_network


class CanonicalTest(unittest.TestCase):
    def test_ipv4_and_ipv6_are_canonical(self):
        self.assertEqual(addr.token(addr.canonical(" 203.0.113.7 ")), "203.0.113.7")
        self.assertEqual(addr.token(addr.canonical("2001:DB8:0:0::1")), "2001:db8::1")
        self.assertEqual(addr.token(addr.canonical("203.0.113.7/24")), "203.0.113.0/24")
        self.assertEqual(addr.token(addr.canonical("203.0.113.7/32")), "203.0.113.7")
        self.assertEqual(addr.token(addr.canonical("2001:db8::/48")), "2001:db8::/48")

    def test_ipv4_mapped_ipv6_becomes_ipv4(self):
        self.assertEqual(addr.token(addr.canonical("::ffff:203.0.113.7")), "203.0.113.7")
        self.assertEqual(addr.token(addr.canonical("::ffff:198.51.100.0/120")), "198.51.100.0/24")

    def test_scope_is_derived_from_the_parsed_value(self):
        self.assertEqual(addr.scope_of(addr.canonical("203.0.113.7")), "ip")
        self.assertEqual(addr.scope_of(addr.canonical("203.0.113.0/24")), "range")
        self.assertEqual(addr.scope_of(addr.canonical("2001:db8::1/128")), "ip")

    def test_invalid_input_gets_stable_codes(self):
        for raw in ("", "abc", "1.2.3", "203.0.113.7 198.51.100.1", "fe80::1%eth0", None, 7, "1" * 100, "010.1.1.1"):
            with self.subTest(raw=raw), self.assertRaises(addr.AddressError) as cm:
                addr.canonical(raw)
            self.assertEqual(cm.exception.code, "invalid_ip")
        for raw in ("203.0.113.0/33", "x/24", "2001:db8::/129", "203.0.113.0/"):
            with self.subTest(raw=raw), self.assertRaises(addr.AddressError) as cm:
                addr.canonical(raw)
            self.assertEqual(cm.exception.code, "invalid_range")

    def test_width_limits(self):
        addr.check_width(addr.canonical("203.0.0.0/16"))
        addr.check_width(addr.canonical("2001:db8::/48"))
        for raw in ("203.0.0.0/15", "2001:db8::/47"):
            with self.subTest(raw=raw), self.assertRaises(addr.AddressError) as cm:
                addr.check_width(addr.canonical(raw))
            self.assertEqual(cm.exception.code, "range_too_wide")

    def test_client_address(self):
        self.assertEqual(str(addr.client_address("203.0.113.7")), "203.0.113.7")
        self.assertEqual(str(addr.client_address("::ffff:203.0.113.7")), "203.0.113.7")
        for raw in (None, "", "junk", "203.0.113.0/24"):
            self.assertIsNone(addr.client_address(raw))


class ProtectedTest(unittest.TestCase):
    def setUp(self):
        self.p = protected.build(never=protected.parse_never("198.51.100.9, 2001:db8:1::/64"))

    def test_every_core_class_is_protected(self):
        cases = {
            "127.0.0.1": "loopback", "::1": "loopback",
            "10.1.2.3": "private", "172.16.5.5": "private", "192.168.1.1": "private",
            "169.254.1.1": "link_local", "fe80::1": "link_local",
            "100.64.1.1": "cgnat", "fd12::1": "ula",
            "0.0.0.0": "special", "224.0.0.1": "special", "240.0.0.1": "special",
            "ff02::1": "special", "::": "special",
        }
        for raw, category in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(self.p.overlap(addr.canonical(raw)), category)

    def test_documentation_ranges_are_bannable(self):
        for raw in ("203.0.113.7", "192.0.2.1", "2001:db8::1", "198.18.0.1"):
            with self.subTest(raw=raw):
                self.assertIsNone(self.p.overlap(addr.canonical(raw)))

    def test_overlap_is_checked_in_both_directions(self):
        self.assertEqual(self.p.overlap(addr.canonical("198.51.100.9")), "never")      # inside
        self.assertEqual(self.p.overlap(addr.canonical("198.51.100.0/24")), "never")   # contains
        self.assertEqual(self.p.overlap(addr.canonical("2001:db8:1::/48")), "never")
        self.assertEqual(self.p.overlap(addr.canonical("2001:db8:1::5")), "never")
        self.assertIsNone(self.p.overlap(addr.canonical("198.51.101.0/24")))
        self.assertTrue(protected.overlaps(net("10.0.0.0/8"), net("10.1.0.0/16")))
        self.assertTrue(protected.overlaps(net("10.1.0.0/16"), net("10.0.0.0/8")))

    def test_families_never_overlap(self):
        # ::a00:1 has the same integer value as 10.0.0.1; it must not read as private.
        self.assertIsNone(self.p.overlap(addr.canonical("::a00:1")))

    def test_verified_console_addresses(self):
        p = protected.build(management=[net("198.51.100.20/32")])
        self.assertEqual(p.overlap(addr.canonical("198.51.100.0/24")), "operator")

    def test_parse_never_rejects_invalid_tokens(self):
        self.assertEqual(protected.parse_never(""), ())
        self.assertEqual(protected.parse_never(" 203.0.113.7,198.51.100.0/24  2001:db8::1 "),
                         (net("203.0.113.7/32"), net("198.51.100.0/24"), net("2001:db8::1/128")))
        with self.assertRaises(protected.ConfigError):
            protected.parse_never("203.0.113.7, nope")

    def test_exclusion_tokens_add_only_uncovered_extras(self):
        p = protected.build(never=protected.parse_never("198.51.100.9 10.1.1.1"),
                            management=[net("198.51.100.20/32")],
                            docker=[net("172.18.0.0/16")])
        tokens = p.exclusion_tokens()
        self.assertEqual(tokens[:5], ["private_ranges", "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"])
        self.assertEqual(tokens[5:], ["198.51.100.9", "198.51.100.20"])

    def test_docker_networks_from_proc_route(self):
        text = ("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                "eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
                "eth0\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n")
        self.assertEqual(protected.docker_networks(text), [net("172.18.0.0/16")])
        self.assertEqual(protected.docker_networks("garbage"), [])

    def test_summary_groups_by_category_with_labels(self):
        summary = {s["category"]: s for s in self.p.summary()}
        self.assertEqual(summary["never"]["values"], ["198.51.100.9", "2001:db8:1::/64"])
        self.assertEqual(summary["loopback"]["label"], "Loopback")


if __name__ == "__main__":
    unittest.main()
