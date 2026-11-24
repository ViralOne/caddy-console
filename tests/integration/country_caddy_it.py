"""Client-IP profiles and country policy against stock caddy:2.11.9 (spec Phase 4 gate).

  docker compose -f docker-compose.dev.yaml exec -T caddy-console \
    /app/.venv/bin/python -m unittest tests.integration.country_caddy_it -v

Synthetic fixtures only: documentation address ranges and a four-row country
dataset. The test client is the only real peer Caddy sees, and it is a private
Docker address; "trusted Cloudflare peer" scenarios make that address the
configured peer, and spoofing scenarios render the policy with a synthetic
protected set so the client counts as a public peer.

Two listeners on caddy-target: :80 follows the client-IP profile file, :8080
is a harness listener that trusts X-Forwarded-For from private peers so direct
mode can be exercised with public documentation addresses as client_ip.
"""
import tests.integration._env as itenv  # noqa: I001  (must precede src imports)

import os

os.environ["COUNTRY_POLICY_ENABLED"] = "true"
os.environ["CLIENT_IP_MODE"] = "direct"

import json
import re
import shutil
import socket
import unittest
from unittest import mock

import requests

from src import config, create_app
from src.bans import caddy as caddy_admin, country, countrydata, fsio, profile, protected, service

D = itenv.BANS_DIR
HOST = "echo.it.example.com"
SITE = f"import {D}/geo*.caddy\n\trespond \"{{client_ip}}\" 200"
CADDYFILE = f"""{{
\tadmin 0.0.0.0:2019
\tservers :80 {{
\t\timport {D}/cloudflare-trusted-proxies*.caddy
\t\tclient_ip_headers CF-Connecting-IP
\t}}
\tservers :8080 {{
\t\ttrusted_proxies static private_ranges
\t\tclient_ip_headers X-Forwarded-For
\t}}
}}

http://{HOST} {{
\t{SITE}
}}

http://{HOST}:8080 {{
\t{SITE}
}}
"""
# Documentation ranges only. DE is allowed in every policy; US is never allowed.
DE4, DE6 = "198.51.100.0/24", "2001:db8:de::/48"
US4, US6 = "203.0.113.0/24", "2001:db8:5::/48"
DE_IP, DE_IP6 = "198.51.100.9", "2001:db8:de::9"
US_IP, US_IP6 = "203.0.113.9", "2001:db8:5::9"
LAN_IP = "192.168.1.5"
DATASET = [(DE4, "DE"), (DE6, "DE"), (US4, "US"), (US6, "US")]
GEO = os.path.join(D, "geo.caddy")
PROFILE_FILE = os.path.join(D, "cloudflare-trusted-proxies.caddy")


def own_ip():
    """The address Caddy sees this client from."""
    with socket.create_connection((itenv.DATA_URL.split("//")[1].split(":")[0], 80), timeout=5) as s:
        return s.getsockname()[0]


def get(headers=None, port=80):
    host = itenv.DATA_URL.split("//")[1].split(":")[0]
    r = requests.get(f"http://{host}:{port}/", headers={"Host": HOST, **(headers or {})},
                     allow_redirects=False, timeout=5)
    return r.status_code, r.text


def text(path):
    with open(path, encoding="ascii") as f:
        return f.read()


def put_dataset():
    os.makedirs(config.GEOIP_DIR, exist_ok=True)
    with open(countrydata.path(), "wb") as f:
        f.write(countrydata.dumps(DATASET, "2099-01"))


def wipe():
    for root in (itenv.BACKUP_DIR, D):
        shutil.rmtree(root, ignore_errors=True)
        os.makedirs(root)
    with open(f"{itenv.ROOT}/Caddyfile", "w", encoding="utf-8") as f:
        f.write(CADDYFILE)
    service.reset_caches()
    put_dataset()


def reload():
    r = caddy_admin.load(CADDYFILE)
    assert r.status == "applied", r.message


def live_hash():
    return caddy_admin.config_hash(caddy_admin.live_config())


def snapshot():
    names = (GEO, PROFILE_FILE, country.PATH, profile.PATH)
    return {os.path.basename(p): fsio.read_bytes(p) for p in names} | {"live": live_hash()}


def trusted_ranges(adapted):
    out = []
    for server in adapted["apps"]["http"]["servers"].values():
        if ":80" not in server["listen"]:        # the profile-driven listener, not the harness
            continue
        out += (server.get("trusted_proxies") or {}).get("ranges") or []
    return out


class CountryIT(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open("/etc/caddy/Caddyfile", encoding="utf-8") as f:
            cls.dev_caddyfile = f.read()
        cls.app = create_app()
        cls.app.testing = True
        cls.me = own_ip()

    @classmethod
    def tearDownClass(cls):
        caddy_admin.load(cls.dev_caddyfile)

    def setUp(self):
        wipe()
        reload()

    # -- helpers -----------------------------------------------------------
    def ok(self, result):
        body, status = result
        self.assertEqual(status, 200, body)
        return body

    def set_profile(self, mode, peers=None, tunnel_only=False):
        return self.ok(service.set_client_ip_profile(
            {"mode": mode, "tunnel_peers": peers or [], "tunnel_only": tunnel_only}, "it@example.com"))

    def set_country(self, codes, enabled=True):
        return service.set_country_policy({"enabled": enabled, "countries": codes}, "it@example.com")

    def synthetic(self, mode, peers, exclusion, codes=("DE",)):
        """Write the profile and country files for `mode` with explicit trusted
        peers and protected set, bypassing the console's own validation."""
        prof = profile.Profile(mode=mode, tunnel_peers=[], ranges={"v4": peers, "v6": ["2001:db8:ffff::/48"]})
        if mode == "cloudflare-tunnel":
            prof.tunnel_peers = peers
        policy = country.Policy(enabled=True, countries=sorted(codes))
        data, _ = country.render(policy, mode, prof.peers(), exclusion)
        fsio.atomic_write(PROFILE_FILE, profile.render(prof), 0o644)
        fsio.atomic_write(GEO, data, 0o644)
        reload()

    def edge(self, ip, country_code=None, port=80):
        headers = {"CF-Connecting-IP": ip}
        if country_code:
            headers["CF-IPCountry"] = country_code
        return get(headers, port)

    def assert_cloudflare_policy(self):
        """What a trusted Cloudflare peer can and cannot do, IPv4 and IPv6."""
        self.assertEqual(self.edge(US_IP, "DE"), (200, US_IP))
        self.assertEqual(self.edge(US_IP6, "DE"), (200, US_IP6))
        self.assertEqual(self.edge(DE_IP, "US")[0], 403)
        self.assertEqual(self.edge(DE_IP6, "US")[0], 403)
        self.assertEqual(self.edge(US_IP)[0], 403, "a missing CF-IPCountry must deny public traffic")
        self.assertEqual(self.edge(US_IP6)[0], 403)
        self.assertEqual(self.edge(US_IP, "XX")[0], 403, "XX is allowed only when named")
        self.assertEqual(self.edge(US_IP, "T1")[0], 403, "T1 is allowed only when named")
        self.assertEqual(self.edge(US_IP, "")[0], 403)
        self.assertEqual(self.edge(LAN_IP), (200, LAN_IP), "a LAN client bypasses country blocking")
        self.assertEqual(self.edge("fd00:db8::5"), (200, "fd00:db8::5"))
        self.assertEqual(self.edge("127.0.0.1")[0], 200)

    # -- every generated profile file imports and adapts ----------------------
    def test_every_profile_variant_imports_and_adapts(self):
        variants = {
            "direct": ("direct", [], False),
            "proxied": ("cloudflare-proxied", [], False),
            "tunnel host": ("cloudflare-tunnel", ["172.30.0.2"], False),
            "tunnel subnet": ("cloudflare-tunnel", ["172.30.0.0/28"], False),
            "tunnel ipv6": ("cloudflare-tunnel", ["fd00:db8::2"], False),
            "tunnel ipv6 subnet": ("cloudflare-tunnel", ["fd00:db8::/64"], False),
            "tunnel private_ranges": ("cloudflare-tunnel", ["private_ranges"], True),
        }
        for name, (mode, peers, only) in variants.items():
            with self.subTest(name):
                prof = profile.from_payload({"mode": mode, "tunnel_peers": peers, "tunnel_only": only},
                                            profile.default())
                self.assert_adapts(profile.render(prof), bool(prof.peers()))
        # A tunnel profile that has no address yet trusts nothing and still adapts.
        self.assert_adapts(profile.render(profile.Profile(mode="cloudflare-tunnel")), False)
        for refused in (["private_ranges"], ["10.0.0.0/8"], ["203.0.113.4"], []):
            body, status = service.set_client_ip_profile(
                {"mode": "cloudflare-tunnel", "tunnel_peers": refused}, "it@example.com")
            self.assertEqual(status, 400, (refused, body))

    def assert_adapts(self, data, trusts):
        fsio.atomic_write(PROFILE_FILE, data, 0o644)
        adapted = caddy_admin.adapt(CADDYFILE)
        self.assertTrue(adapted.ok, adapted.message)
        self.assertEqual(bool(trusted_ranges(adapted.config)), trusts)

    # -- direct --------------------------------------------------------------
    def test_direct_ignores_forged_cloudflare_headers(self):
        self.ok(self.set_country(["DE"]))
        self.assertFalse(os.path.exists(PROFILE_FILE), "direct mode renders no trusted proxies by default")
        marker = detect_marker()
        self.assertIn("direct", marker)
        forged = {"CF-Connecting-IP": DE_IP, "CF-IPCountry": "DE"}
        # :80 follows the profile: nothing is trusted, so client_ip is the TCP peer.
        self.assertEqual(get(forged), (200, self.me))
        # Harness listener: public documentation clients decided by range, never by the header.
        self.assertEqual(get({"X-Forwarded-For": DE_IP}, 8080), (200, DE_IP))
        self.assertEqual(get({"X-Forwarded-For": DE_IP6}, 8080), (200, DE_IP6))
        self.assertEqual(get({"X-Forwarded-For": US_IP, **forged}, 8080)[0], 403)
        self.assertEqual(get({"X-Forwarded-For": US_IP6, **forged}, 8080)[0], 403)
        self.assertEqual(get({"X-Forwarded-For": "192.0.2.77", "CF-IPCountry": "DE"}, 8080)[0], 403)
        self.assertEqual(get({"X-Forwarded-For": LAN_IP}, 8080), (200, LAN_IP))
        self.assertEqual(get({"X-Forwarded-For": "fd00:db8::5"}, 8080)[0], 200)
        geo = text(GEO)
        self.assertNotIn("CF-IPCountry", geo)
        self.assertIn(DE4, geo)
        self.assertIn(DE6, geo)
        self.assertNotIn(US4, geo)

    # -- Cloudflare proxied --------------------------------------------------
    def test_proxied_trusts_headers_only_from_cloudflare_peers(self):
        self.set_profile("cloudflare-proxied")
        self.ok(self.set_country(["DE"]))
        self.assertIn("cloudflare", detect_marker())
        # The real edge ranges do not include this peer: forged headers change nothing.
        self.assertEqual(self.edge(US_IP, "DE"), (200, self.me))
        # Synthetic edge that includes this peer (real protected set).
        real = protected.build(docker=protected.read_docker_networks()).exclusion_tokens()
        self.synthetic("cloudflare-proxied", [f"{self.me}/32"], real)
        self.assert_cloudflare_policy()
        # Synthetic edge that does not include this peer, with this peer counted as public:
        # forged client IP and country headers are ignored and the request is denied.
        self.synthetic("cloudflare-proxied", ["192.0.2.1/32"], ["127.0.0.0/8"])
        for code in ("DE", None):
            self.assertEqual(self.edge(LAN_IP, code)[0], 403)
            self.assertEqual(self.edge(DE_IP, code)[0], 403)
        self.assertEqual(self.edge(US_IP6, "DE")[0], 403)
        self.assertEqual(get({"CF-IPCountry": "DE"})[0], 403)

    def test_proxied_named_special_codes(self):
        real = protected.build(docker=protected.read_docker_networks()).exclusion_tokens()
        self.synthetic("cloudflare-proxied", [f"{self.me}/32"], real, codes=("DE", "XX", "T1"))
        self.assertEqual(self.edge(US_IP, "XX")[0], 200)
        self.assertEqual(self.edge(US_IP, "T1")[0], 200)
        self.assertEqual(self.edge(US_IP, "DE")[0], 200)
        self.assertEqual(self.edge(US_IP, "US")[0], 403)
        self.assertEqual(self.edge(US_IP)[0], 403)

    # -- Cloudflare Tunnel ---------------------------------------------------
    def test_tunnel_trusts_headers_only_from_the_fixed_cloudflared_peer(self):
        self.set_profile("cloudflare-tunnel", [self.me])
        self.ok(self.set_country(["DE"]))
        self.assertIn("cloudflare", detect_marker())
        self.assertEqual(text(PROFILE_FILE).count("trusted_proxies static "), 1)
        self.assert_cloudflare_policy()
        # The fixed peer moves elsewhere: this client is no longer trusted.
        self.set_profile("cloudflare-tunnel", ["172.30.99.250"])
        self.assertEqual(self.edge(US_IP, "DE"), (200, self.me))
        # Synthetic: same untrusted peer counted as public, spoofed headers fail.
        self.synthetic("cloudflare-tunnel", ["172.30.99.250/32"], ["127.0.0.0/8"])
        self.assertEqual(self.edge(LAN_IP, "DE")[0], 403)
        self.assertEqual(self.edge(DE_IP, "DE")[0], 403)
        self.assertEqual(get({"CF-IPCountry": "DE"})[0], 403)
        # And trusted again once the peer is this client.
        self.synthetic("cloudflare-tunnel", [f"{self.me}/32"], ["127.0.0.0/8"])
        self.assertEqual(self.edge(US_IP, "DE"), (200, US_IP))
        self.assertEqual(self.edge(US_IP, "US")[0], 403)

    def test_switching_profiles_regenerates_the_country_shape(self):
        self.ok(self.set_country(["DE"]))
        self.assertIn(DE4, text(GEO))
        self.set_profile("cloudflare-tunnel", [self.me])
        geo = text(GEO)
        self.assertIn("CF-IPCountry ^(?:DE)$", geo)
        self.assertNotIn(DE4, geo)
        self.set_profile("direct")
        self.assertIn(DE4, text(GEO))
        self.assertEqual(get({"X-Forwarded-For": US_IP}, 8080)[0], 403)
        self.assertEqual(get({"X-Forwarded-For": DE_IP}, 8080)[0], 200)

    # -- the prefix cap ------------------------------------------------------
    def test_policy_above_the_cap_changes_nothing(self):
        self.ok(self.set_country(["DE"]))
        self.assertEqual(get({"X-Forwarded-For": US_IP}, 8080)[0], 403)
        before = snapshot()
        with mock.patch.object(config, "COUNTRY_MAX_PREFIXES", 3):
            body, status = self.set_country(["DE", "US"])
        self.assertEqual(status, 409, body)
        self.assertEqual(body["code"], "country_prefix_cap_exceeded")
        self.assertEqual(snapshot(), before, "live config, geo.caddy and the policy state must not change")
        self.assertEqual(get({"X-Forwarded-For": US_IP}, 8080)[0], 403)
        self.assertEqual(get({"X-Forwarded-For": DE_IP}, 8080)[0], 200)
        with mock.patch.object(config, "COUNTRY_MAX_PREFIXES", 4):
            self.ok(self.set_country(["DE", "US"]))
        self.assertEqual(get({"X-Forwarded-For": US_IP6}, 8080)[0], 200)

    # -- the origin guard ----------------------------------------------------
    def guard_code(self, lan):
        with open(os.path.join(os.path.dirname(config.__file__), "snippets.json"), encoding="utf-8") as f:
            code = next(x["code"] for x in json.load(f) if x.get("id") == "cloudflare-origin-guard")
        return code.replace("192.168.1.0/24", lan)

    def test_origin_guard_covers_sites_built_on_handle(self):
        """A bare `respond` would run after `handle`; the matcher-specific handle runs first."""
        def site(lan):
            guard = "".join("\t" + l + "\n" for l in self.guard_code(lan).splitlines())
            return (f"http://{HOST} {{\n{guard}\thandle /api/* {{\n\t\trespond \"api\" 200\n\t}}\n"
                    "\thandle {\n\t\trespond \"app\" 200\n\t}\n}\n")
        base = "{\n\tadmin 0.0.0.0:2019\n}\n\n"
        try:
            for lan, want in (("192.0.2.0/24", 403), (f"{self.me}/32", 200)):
                r = caddy_admin.load(base + site(lan))
                self.assertEqual(r.status, "applied", r.message)
                self.assertEqual(get()[0], want, lan)
                self.assertEqual(requests.get(f"http://{itenv.DATA_URL.split('//')[1].split(':')[0]}/api/x",
                                              headers={"Host": HOST}, timeout=5).status_code, want, lan)
        finally:
            reload()


def detect_marker():
    """The shape marker in the live config: direct or cloudflare."""
    text = json.dumps(caddy_admin.live_config())
    found = re.findall(r"caddy_console_country_policy\W+(\w+)", text)
    assert found, "no country marker in the live config"
    return found[0]


if __name__ == "__main__":
    unittest.main()
