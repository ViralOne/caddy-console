"""Assert a plugin image carries exactly the expected third-party modules.

  docker run --rm IMAGE caddy list-modules --json --skip-standard | python3 dev/check-plugin-modules.py crowdsec
"""
import json
import re
import sys

BOUNCER = "github.com/hslatman/caddy-crowdsec-bouncer"
CLOUDFLARE = "github.com/caddy-dns/cloudflare"
# The bouncer's http package also registers caddy-l4 modules (pulled in by the
# bouncer, version pinned by go.sum); nothing configures a layer4 app, but the
# set is asserted so a new module never slips in unnoticed.
LAYER4 = "github.com/mholt/caddy-l4"
EXPECTED = {
    "crowdsec": {"admin.api.crowdsec": BOUNCER, "crowdsec": BOUNCER,
                 "http.handlers.appsec": BOUNCER, "http.handlers.crowdsec": BOUNCER,
                 "caddy.listeners.layer4": LAYER4, "layer4": LAYER4, "layer4.matchers.local_ip": LAYER4,
                 "layer4.matchers.not": LAYER4, "layer4.matchers.remote_ip": LAYER4},
}
EXPECTED["crowdsec-cloudflare"] = {**EXPECTED["crowdsec"], "dns.providers.cloudflare": CLOUDFLARE}


def required_versions(variant):
    """Versions from the committed go.mod, so this check and the build agree."""
    with open(f"caddy-plugin/{variant}/go.mod", encoding="utf-8") as f:
        text = f.read()
    return {m: v for m, v in re.findall(r"^\s*(github\.com/\S+)\s+(v\S+)", text, re.M)}


def main(variant):
    if variant not in EXPECTED:
        sys.exit(f"unknown variant {variant!r}")
    mods = json.load(sys.stdin)
    found = {m["module_name"]: m for m in mods if m.get("module_type") in ("non-standard", "unknown")}
    problems = []
    if set(found) != set(EXPECTED[variant]):
        problems.append(f"non-standard modules are {sorted(found)}, expected {sorted(EXPECTED[variant])}")
    versions = required_versions(variant)
    for name, module in EXPECTED[variant].items():
        m = found.get(name) or {}
        if not str(m.get("package_url", "")).startswith(module):
            problems.append(f"{name} comes from {m.get('package_url')!r}, expected {module}")
        elif m.get("version") != versions.get(module):
            problems.append(f"{name} is {m.get('version')!r}, go.mod pins {versions.get(module)!r}")
    if problems:
        sys.exit("\n".join(problems))
    print(f"{variant}: modules ok ({', '.join(sorted(found))})")


main(*sys.argv[1:2])
