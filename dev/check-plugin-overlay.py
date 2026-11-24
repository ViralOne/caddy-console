"""Check the CrowdSec plugin overlay on `docker compose config --format json` (stdin).

  docker compose -f BASE -f CROWDSEC -f PLUGIN config --format json | python3 dev/check-plugin-overlay.py CADDY CONSOLE VARIANT

VARIANT is crowdsec or crowdsec-cloudflare (the image the stack must use).
"""
import ipaddress
import json
import re
import sys

ADMIN_IP, ADMIN_ADDR, SUBNET = "172.30.250.2", "172.30.250.2:2019", "172.30.250.0/29"
IMAGE = r"^ghcr\.io/viralone/caddy-{variant}(?::[\w.-]+)?(?:@sha256:[0-9a-f]{{64}}|:sha-[0-9a-f]{{7,40}})$"


def nets(service):
    return set(service.get("networks") or {})


def exposed(service):
    """True when the service publishes the admin port (either side) or a container port 8080 (LAPI).

    A host port 8080 mapped to another container port is fine: the internal stack
    publishes 8080:80 for Caddy's data plane.
    """
    for p in service.get("ports") or []:
        if "2019" in (str(p.get("target")), str(p.get("published"))) or str(p.get("target")) == "8080":
            return True
    return False


def main(caddy, console, variant):
    cfg = json.load(sys.stdin)
    services, networks, problems = cfg["services"], cfg.get("networks") or {}, []
    cd, co, cs = services[caddy], services[console], services.get("crowdsec") or {}
    if not re.match(IMAGE.format(variant=re.escape(variant)), cd.get("image", "")):
        problems.append(f"Caddy image must be ghcr.io/viralone/caddy-{variant} by digest or sha- tag: {cd.get('image')}")
    if not {"caddy-admin", "crowdsec-lapi"} <= nets(cd):
        problems.append(f"Caddy networks are {sorted(nets(cd))}; it needs caddy-admin and crowdsec-lapi")
    if ((cd.get("networks") or {}).get("caddy-admin") or {}).get("ipv4_address") != ADMIN_IP:
        problems.append(f"Caddy has no fixed ipv4_address {ADMIN_IP} on caddy-admin")
    admin = networks.get("caddy-admin") or {}
    if not admin.get("internal"):
        problems.append("caddy-admin is not internal")
    subnets = [c.get("subnet") for c in ((admin.get("ipam") or {}).get("config") or [])]
    if subnets != [SUBNET]:
        problems.append(f"caddy-admin subnet is {subnets}, expected [{SUBNET}]")
    ranges = [c.get("ip_range") for c in ((admin.get("ipam") or {}).get("config") or [])]
    if not ranges or not all(r and ipaddress.ip_address(ADMIN_IP) not in ipaddress.ip_network(r, strict=False)
                             for r in ranges):
        problems.append(f"caddy-admin needs an ip_range that excludes {ADMIN_IP}, so a dynamic lease cannot take it")
    env, cenv, senv = cd.get("environment") or {}, co.get("environment") or {}, cs.get("environment") or {}
    for k, v in (("CADDY_ADMIN_ADDRESS", ADMIN_ADDR), ("CADDY_ADMIN_SUBNET", SUBNET)):
        if env.get(k) != v:
            problems.append(f"Caddy {k} must be {v}")
    if not env.get("CROWDSEC_PLUGIN_BOUNCER_KEY") and not env.get("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE"):
        problems.append("Caddy has neither CROWDSEC_PLUGIN_BOUNCER_KEY nor CROWDSEC_PLUGIN_BOUNCER_KEY_FILE")
    if f"http://{ADMIN_ADDR}/" not in " ".join(map(str, (cd.get("healthcheck") or {}).get("test") or [])):
        problems.append("the Caddy health check does not use the fixed admin address")
    if cenv.get("CADDY_API_URL") != f"http://{ADMIN_ADDR}" or cenv.get("CADDY_ADMIN_ADDRESS") != ADMIN_ADDR:
        problems.append("the console must use CADDY_API_URL and CADDY_ADMIN_ADDRESS at the fixed admin address")
    if "CROWDSEC_PLUGIN_BOUNCER_KEY" in cenv:
        problems.append("the console must not receive the plugin's bouncer key")
    plug, cons = senv.get("BOUNCER_KEY_caddy_plugin"), senv.get("BOUNCER_KEY_caddy_console")
    if env.get("CROWDSEC_PLUGIN_BOUNCER_KEY") and plug != env.get("CROWDSEC_PLUGIN_BOUNCER_KEY"):
        problems.append("crowdsec BOUNCER_KEY_caddy_plugin and Caddy's CROWDSEC_PLUGIN_BOUNCER_KEY differ")
    if plug and plug == cons:
        problems.append("the plugin and the console share one bouncer key; they must differ")
    for name, svc in services.items():
        if name not in (caddy, console) and "caddy-admin" in nets(svc):
            problems.append(f"{name} joins caddy-admin")
        if name not in (caddy, console, "crowdsec") and "crowdsec-lapi" in nets(svc):
            problems.append(f"{name} joins crowdsec-lapi")
        if exposed(svc):
            problems.append(f"{name} publishes port 2019 or container port 8080")
    if cs.get("ports"):
        problems.append("crowdsec publishes ports")
    # A peer that shares a network with Caddy must not forge frames or routes to
    # the admin address (weak host model): no NET_RAW, no NET_ADMIN.
    for name, svc in services.items():
        if name == "crowdsec" or name.startswith("cloudflared"):
            if "ALL" not in (svc.get("cap_drop") or []) or set(svc.get("cap_add") or []) & {"NET_RAW", "NET_ADMIN", "ALL"}:
                problems.append(f"{name} must drop all capabilities (cap_drop: [ALL], no NET_RAW or NET_ADMIN)")
    if problems:
        sys.exit("\n".join(problems))


main(*sys.argv[1:4])
