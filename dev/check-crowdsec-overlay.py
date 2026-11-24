"""Check the CrowdSec overlay's isolation rules on `docker compose config --format json` (stdin).

  docker compose -f BASE -f OVERLAY config --format json | python3 dev/check-crowdsec-overlay.py CADDY CONSOLE [--plugin]

--plugin (the plugin overlay is on top) allows Caddy on crowdsec-lapi.
"""
import json
import re
import sys

IMAGE = re.compile(r"^crowdsecurity/crowdsec:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$")
ENV = {"COLLECTIONS": "crowdsecurity/caddy", "PARSERS": "crowdsecurity/whitelists", "DISABLE_ONLINE_API": "true"}
MOUNTS = ("/etc/crowdsec/acquis.d/caddy.yaml", "/etc/crowdsec/parsers/s02-enrich/caddy-console-safe-fields.yaml",
          "/var/log/caddy")


def nets(service):
    return set(service.get("networks") or {})


def main(caddy, console, plugin=False):
    cfg = json.load(sys.stdin)
    services, problems = cfg["services"], []
    cs = services.get("crowdsec")
    if cs is None:
        sys.exit("no crowdsec service")
    if not IMAGE.match(cs.get("image", "")):
        problems.append(f"crowdsec image is not pinned by version and digest: {cs.get('image')}")
    if cs.get("ports"):
        problems.append("crowdsec publishes ports")
    if nets(cs) != {"crowdsec-lapi", "crowdsec-egress"}:
        problems.append(f"crowdsec networks are {sorted(nets(cs))}")
    if not (cfg.get("networks", {}).get("crowdsec-lapi") or {}).get("internal"):
        problems.append("crowdsec-lapi is not internal")
    for name, svc in services.items():
        if name not in ("crowdsec", console) + ((caddy,) if plugin else ()) and "crowdsec-lapi" in nets(svc):
            problems.append(f"{name} joins crowdsec-lapi")
    if not plugin and "crowdsec-lapi" in nets(services[caddy]):
        problems.append("Caddy joins crowdsec-lapi")
    if "crowdsec-lapi" not in nets(services[console]):
        problems.append("the console does not join crowdsec-lapi")
    env = cs.get("environment") or {}
    problems += [f"crowdsec {k} must be {v!r}" for k, v in ENV.items() if env.get(k) != v]
    cenv = services[console].get("environment") or {}
    if cenv.get("CROWDSEC_URL") != "http://crowdsec:8080":
        problems.append("the console has no CROWDSEC_URL=http://crowdsec:8080")
    if not env.get("BOUNCER_KEY_caddy_console") or env.get("BOUNCER_KEY_caddy_console") != cenv.get("CROWDSEC_CONSOLE_BOUNCER_KEY"):
        problems.append("BOUNCER_KEY_caddy_console and the console's CROWDSEC_CONSOLE_BOUNCER_KEY differ or are empty")
    mounts = {v.get("target"): v for v in cs.get("volumes") or []}
    # A Compose config (inline `content:` or file) is always mounted read-only.
    cfgs = {c.get("target") for c in cs.get("configs") or [] if isinstance(c, dict)}
    problems += [f"{t} is not mounted read-only" for t in MOUNTS
                 if t not in cfgs and not (mounts.get(t) or {}).get("read_only")]
    if problems:
        sys.exit("\n".join(problems))


main(sys.argv[1], sys.argv[2], "--plugin" in sys.argv[3:])
