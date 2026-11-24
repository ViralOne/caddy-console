"""Load the integration Caddyfile with 203.0.113.7 banned; used by dev/bans-it.sh.

  python -m tests.integration.bans_recovery_prep [ADMIN_ADDRESS]

With ADMIN_ADDRESS (e.g. 172.20.0.3:2019) the loaded Caddyfile binds the admin
API to that fixed address instead of 0.0.0.0:2019, so host recovery can be
checked against a non-wildcard listener. The caller must restore the wildcard.
"""
import tests.integration._env as itenv  # noqa: I001  (must precede src imports)

import sys

from src.bans import caddy as caddy_admin, service
from tests.integration.bans_caddy_it import BANNED, CADDYFILE, reset_itest, write_caddyfile

reset_itest()
if len(sys.argv) > 1:
    # A fixed bind enforces Host and Origin, so list both names, as the tunnel stack does.
    admin = f"admin {sys.argv[1]} {{\n\t\torigins caddy-target:2019 {sys.argv[1]}\n\t}}"
    fixed = CADDYFILE.replace("admin 0.0.0.0:2019", admin, 1)
    write_caddyfile(fixed)
    assert caddy_admin.load(fixed).status == "applied"
body, status = service.add_ban({"value": BANNED, "duration": "permanent"}, "it@example.com", None)
assert status == 201 and body["enforcement"] == "enforced", body
print(f"prepared: {BANNED} banned, admin {sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0:2019'}"
      f" (Caddyfile {itenv.ROOT}/Caddyfile)")
