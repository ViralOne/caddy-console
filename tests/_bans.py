"""Shared fixtures for the IP-ban tests (not a test module: never discovered).

reset() returns every ban-related file to a clean slate; FakeCaddy (Task 6)
stands in for the admin API.
"""
import os
import shutil

import tests._env as env

MANUAL_SITE = "example.com {{\n\timport {bans_dir}/bans-manual*.caddy\n\trespond 200\n}}\n"


def write_caddyfile(text):
    with open(env.CADDYFILE, "w", encoding="utf-8") as f:
        f.write(text)


def reset(caddyfile=None):
    for name in os.listdir(env.BACKUP_DIR):
        if name.startswith("bans") or name.startswith(".bans"):
            path = os.path.join(env.BACKUP_DIR, name)
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.remove(path)
    shutil.rmtree(os.path.join(env.BACKUP_DIR, ".policy-transactions"), ignore_errors=True)
    shutil.rmtree(env.BANS_DIR, ignore_errors=True)
    os.makedirs(env.BANS_DIR)
    write_caddyfile(caddyfile if caddyfile is not None else MANUAL_SITE.format(bans_dir=env.BANS_DIR))
