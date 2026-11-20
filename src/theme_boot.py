"""The one inline script the app serves, and the CSP hash that allows it.

It runs in <head> before the stylesheets apply, so the stored theme (or the OS
preference) is on <html data-theme> before first paint, with no flash of the
wrong theme. CSP allows it by hash, computed here from the exact string the
templates render, so the two cannot drift. theme.js owns everything after first
paint and must agree on the storage key and its values (dark, light, or absent
for "follow the system").
"""
import base64
import hashlib

THEME_STORAGE_KEY = "ui.theme"

THEME_BOOT_JS = (
    "(function(){var t;try{t=localStorage.getItem('ui.theme')}catch(e){}"
    "if(t!=='dark'&&t!=='light'){t=window.matchMedia&&"
    "window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'}"
    "document.documentElement.setAttribute('data-theme',t)})();"
)

THEME_BOOT_HASH = "sha256-" + base64.b64encode(
    hashlib.sha256(THEME_BOOT_JS.encode("utf-8")).digest()
).decode("ascii")
