#!/usr/bin/env bash
# Adapt representative plugin layouts with the plugin image and print the JSON
# (only `caddy adapt`; nothing runs):
#   ./dev/build-plugin-image.sh crowdsec
#   tests/integration/make_plugin_fixtures.sh caddy-crowdsec:local > tests/fixtures/bans/adapted-plugin-layouts.json
set -euo pipefail
cd "$(dirname "$0")/../.."
IMAGE="${1:?usage: make_plugin_fixtures.sh IMAGE}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
H='# Managed by Caddy Console. Do not edit; changes are overwritten.'
route() {   # $1: dir, $2: exclusion tokens
  mkdir -p "$tmp/fx/$1"
  printf '%s\n(protect_crowdsec) {\n\tvars caddy_console_plugin_protect 1\n\t@caddy_console_crowdsec_candidate {\n\t\tnot client_ip %s\n\t}\n\tcrowdsec @caddy_console_crowdsec_candidate\n}\n' "$H" "$2" \
    > "$tmp/fx/$1/crowdsec-plugin-protect.caddy"
}
route current "private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10"
route old "private_ranges 100.64.0.0/10 169.254.0.0/16"
printf '%s\nvars caddy_console_manual_policy 1\n@caddy_console_manual_banned {\n\tclient_ip 198.51.100.0/24 203.0.113.7\n\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10\n}\nhandle @caddy_console_manual_banned {\n\trespond 403\n}\n' "$H" \
  > "$tmp/fx/current/bans-manual.caddy"
printf '%s\nvars caddy_console_crowdsec_policy 1\n@caddy_console_crowdsec_banned {\n\tclient_ip 192.0.2.0/24 203.0.113.9\n\tnot client_ip private_ranges 100.64.0.0/10 169.254.0.0/16 fc00::/7 fe80::/10\n}\nhandle @caddy_console_crowdsec_banned {\n\trespond 403\n}\n' "$H" \
  > "$tmp/fx/current/bans-crowdsec.caddy"
G='{
	admin 0.0.0.0:2019
	crowdsec {
		api_url http://crowdsec:8080
		api_key {env.CROWDSEC_PLUGIN_BOUNCER_KEY}
		ticker_interval 10s
	}
	order crowdsec first
}
'
M='import /etc/caddy/fx/current/bans-manual*.caddy'
C='import /etc/caddy/fx/current/bans-crowdsec*.caddy'
layout() {  # $1: name, $2: route dir, $3: site body
  printf '%simport /etc/caddy/fx/%s/crowdsec-plugin-protect*.caddy\n\na.example.com {\n%s}\n' "$G" "$2" "$3" > "$tmp/$1.Caddyfile"
}
layout plugin_only current $'\timport protect_crowdsec\n\treverse_proxy 127.0.0.1:9\n'
layout manual_and_plugin current $'\t'"$M"$'\n\timport protect_crowdsec\n\treverse_proxy 127.0.0.1:9\n'
layout manual_crowdsec_and_plugin current $'\t'"$M"$'\n\t'"$C"$'\n\timport protect_crowdsec\n\treverse_proxy 127.0.0.1:9\n'
layout manual_and_crowdsec_file current $'\t'"$M"$'\n\t'"$C"$'\n\treverse_proxy 127.0.0.1:9\n'
layout bare_handler current $'\t'"$M"$'\n\tcrowdsec\n\treverse_proxy 127.0.0.1:9\n'
layout app_without_handler current $'\t'"$M"$'\n\treverse_proxy 127.0.0.1:9\n'
layout plugin_redir current $'\timport protect_crowdsec\n\tredir /old /new\n\treverse_proxy 127.0.0.1:9\n'
layout plugin_strict_route current $'\troute {\n\t\timport protect_crowdsec\n\t\t'"$M"$'\n\t\treverse_proxy 127.0.0.1:9\n\t}\n'
layout plugin_outdated old $'\timport protect_crowdsec\n\treverse_proxy 127.0.0.1:9\n'
out="$tmp/out"
mkdir "$out"
for f in "$tmp"/*.Caddyfile; do
  name="$(basename "$f" .Caddyfile)"
  docker run --rm -v "$tmp:/etc/caddy:ro" "$IMAGE" caddy adapt --config "/etc/caddy/$name.Caddyfile" \
    --adapter caddyfile > "$out/$name.json"
done
python3 - "$out" <<'PY'
import json, os, sys
d = sys.argv[1]
print(json.dumps({n[:-5]: json.load(open(os.path.join(d, n))) for n in sorted(os.listdir(d))}, indent=1, sort_keys=True))
PY
