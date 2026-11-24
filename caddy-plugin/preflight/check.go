package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

const envPlaceholder = "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"

// Same rule as src/bans/plugin.py parse_key_file(): absolute, plain segments only.
var keyPath = regexp.MustCompile(`^/(?:[A-Za-z0-9_][A-Za-z0-9._-]*/)*[A-Za-z0-9_][A-Za-z0-9._-]*$`)

// Env is what the preflight reads from the container environment. KeySet
// says whether CROWDSEC_PLUGIN_BOUNCER_KEY is non-empty; the value is never read.
type Env struct {
	AdminAddress string // CADDY_ADMIN_ADDRESS, for example 172.30.250.2:2019
	AdminSubnet  string // CADDY_ADMIN_SUBNET, for example 172.30.250.0/29
	KeySet       bool
	KeyFile      string // CROWDSEC_PLUGIN_BOUNCER_KEY_FILE
}

type adaptedConfig struct {
	Admin *struct {
		Disabled bool     `json:"disabled"`
		Listen   string   `json:"listen"`
		Origins  []string `json:"origins"`
	} `json:"admin"`
	Apps struct {
		CrowdSec *struct {
			APIKey string `json:"api_key"`
		} `json:"crowdsec"`
	} `json:"apps"`
}

func required(admin netip.AddrPort) string {
	return fmt.Sprintf("put this in the global options:\n\tadmin %s {\n\t\torigins caddy:2019 %s\n\t}", admin, admin)
}

func fixedAddress(raw string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(raw)
	if err == nil {
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	a := ap.Addr()
	if err != nil || ap.Port() == 0 || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() ||
		a.IsLinkLocalUnicast() || a.Zone() != "" {
		return netip.AddrPort{}, errors.New("CADDY_ADMIN_ADDRESS must be Caddy's fixed caddy-admin address and port, " +
			"for example 172.30.250.2:2019 (not a wildcard, loopback or host name)")
	}
	return ap, nil
}

// Check returns nil when Caddy may start. config is `caddy adapt` output;
// ifaces lists the container's addresses with their networks; stat reports
// on the key file without opening it. Messages never contain the key.
func Check(env Env, config []byte, ifaces []netip.Prefix, stat func(string) (fs.FileInfo, error)) error {
	admin, err := fixedAddress(env.AdminAddress)
	if err != nil {
		return err
	}
	subnet, err := netip.ParsePrefix(env.AdminSubnet)
	if err != nil || subnet != subnet.Masked() {
		return errors.New("CADDY_ADMIN_SUBNET must be the caddy-admin network, for example 172.30.250.0/29")
	}
	if !subnet.Contains(admin.Addr()) {
		return fmt.Errorf("CADDY_ADMIN_ADDRESS %s is not inside CADDY_ADMIN_SUBNET %s", admin, subnet)
	}
	var cfg adaptedConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return fmt.Errorf("cannot read the adapted Caddyfile (%v)", err)
	}
	if err := checkAdmin(cfg, admin); err != nil {
		return err
	}
	if err := checkInterface(admin.Addr(), subnet, ifaces); err != nil {
		return err
	}
	return checkKey(env, cfg, stat)
}

func checkAdmin(cfg adaptedConfig, admin netip.AddrPort) error {
	if cfg.Admin == nil || (cfg.Admin.Listen == "" && !cfg.Admin.Disabled) {
		return fmt.Errorf("the Caddyfile has no admin line, so Caddy would listen on localhost:2019; %s", required(admin))
	}
	if cfg.Admin.Disabled {
		return fmt.Errorf("the Caddyfile turns the admin API off (admin off), but the console needs it; %s", required(admin))
	}
	listen := strings.TrimPrefix(cfg.Admin.Listen, "tcp/")
	if strings.HasPrefix(listen, "unix/") {
		return fmt.Errorf("the admin API is a unix socket, which the console cannot reach; %s", required(admin))
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("the admin listen address %q is not host:port; %s", cfg.Admin.Listen, required(admin))
	}
	if host == "localhost" {
		return fmt.Errorf("the admin API listens on loopback only (%s), so the console cannot reach it; %s", listen, required(admin))
	}
	if host == "" {
		return fmt.Errorf("the admin API listens on a wildcard address (%s), which CrowdSec could reach; %s", listen, required(admin))
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("the admin listen host %q is not an IP address; %s", host, required(admin))
	}
	a = a.Unmap()
	switch {
	case a.IsUnspecified():
		return fmt.Errorf("the admin API listens on a wildcard address (%s), which CrowdSec could reach; %s", listen, required(admin))
	case a.IsLoopback():
		return fmt.Errorf("the admin API listens on loopback only (%s), so the console cannot reach it; %s", listen, required(admin))
	}
	if netip.AddrPortFrom(a, admin.Port()) != admin || port != fmt.Sprint(admin.Port()) {
		return fmt.Errorf("the admin listen address %s differs from CADDY_ADMIN_ADDRESS %s; %s", listen, admin, required(admin))
	}
	if !slices.Contains(cfg.Admin.Origins, admin.String()) {
		return fmt.Errorf("the admin origins must list %s, or the console and recovery commands are refused; %s", admin, required(admin))
	}
	return nil
}

func checkInterface(admin netip.Addr, subnet netip.Prefix, ifaces []netip.Prefix) error {
	var own *netip.Prefix
	for i, p := range ifaces {
		if p.Addr().Unmap() == admin {
			own = &ifaces[i]
		}
	}
	if own == nil {
		return fmt.Errorf("the container has no address %s; give Caddy ipv4_address %s on caddy-admin", admin, admin)
	}
	if own.Masked() != subnet {
		return fmt.Errorf("%s is on a network other than CADDY_ADMIN_SUBNET %s (%s)", admin, subnet, own.Masked())
	}
	for _, p := range ifaces {
		if p.Addr().Unmap() != admin && p.Masked().Contains(admin) {
			return fmt.Errorf("%s is also reachable through another interface (%s); caddy-admin must not be shared", admin, p)
		}
	}
	return nil
}

func validKeyPath(p string) bool {
	if len(p) > 255 || !keyPath.MatchString(p) {
		return false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func checkKey(env Env, cfg adaptedConfig, stat func(string) (fs.FileInfo, error)) error {
	want := envPlaceholder
	if env.KeyFile != "" {
		if env.KeySet {
			return errors.New("set CROWDSEC_PLUGIN_BOUNCER_KEY or CROWDSEC_PLUGIN_BOUNCER_KEY_FILE, not both")
		}
		if !validKeyPath(env.KeyFile) {
			return errors.New("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE must be an absolute path such as " +
				"/run/secrets/crowdsec_plugin_bouncer_key (letters, digits, '.', '_', '-' and '/')")
		}
		info, err := stat(env.KeyFile)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Errorf("the key file %s is not mounted in the Caddy container; mount the secret at exactly "+
				"the path in CROWDSEC_PLUGIN_BOUNCER_KEY_FILE", env.KeyFile)
		case err != nil:
			// A stat error names the path and the errno text only; it never reads the file.
			return fmt.Errorf("the key file %s cannot be checked (%v)", env.KeyFile, err)
		case !info.Mode().IsRegular():
			return fmt.Errorf("the key file %s is not a regular file", env.KeyFile)
		case info.Size() == 0:
			return fmt.Errorf("the key file %s is empty", env.KeyFile)
		case info.Size() > 4096:
			return fmt.Errorf("the key file %s is larger than 4 KiB", env.KeyFile)
		}
		want = "{file." + env.KeyFile + "}"
	}
	if cfg.Apps.CrowdSec == nil {
		return nil // the global crowdsec app is not configured yet
	}
	got := cfg.Apps.CrowdSec.APIKey
	if got == want {
		if env.KeyFile == "" && !env.KeySet {
			return errors.New("CROWDSEC_PLUGIN_BOUNCER_KEY is empty; set it, or use CROWDSEC_PLUGIN_BOUNCER_KEY_FILE")
		}
		return nil
	}
	if strings.HasPrefix(got, "{env.") || strings.HasPrefix(got, "{file.") {
		return fmt.Errorf("the crowdsec api_key is %s, but this container expects %s", got, want)
	}
	return fmt.Errorf("the crowdsec api_key is written into the Caddyfile, where anyone who can read Caddy's "+
		"config sees it; use api_key %s", want)
}
