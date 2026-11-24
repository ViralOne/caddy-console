package main

import (
	"encoding/json"
	"io/fs"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const (
	adminAddr = "172.30.250.2:2019"
	subnet    = "172.30.250.0/29"
	keyFile   = "/run/secrets/crowdsec_plugin_bouncer_key"
	secret    = "3f9a1c0b7e6d5a4f3e2d1c0b9a8f7e6d"
)

type fakeInfo struct {
	size int64
	mode fs.FileMode
}

func (f fakeInfo) Name() string       { return "k" }
func (f fakeInfo) Size() int64        { return f.size }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

func statWith(files map[string]fakeInfo) func(string) (fs.FileInfo, error) {
	return func(p string) (fs.FileInfo, error) {
		if fi, ok := files[p]; ok {
			return fi, nil
		}
		return nil, fs.ErrNotExist
	}
}

var mounted = statWith(map[string]fakeInfo{keyFile: {size: 65}})

func ifaces(p ...string) []netip.Prefix {
	out := []netip.Prefix{}
	for _, s := range p {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

var docker = ifaces("172.30.250.2/29", "172.19.0.3/16", "127.0.0.1/8")

// cfg builds adapted JSON. admin nil means no admin key; apiKey "" means no crowdsec app.
func cfg(admin map[string]any, apiKey string) []byte {
	doc := map[string]any{"apps": map[string]any{}}
	if admin != nil {
		doc["admin"] = admin
	}
	if apiKey != "" {
		doc["apps"] = map[string]any{"crowdsec": map[string]any{"api_url": "http://crowdsec:8080", "api_key": apiKey}}
	}
	b, _ := json.Marshal(doc)
	return b
}

func fixed() map[string]any {
	return map[string]any{"listen": "tcp/" + adminAddr, "origins": []string{"caddy:2019", adminAddr}}
}

func envMode() Env  { return Env{AdminAddress: adminAddr, AdminSubnet: subnet, KeySet: true} }
func fileMode() Env { return Env{AdminAddress: adminAddr, AdminSubnet: subnet, KeyFile: keyFile} }

func mustRefuse(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal %q does not contain %q", err.Error(), want)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("refusal echoes the key: %q", err.Error())
	}
}

func TestFixedBindStartsInBothKeyModes(t *testing.T) {
	if err := Check(envMode(), cfg(fixed(), "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"), docker, mounted); err != nil {
		t.Fatal(err)
	}
	if err := Check(fileMode(), cfg(fixed(), "{file."+keyFile+"}"), docker, mounted); err != nil {
		t.Fatal(err)
	}
	listen := fixed()
	listen["listen"] = adminAddr // without the tcp/ prefix
	if err := Check(envMode(), cfg(listen, ""), docker, mounted); err != nil {
		t.Fatal(err)
	}
}

func TestWildcardAndLoopbackAdminAreRefused(t *testing.T) {
	cases := map[string]string{
		"tcp/0.0.0.0:2019": "wildcard", ":2019": "wildcard", "tcp/[::]:2019": "wildcard",
		"localhost:2019": "loopback", "tcp/127.0.0.1:2019": "loopback", "[::1]:2019": "loopback",
		"unix//run/caddy-admin.sock": "unix socket", "tcp/172.30.250.3:2019": "differs from CADDY_ADMIN_ADDRESS",
	}
	for listen, want := range cases {
		a := fixed()
		a["listen"] = listen
		mustRefuse(t, Check(envMode(), cfg(a, ""), docker, mounted), want)
	}
	mustRefuse(t, Check(envMode(), cfg(nil, ""), docker, mounted), "no admin line")
	mustRefuse(t, Check(envMode(), cfg(map[string]any{"disabled": true}, ""), docker, mounted), "admin off")
	err := Check(envMode(), cfg(nil, ""), docker, mounted)
	if !strings.Contains(err.Error(), "admin 172.30.250.2:2019 {") {
		t.Fatalf("the refusal must show the required bind: %v", err)
	}
}

func TestOriginsMustListTheFixedAddress(t *testing.T) {
	a := fixed()
	a["origins"] = []string{"caddy:2019"}
	mustRefuse(t, Check(envMode(), cfg(a, ""), docker, mounted), "origins")
	delete(a, "origins")
	mustRefuse(t, Check(envMode(), cfg(a, ""), docker, mounted), "origins")
}

func TestAdminAddressSettingsAreValidated(t *testing.T) {
	for _, bad := range []string{"", "0.0.0.0:2019", "127.0.0.1:2019", "caddy:2019", "172.30.250.2", "[fe80::1]:2019"} {
		e := envMode()
		e.AdminAddress = bad
		mustRefuse(t, Check(e, cfg(fixed(), ""), docker, mounted), "CADDY_ADMIN_ADDRESS")
	}
	e := envMode()
	e.AdminSubnet = "172.30.250.1/29"
	mustRefuse(t, Check(e, cfg(fixed(), ""), docker, mounted), "CADDY_ADMIN_SUBNET")
	e.AdminSubnet = "172.30.251.0/29"
	mustRefuse(t, Check(e, cfg(fixed(), ""), docker, mounted), "not inside CADDY_ADMIN_SUBNET")
}

func TestAddressMustBeOnTheAdminNetworkOnly(t *testing.T) {
	mustRefuse(t, Check(envMode(), cfg(fixed(), ""), ifaces("172.19.0.3/16"), mounted), "has no address 172.30.250.2")
	mustRefuse(t, Check(envMode(), cfg(fixed(), ""), ifaces("172.30.250.2/24"), mounted), "a network other than")
	shared := ifaces("172.30.250.2/29", "172.30.250.4/29")
	mustRefuse(t, Check(envMode(), cfg(fixed(), ""), shared, mounted), "another interface")
}

func TestLiteralKeyIsRefusedWithoutEchoingIt(t *testing.T) {
	mustRefuse(t, Check(envMode(), cfg(fixed(), secret), docker, mounted), "written into the Caddyfile")
}

func TestKeyFileMismatchIsRefused(t *testing.T) {
	mustRefuse(t, Check(fileMode(), cfg(fixed(), "{file./run/secrets/other}"), docker, mounted),
		"{file./run/secrets/other}")
	mustRefuse(t, Check(fileMode(), cfg(fixed(), "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"), docker, mounted),
		"{file."+keyFile+"}")
	missing := statWith(map[string]fakeInfo{"/run/secrets/other": {size: 65}})
	mustRefuse(t, Check(fileMode(), cfg(fixed(), "{file."+keyFile+"}"), docker, missing), "is not mounted")
	mustRefuse(t, Check(fileMode(), cfg(fixed(), ""), docker, missing), "is not mounted") // checked before the app exists
	empty := statWith(map[string]fakeInfo{keyFile: {size: 0}})
	mustRefuse(t, Check(fileMode(), cfg(fixed(), ""), docker, empty), "is empty")
	dir := statWith(map[string]fakeInfo{keyFile: {mode: fs.ModeDir}})
	mustRefuse(t, Check(fileMode(), cfg(fixed(), ""), docker, dir), "not a regular file")
	for _, bad := range []string{"run/secrets/k", "/run/secrets/../k", "/run/./k", "/run/secrets/k ", "/run/secrets/{k}"} {
		e := fileMode()
		e.KeyFile = bad
		mustRefuse(t, Check(e, cfg(fixed(), ""), docker, mounted), "absolute path")
	}
	both := fileMode()
	both.KeySet = true
	mustRefuse(t, Check(both, cfg(fixed(), ""), docker, mounted), "not both")
}

func TestEnvModeNeedsTheKeyAndThePlaceholder(t *testing.T) {
	e := envMode()
	e.KeySet = false
	mustRefuse(t, Check(e, cfg(fixed(), "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}"), docker, mounted), "CROWDSEC_PLUGIN_BOUNCER_KEY is empty")
	if err := Check(e, cfg(fixed(), ""), docker, mounted); err != nil {
		t.Fatalf("no crowdsec app yet: only the admin checks apply: %v", err)
	}
	mustRefuse(t, Check(envMode(), cfg(fixed(), "{env.OTHER}"), docker, mounted), "{env.CROWDSEC_PLUGIN_BOUNCER_KEY}")
}

func TestUnreadableConfigIsRefused(t *testing.T) {
	mustRefuse(t, Check(envMode(), []byte("not json"), docker, mounted), "adapted Caddyfile")
}

func TestStatErrorsOtherThanMissingAreReported(t *testing.T) {
	denied := func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }
	mustRefuse(t, Check(fileMode(), cfg(fixed(), ""), docker, denied), "cannot be checked")
}

func TestFlagValue(t *testing.T) {
	args := []string{"caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter=caddyfile"}
	if got := flagValue(args, "--config", "x"); got != "/etc/caddy/Caddyfile" {
		t.Fatal(got)
	}
	if got := flagValue(args, "--adapter", "x"); got != "caddyfile" {
		t.Fatal(got)
	}
	if got := flagValue(args, "--watch", "none"); got != "none" {
		t.Fatal(got)
	}
}
