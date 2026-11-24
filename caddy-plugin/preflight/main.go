// caddy-console-preflight is the entrypoint of the Caddy Console plugin images
// (docs/security.md#crowdsec-plugin). For `caddy run ...` it adapts the
// Caddyfile and refuses to start Caddy unless the admin API is bound to the
// fixed caddy-admin address with origins and the CrowdSec bouncer key is a
// placeholder matching the configured secret mode. Every other command
// (caddy adapt, caddy version, sh) is exec'd unchanged.
package main

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func flagValue(args []string, name, def string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			return v
		}
	}
	return def
}

func localPrefixes() []netip.Prefix {
	out := []netip.Prefix{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		ip = ip.Unmap()
		if ip.Is4() && ones > 32 {
			ones -= 96
		}
		out = append(out, netip.PrefixFrom(ip, ones))
	}
	return out
}

func preflight(args []string) error {
	cmd := exec.Command("/usr/bin/caddy", "adapt",
		"--config", flagValue(args, "--config", "/etc/caddy/Caddyfile"),
		"--adapter", flagValue(args, "--adapter", "caddyfile"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[:2000]
		}
		return fmt.Errorf("caddy adapt failed (%v): %s", err, msg)
	}
	env := Env{
		AdminAddress: os.Getenv("CADDY_ADMIN_ADDRESS"),
		AdminSubnet:  os.Getenv("CADDY_ADMIN_SUBNET"),
		KeySet:       os.Getenv("CROWDSEC_PLUGIN_BOUNCER_KEY") != "",
		KeyFile:      os.Getenv("CROWDSEC_PLUGIN_BOUNCER_KEY_FILE"),
	}
	return Check(env, out, localPrefixes(), os.Stat)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: caddy-console-preflight caddy run [flags] | <command> [args]")
		os.Exit(2)
	}
	if len(args) >= 2 && args[0] == "caddy" && args[1] == "run" {
		if err := preflight(args); err != nil {
			fmt.Fprintf(os.Stderr, "caddy-console preflight: refusing to start Caddy: %v\n", err)
			os.Exit(78)
		}
		fmt.Fprintln(os.Stderr, "caddy-console preflight: admin bind and bouncer key checks passed")
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "caddy-console preflight: %v\n", err)
		os.Exit(127)
	}
	if err := syscall.Exec(path, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "caddy-console preflight: exec %s: %v\n", path, err)
		os.Exit(126)
	}
}
