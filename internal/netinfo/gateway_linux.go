package netinfo

import (
	"net"
	"os"
	"os/exec"
)

// defaultGateway resolves the IPv4 default gateway for iface on Linux. It reads the
// kernel routing table from /proc/net/route first (no external process), and
// falls back to `ip route show default` when /proc is unavailable (e.g. a
// restricted container mount).
func defaultGateway(iface string) net.IP {
	if data, err := os.ReadFile("/proc/net/route"); err == nil {
		if gw := parseProcNetRoute(data, iface); gw != nil {
			return gw
		}
	}
	if out, err := exec.Command("ip", "route", "show", "default").Output(); err == nil {
		if gw := parseIPRouteDefault(out, iface); gw != nil {
			return gw
		}
	}
	return nil
}
