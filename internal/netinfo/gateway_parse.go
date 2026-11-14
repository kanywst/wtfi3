package netinfo

import (
	"net"
	"strconv"
	"strings"
)

// rtfGateway is the RTF_GATEWAY flag in /proc/net/route: the route goes via a
// gateway rather than being directly on-link.
const rtfGateway = 0x0002

// parseProcNetRoute extracts the IPv4 default gateway from the contents of
// /proc/net/route. Each row after the header is tab/space separated with the
// columns Iface, Destination, Gateway, Flags, ... where Destination and Gateway
// are little-endian hex. The default route has Destination 00000000 and the
// RTF_GATEWAY flag set. Returns nil when no default route is present.
func parseProcNetRoute(data []byte) net.IP {
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 { // header row
			continue
		}
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		if f[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfGateway == 0 {
			continue
		}
		if gw := hexLEToIP(f[2]); gw != nil {
			return gw
		}
	}
	return nil
}

// hexLEToIP converts a little-endian 8-char hex word (as /proc/net/route stores
// an IPv4 address) into a net.IP. "0102A8C0" becomes 192.168.2.1.
func hexLEToIP(h string) net.IP {
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return nil
	}
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).To4()
}

// parseIPRouteDefault reads the gateway from `ip route show default` output,
// e.g. "default via 192.168.1.1 dev wlan0 proto dhcp metric 600". Returns nil
// when no "via" address is found.
func parseIPRouteDefault(out []byte) net.IP {
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "via" {
				if ip := net.ParseIP(f[i+1]); ip != nil {
					return ip.To4()
				}
			}
		}
	}
	return nil
}
