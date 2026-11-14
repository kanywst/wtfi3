package netinfo

import (
	"math"
	"net"
	"strconv"
	"strings"
)

// rtfGateway is the RTF_GATEWAY flag in /proc/net/route: the route goes via a
// gateway rather than being directly on-link.
const rtfGateway = 0x0002

// parseProcNetRoute extracts the IPv4 default gateway for iface from the
// contents of /proc/net/route. Each row after the header is tab/space separated
// with the columns Iface, Destination, Gateway, Flags, RefCnt, Use, Metric, ...
// where Destination and Gateway are little-endian hex. A default route has
// Destination 00000000 and the RTF_GATEWAY flag set. Only routes on iface count
// (any interface when iface is ""), and the lowest Metric wins, as the kernel
// would choose. Returns nil when no such route is present.
func parseProcNetRoute(data []byte, iface string) net.IP {
	var best net.IP
	bestMetric := uint64(math.MaxUint64)
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 { // header row
			continue
		}
		f := strings.Fields(line)
		if len(f) < 7 || f[1] != "00000000" || (iface != "" && f[0] != iface) {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfGateway == 0 {
			continue
		}
		metric, err := strconv.ParseUint(f[6], 10, 64)
		if err != nil {
			continue
		}
		if gw := hexLEToIP(f[2]); gw != nil && metric < bestMetric {
			best, bestMetric = gw, metric
		}
	}
	return best
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

// parseIPRouteDefault reads the IPv4 gateway for iface from `ip route show
// default` output, e.g. "default via 192.168.1.1 dev wlan0 proto dhcp metric
// 600". Lines on other devices (when iface is not "") and non-IPv4 "via"
// addresses are skipped; the lowest metric wins. Returns nil when none match.
func parseIPRouteDefault(out []byte, iface string) net.IP {
	var best net.IP
	bestMetric := uint64(math.MaxUint64)
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		var via net.IP
		dev, metric := "", uint64(0)
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "via":
				via = net.ParseIP(f[i+1]).To4()
			case "dev":
				dev = f[i+1]
			case "metric":
				if m, err := strconv.ParseUint(f[i+1], 10, 64); err == nil {
					metric = m
				}
			}
		}
		if via == nil || (iface != "" && dev != iface) {
			continue
		}
		if metric < bestMetric {
			best, bestMetric = via, metric
		}
	}
	return best
}
