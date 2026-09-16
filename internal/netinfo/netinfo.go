// Package netinfo resolves local interface and gateway information.
package netinfo

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// Self describes the capturing host's view of its network.
type Self struct {
	Name    string
	IP      net.IP // primary IPv4 (for display and v4 ARP spoofing)
	MAC     net.HardwareAddr
	Mask    net.IPMask   // mask of the primary IPv4
	Nets    []*net.IPNet // every on-link prefix (IPv4 and IPv6)
	Gateway net.IP
	GwMAC   net.HardwareAddr // learned at runtime (spoof mode)
	WiFi    *WiFi            // nil on wired interfaces
}

// Lookup gathers the on-link prefixes (IPv4 and IPv6), the primary IPv4
// address, MAC, and default gateway for the named interface.
func Lookup(name string) (*Self, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, _ := ifc.Addrs()
	var ip net.IP
	var mask net.IPMask
	var nets []*net.IPNet
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		nets = append(nets, ipn)
		if ip == nil && ipn.IP.To4() != nil {
			ip = ipn.IP.To4()
			mask = ipn.Mask
		}
	}
	if len(nets) == 0 {
		return nil, fmt.Errorf("no addresses on %s", name)
	}
	return &Self{
		Name: name, IP: ip, MAC: ifc.HardwareAddr, Mask: mask, Nets: nets,
		Gateway: defaultGateway(), WiFi: LookupWiFi(name),
	}, nil
}

// defaultGateway parses the system default route (macOS/BSD `route` output).
func defaultGateway() net.IP {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "gateway:" {
			return net.ParseIP(fields[1]).To4()
		}
	}
	return nil
}
