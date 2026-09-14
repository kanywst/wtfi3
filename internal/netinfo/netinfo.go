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
	IP      net.IP
	MAC     net.HardwareAddr
	Mask    net.IPMask
	Gateway net.IP
	GwMAC   net.HardwareAddr // learned at runtime (spoof mode)
}

// Lookup gathers the IPv4 address, mask, MAC, and default gateway for the named
// interface.
func Lookup(name string) (*Self, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, _ := ifc.Addrs()
	var ip net.IP
	var mask net.IPMask
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			ip = ipn.IP.To4()
			mask = ipn.Mask
			break
		}
	}
	if ip == nil {
		return nil, fmt.Errorf("no IPv4 address on %s", name)
	}
	return &Self{Name: name, IP: ip, MAC: ifc.HardwareAddr, Mask: mask, Gateway: defaultGateway()}, nil
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
