package netinfo

import (
	"net"
	"os/exec"
	"strings"
)

// defaultGateway parses the default route for iface from macOS/BSD `route`
// output. With an interface, `-ifscope` asks for that interface's default
// route, so `-i en0` on a Mac whose primary route is Ethernet gets the Wi-Fi
// gateway, not the Ethernet one. No match returns nil rather than another
// interface's gateway.
func defaultGateway(iface string) net.IP {
	args := []string{"-n", "get", "default"}
	if iface != "" {
		args = []string{"-n", "get", "-ifscope", iface, "default"}
	}
	out, err := exec.Command("route", args...).Output()
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
