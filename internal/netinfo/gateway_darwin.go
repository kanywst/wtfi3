package netinfo

import (
	"net"
	"os/exec"
	"strings"
)

// defaultGateway parses the system default route from macOS/BSD `route` output.
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
