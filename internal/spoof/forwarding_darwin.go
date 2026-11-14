package spoof

import (
	"os/exec"
	"strings"
)

// darwinForwardingKey is the macOS/BSD sysctl name for IPv4 forwarding.
const darwinForwardingKey = "net.inet.ip.forwarding"

// readForwarding returns the current IPv4 forwarding value ("0"/"1") and whether
// it could be read.
func readForwarding() (string, bool) {
	out, err := exec.Command("sysctl", "-n", darwinForwardingKey).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// writeForwarding sets the IPv4 forwarding sysctl to v ("0" or "1").
func writeForwarding(v string) error {
	return exec.Command("sysctl", "-w", darwinForwardingKey+"="+v).Run()
}
