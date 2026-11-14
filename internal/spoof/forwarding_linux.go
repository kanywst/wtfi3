package spoof

import (
	"os"
	"os/exec"
	"strings"
)

const (
	// linuxForwardingProc is the procfs knob for IPv4 forwarding.
	linuxForwardingProc = "/proc/sys/net/ipv4/ip_forward"
	// linuxForwardingKey is the equivalent sysctl name, used as a fallback.
	linuxForwardingKey = "net.ipv4.ip_forward"
)

// readForwarding returns the current IPv4 forwarding value ("0"/"1") and whether
// it could be read, preferring procfs and falling back to sysctl.
func readForwarding() (string, bool) {
	if b, err := os.ReadFile(linuxForwardingProc); err == nil {
		return strings.TrimSpace(string(b)), true
	}
	if out, err := exec.Command("sysctl", "-n", linuxForwardingKey).Output(); err == nil {
		return strings.TrimSpace(string(out)), true
	}
	return "", false
}

// writeForwarding sets IPv4 forwarding to v ("0" or "1") via procfs, falling
// back to sysctl when the procfs write fails.
func writeForwarding(v string) error {
	if err := os.WriteFile(linuxForwardingProc, []byte(v+"\n"), 0o644); err == nil {
		return nil
	}
	return exec.Command("sysctl", "-w", linuxForwardingKey+"="+v).Run()
}
