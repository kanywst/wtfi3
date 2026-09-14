package spoof

import (
	"net"
	"testing"
)

func TestDeriveCIDR(t *testing.T) {
	_, n, _ := net.ParseCIDR("192.168.0.0/24")
	if got := deriveCIDR(net.IPv4(192, 168, 0, 15), n.Mask); got != "192.168.0.0/24" {
		t.Fatalf("deriveCIDR = %s, want 192.168.0.0/24", got)
	}
}

func TestHostsOf(t *testing.T) {
	// /30 has .0 (network), .1, .2 (hosts), .3 (broadcast).
	ips, err := hostsOf("192.168.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("hosts = %d, want 2 (network and broadcast dropped)", len(ips))
	}
	if ips[0].String() != "192.168.0.1" || ips[1].String() != "192.168.0.2" {
		t.Fatalf("hosts = %v, want [.1 .2]", ips)
	}
}

func TestNextIP(t *testing.T) {
	if got := nextIP(net.IPv4(192, 168, 0, 255).To4()).String(); got != "192.168.1.0" {
		t.Fatalf("nextIP rollover = %s, want 192.168.1.0", got)
	}
}
