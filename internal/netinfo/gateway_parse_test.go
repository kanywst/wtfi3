package netinfo

import "testing"

func TestParseProcNetRoute(t *testing.T) {
	// Real-shaped /proc/net/route: a default route via 192.168.2.1 on wlan0,
	// plus an on-link route (no RTF_GATEWAY) that must be ignored.
	const table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"wlan0\t0002A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n" +
		"wlan0\t00000000\t0102A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
	gw := parseProcNetRoute([]byte(table), "")
	if gw == nil {
		t.Fatal("no gateway parsed")
	}
	if gw.String() != "192.168.2.1" {
		t.Fatalf("gateway = %s, want 192.168.2.1", gw.String())
	}
}

func TestParseProcNetRouteNoDefault(t *testing.T) {
	const table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"wlan0\t0002A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"
	if gw := parseProcNetRoute([]byte(table), ""); gw != nil {
		t.Fatalf("gateway = %s, want nil (no default route)", gw.String())
	}
}

func TestParseProcNetRouteDefaultWithoutGatewayFlag(t *testing.T) {
	// Destination 0.0.0.0 but RTF_GATEWAY (0x2) not set: not a usable gateway.
	const table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"wlan0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"
	if gw := parseProcNetRoute([]byte(table), ""); gw != nil {
		t.Fatalf("gateway = %s, want nil", gw.String())
	}
}

func TestParseProcNetRouteGarbage(t *testing.T) {
	if gw := parseProcNetRoute([]byte("not a routing table\n"), ""); gw != nil {
		t.Fatalf("gateway = %s, want nil", gw.String())
	}
	if gw := parseProcNetRoute(nil, ""); gw != nil {
		t.Fatalf("gateway = %s, want nil", gw.String())
	}
}

func TestParseIPRouteDefault(t *testing.T) {
	cases := []struct {
		name, out, want string
	}{
		{"typical", "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n", "192.168.1.1"},
		{"no metric", "default via 10.0.0.1 dev eth0\n", "10.0.0.1"},
		{"empty", "", ""},
		{"no via", "default dev wlan0 scope link\n", ""},
		{"malformed via at end", "default via\n", ""},
	}
	for _, c := range cases {
		gw := parseIPRouteDefault([]byte(c.out), "")
		got := ""
		if gw != nil {
			got = gw.String()
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseProcNetRoutePicksCaptureInterface(t *testing.T) {
	// Two defaults: eth0 (metric 100) and wlan0 (metric 600). Capturing on
	// wlan0 must spoof wlan0's gateway, not the lower-metric eth0 one.
	const table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
		"wlan0\t00000000\t0102A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
	for iface, want := range map[string]string{"wlan0": "192.168.2.1", "eth0": "10.0.0.1", "": "10.0.0.1", "usb0": ""} {
		gw := parseProcNetRoute([]byte(table), iface)
		got := ""
		if gw != nil {
			got = gw.String()
		}
		if got != want {
			t.Errorf("iface %q: got %q, want %q", iface, got, want)
		}
	}
}

func TestParseIPRouteDefaultInterfaceAndIPv6(t *testing.T) {
	const out = "default via fe80::1 dev wlan0 proto ra metric 1024\n" +
		"default via 10.0.0.1 dev eth0 metric 100\n" +
		"default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"
	for iface, want := range map[string]string{"wlan0": "192.168.1.1", "eth0": "10.0.0.1", "": "10.0.0.1", "usb0": ""} {
		gw := parseIPRouteDefault([]byte(out), iface)
		got := ""
		if gw != nil {
			got = gw.String()
		}
		if got != want {
			t.Errorf("iface %q: got %q, want %q", iface, got, want)
		}
	}
}
