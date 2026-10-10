package netinfo

import "testing"

// Trimmed real output of `ipconfig getsummary en0` on macOS 26 without Location
// access: the interface is associated, but SSID/BSSID come back redacted. The
// embedded DHCP packet dump is unindented on purpose, as the real tool prints
// it that way; the parser must not read keys out of it.
const summaryRedacted = `<dictionary> {
  BSSID : <redacted>
  ConnectionID : 49
  IPv4 : <array> {
    0 : <dictionary> {
      DHCP : <dictionary> {
        Packet : op = BOOTREPLY
htype = 1
options:
domain_name (string): wi2.ne.jp
SSID : not-a-real-key
        State : BOUND
      }
      Router : 10.49.160.1
    }
  }
  InterfaceType : WiFi
  LinkStatusActive : TRUE
  SSID : <redacted>
  Security : NONE
}`

const summaryWired = `<dictionary> {
  InterfaceType : Ethernet
  LinkStatusActive : TRUE
}`

const summaryNamed = `<dictionary> {
  BSSID : 8c:fd:f0:11:22:33
  InterfaceType : WiFi
  LinkStatusActive : TRUE
  SSID : home-net
  Security : WPA2_PSK
}`

func TestParseIPConfigSummaryRedacted(t *testing.T) {
	w := parseIPConfigSummary(summaryRedacted)
	if w == nil {
		t.Fatal("wireless interface reported as non-wireless")
	}
	if !w.Connected {
		t.Error("associated interface reported as disconnected")
	}
	if !w.Redacted || w.SSID != "" || w.BSSID != "" {
		t.Errorf("want redacted with empty names, got %+v", w)
	}
	if w.Security != "NONE" {
		t.Errorf("security = %q, want NONE", w.Security)
	}
}

func TestParseIPConfigSummaryWired(t *testing.T) {
	if w := parseIPConfigSummary(summaryWired); w != nil {
		t.Errorf("wired interface reported as wireless: %+v", w)
	}
}

func TestParseIPConfigSummaryNamed(t *testing.T) {
	w := parseIPConfigSummary(summaryNamed)
	if w == nil {
		t.Fatal("wireless interface reported as non-wireless")
	}
	if w.SSID != "home-net" || w.BSSID != "8c:fd:f0:11:22:33" || w.Redacted {
		t.Errorf("got %+v", w)
	}
}

func TestParseIWLink(t *testing.T) {
	const connected = `Connected to 8c:fd:f0:11:22:33 (on wlan0)
	SSID: home-net
	freq: 5180
	signal: -42 dBm`
	w := parseIWLink(connected)
	if !w.Connected || w.SSID != "home-net" || w.BSSID != "8c:fd:f0:11:22:33" {
		t.Errorf("got %+v", w)
	}
	if w := parseIWLink("Not connected.\n"); w.Connected || w.SSID != "" {
		t.Errorf("got %+v", w)
	}
	// Malformed "Connected to" line with no BSSID must not panic the parser
	// (LookupWiFi is polled from EvictLoop, so a panic would crash the process).
	if w := parseIWLink("Connected to\nSSID: x\n"); w.BSSID != "" {
		t.Errorf("malformed line: got %+v", w)
	}
}

// Trimmed `iw dev wlan0 scan dump` with the associated BSS between two others,
// so the parser has to pick the right entry and stop at the next "BSS" line.
const scanDump = `BSS 11:22:33:44:55:66(on wlan0)
	capability: ESS ShortSlotTime (0x0401)
	SSID: cafe-free
BSS 8c:fd:f0:11:22:33(on wlan0) -- associated
	freq: 5180
	capability: ESS Privacy ShortSlotTime (0x0411)
	SSID: home-net
	RSN:	 * Version: 1
		 * Group cipher: CCMP
		 * Pairwise ciphers: CCMP
		 * Authentication suites: PSK SAE
		 * Capabilities: 16-PTKSA-RC 1-GTKSA-RC (0x000c)
	WPS:	 * Version: 1.0
BSS aa:bb:cc:dd:ee:ff(on wlan0)
	capability: ESS Privacy (0x0011)
	SSID: corp
	RSN:	 * Version: 1
		 * Authentication suites: IEEE 802.1X
`

func TestParseIWScanSecurity(t *testing.T) {
	cases := []struct {
		name, out, bssid, want string
	}{
		{"mixed WPA2/WPA3", scanDump, "8c:fd:f0:11:22:33", "WPA2_WPA3_PSK"},
		{"bssid case-insensitive", scanDump, "8C:FD:F0:11:22:33", "WPA2_WPA3_PSK"},
		{"associated marker without bssid", scanDump, "", "WPA2_WPA3_PSK"},
		{"open", scanDump, "11:22:33:44:55:66", "NONE"},
		{"enterprise", scanDump, "aa:bb:cc:dd:ee:ff", "WPA2_EAP"},
		{"not in cache", scanDump, "00:00:00:00:00:01", ""},
		{"empty", "", "8c:fd:f0:11:22:33", ""},
		{"wep", "BSS 01:02:03:04:05:06(on wlan0)\n\tcapability: ESS Privacy (0x0011)\n", "01:02:03:04:05:06", "WEP"},
		{"wpa1 psk", "BSS 01:02:03:04:05:06(on wlan0)\n\tcapability: ESS Privacy (0x0011)\n\tWPA:\t * Version: 1\n\t\t * Authentication suites: PSK\n", "01:02:03:04:05:06", "WPA_PSK"},
		{"wpa3 only", "BSS 01:02:03:04:05:06(on wlan0)\n\tcapability: ESS Privacy (0x0011)\n\tRSN:\t * Version: 1\n\t\t * Authentication suites: SAE\n", "01:02:03:04:05:06", "WPA3_SAE"},
		{"owe is not open", "BSS 01:02:03:04:05:06(on wlan0)\n\tcapability: ESS Privacy (0x0011)\n\tRSN:\t * Version: 1\n\t\t * Authentication suites: OWE\n", "01:02:03:04:05:06", "OWE"},
		{"malformed BSS line", "BSS \n\tcapability: ESS (0x0001)\n", "", ""},
	}
	for _, c := range cases {
		if got := parseIWScanSecurity(c.out, c.bssid); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
