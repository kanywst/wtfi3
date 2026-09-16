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
