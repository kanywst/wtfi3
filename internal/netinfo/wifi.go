package netinfo

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// WiFi describes the wireless network the capture interface is attached to.
// It is nil for wired interfaces and for platforms we cannot query.
//
// On macOS 14+ the SSID and BSSID are gated behind Location Services: a process
// without that authorization still learns that the link is up, but gets the
// literal string "<redacted>" instead of the network name. Redacted records
// that case so the dashboard can say "withheld" rather than "not connected"
// (which is what `networksetup -getairportnetwork` misleadingly reports).
type WiFi struct {
	Connected bool
	SSID      string
	BSSID     string
	Security  string
	Redacted  bool
}

const redacted = "<redacted>"

// runWiFiCmd runs a short-lived query command with a timeout, so a wedged driver
// or hung tool cannot stall the periodic WiFi refresh. It
// retries once on error to absorb a transient failure at startup, which would
// otherwise leave WiFi reporting disabled for the life of the process.
func runWiFiCmd(name string, args ...string) (string, bool) {
	for range 2 { // one retry to absorb a transient error
		if out, ok := runWiFiCmdOnce(name, args...); ok {
			return out, true
		}
	}
	return "", false
}

// runWiFiCmdOnce is runWiFiCmd without the retry, for best-effort lookups that
// may fail deterministically (no permission, unsupported driver) on every poll.
func runWiFiCmdOnce(name string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err == nil
}

// LookupWiFi reports the wireless network on the named interface, or nil if the
// interface is not wireless (or the platform tooling is unavailable).
func LookupWiFi(name string) *WiFi {
	switch runtime.GOOS {
	case "darwin":
		out, ok := runWiFiCmd("ipconfig", "getsummary", name)
		if !ok {
			// The query itself failed (not "this is a wired interface" — a wired
			// interface yields a successful summary with InterfaceType != WiFi and
			// is filtered out by parseIPConfigSummary). Return a non-nil empty
			// value so refreshWiFi keeps polling rather than latching a transient
			// startup failure into permanent disablement.
			return &WiFi{}
		}
		return parseIPConfigSummary(out)
	case "linux":
		if _, err := os.Stat("/sys/class/net/" + name + "/wireless"); err != nil {
			return nil
		}
		out, ok := runWiFiCmd("iw", "dev", name, "link")
		if !ok {
			return &WiFi{}
		}
		w := parseIWLink(out)
		if w.Connected {
			// `iw link` has no cipher, so read it from the cached scan entry of
			// the associated BSS. cfg80211 keeps that entry current from the
			// AP's beacons while associated, so it is not a stale scan result.
			// A miss leaves Security empty (unknown), which the dashboard
			// treats as "no warning" rather than "open".
			if dump, ok := runWiFiCmdOnce("iw", "dev", name, "scan", "dump"); ok {
				w.Security = parseIWScanSecurity(dump, w.BSSID)
			}
		}
		return w
	}
	return nil
}

// parseIPConfigSummary reads the top-level keys of `ipconfig getsummary <if>`.
// Only lines indented by exactly two spaces are top-level; deeper indentation
// belongs to nested dictionaries and the embedded DHCP packet dump, which may
// contain arbitrary text.
func parseIPConfigSummary(out string) *WiFi {
	w := &WiFi{}
	wireless := false
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		key, val, ok := strings.Cut(strings.TrimSpace(line), " : ")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "InterfaceType":
			wireless = val == "WiFi"
		case "LinkStatusActive":
			w.Connected = val == "TRUE"
		case "SSID":
			w.SSID, w.Redacted = readable(val)
		case "BSSID":
			w.BSSID, _ = readable(val)
		case "Security":
			w.Security = val
		}
	}
	if !wireless {
		return nil
	}
	return w
}

// parseIWLink reads `iw dev <if> link` output. `iw link` does not report the
// cipher/security; LookupWiFi fills Security from parseIWScanSecurity.
func parseIWLink(out string) *WiFi {
	w := &WiFi{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Not connected"):
			return w
		case strings.HasPrefix(line, "Connected to "):
			w.Connected = true
			// Guard the index: malformed `iw` output must not panic a poll,
			// since LookupWiFi is called periodically by the WiFi refresh loop.
			if f := strings.Fields(strings.TrimPrefix(line, "Connected to ")); len(f) > 0 {
				w.BSSID = f[0]
			}
		case strings.HasPrefix(line, "SSID: "):
			w.SSID = strings.TrimPrefix(line, "SSID: ")
		}
	}
	return w
}

// parseIWScanSecurity finds the BSS entry for bssid in `iw dev <if> scan dump`
// output (or the one marked "-- associated" when bssid is empty) and derives a
// security label in the same vocabulary as macOS's ipconfig: "NONE" for an open
// network, otherwise WEP, WPA/WPA2/WPA3 variants, or OWE (Enhanced Open, which
// is encrypted). It returns "" when the entry is not in the scan cache.
func parseIWScanSecurity(out, bssid string) string {
	var in, found, privacy, rsn, wpa bool
	var auth []string
	section := "" // "RSN" or "WPA" while reading that element's sub-lines
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(raw, "BSS ") {
			if in {
				break // finished the matching entry
			}
			f := strings.Fields(strings.TrimPrefix(raw, "BSS "))
			if len(f) == 0 {
				continue
			}
			mac, _, _ := strings.Cut(f[0], "(")
			if bssid != "" {
				in = strings.EqualFold(mac, bssid)
			} else {
				in = strings.HasSuffix(strings.TrimSpace(raw), "-- associated")
			}
			found = found || in
			continue
		}
		if !in {
			continue
		}
		switch {
		case strings.HasPrefix(line, "capability:"):
			privacy = strings.Contains(line, "Privacy")
			section = ""
		case strings.HasPrefix(line, "RSN:"):
			rsn, section = true, "RSN"
		case strings.HasPrefix(line, "WPA:"):
			wpa, section = true, "WPA"
		case strings.HasPrefix(line, "* Authentication suites:"):
			if section == "RSN" || (section == "WPA" && !rsn) {
				auth = strings.Fields(strings.TrimPrefix(line, "* Authentication suites:"))
			}
		case !strings.HasPrefix(line, "*"):
			section = "" // a new top-level element ends RSN/WPA
		}
	}
	if !found {
		return ""
	}
	if !rsn && !wpa {
		if privacy {
			return "WEP"
		}
		return "NONE"
	}
	has := func(s string) bool {
		for _, a := range auth {
			if a == s {
				return true
			}
		}
		return false
	}
	switch {
	case !rsn:
		if has("PSK") {
			return "WPA_PSK"
		}
		return "WPA_EAP"
	case has("OWE"):
		return "OWE"
	case has("SAE") || has("FT/SAE"):
		if has("PSK") {
			return "WPA2_WPA3_PSK"
		}
		return "WPA3_SAE"
	case has("PSK") || has("FT/PSK") || has("PSK/SHA-256"):
		return "WPA2_PSK"
	default:
		return "WPA2_EAP"
	}
}

// readable returns the value unless the OS withheld it, and whether it did.
func readable(val string) (string, bool) {
	if val == redacted {
		return "", true
	}
	return val, false
}
