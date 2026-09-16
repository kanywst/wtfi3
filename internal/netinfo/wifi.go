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
// or hung tool cannot stall the periodic refresh that EvictLoop drives. It
// retries once on error to absorb a transient failure at startup, which would
// otherwise leave WiFi reporting disabled for the life of the process.
func runWiFiCmd(name string, args ...string) (string, bool) {
	for range 2 { // one retry to absorb a transient error
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		out, err := exec.CommandContext(ctx, name, args...).Output()
		cancel()
		if err == nil {
			return string(out), true
		}
	}
	return "", false
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
		return parseIWLink(out)
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

// parseIWLink reads `iw dev <if> link` output. Note: `iw link` does not report
// the cipher/security, so WiFi.Security stays empty on Linux and the dashboard's
// open-network warning is macOS-only for now (see the README).
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
			// since LookupWiFi is called periodically from EvictLoop.
			if f := strings.Fields(strings.TrimPrefix(line, "Connected to ")); len(f) > 0 {
				w.BSSID = f[0]
			}
		case strings.HasPrefix(line, "SSID: "):
			w.SSID = strings.TrimPrefix(line, "SSID: ")
		}
	}
	return w
}

// readable returns the value unless the OS withheld it, and whether it did.
func readable(val string) (string, bool) {
	if val == redacted {
		return "", true
	}
	return val, false
}
