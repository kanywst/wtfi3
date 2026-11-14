//go:build !darwin && !linux

package spoof

// On platforms without a known forwarding control, reading is unsupported and
// writing is a no-op. Spoofing still refuses to run elsewhere because no default
// gateway resolves, so these are never exercised in practice.
func readForwarding() (string, bool) { return "", false }

func writeForwarding(string) error { return nil }
