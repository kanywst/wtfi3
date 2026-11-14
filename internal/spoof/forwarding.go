package spoof

import "log/slog"

// IP-forwarding sysctl values as written to the OS control.
const (
	forwardingOn  = "1"
	forwardingOff = "0"
)

// enableForwarding turns on kernel IPv4 forwarding so poisoned traffic transits
// this host instead of being dropped, and returns a function that restores the
// prior setting. When the prior value cannot be read, the restore falls back to
// disabling forwarding (the macOS path historically always reset it to off).
// The returned function is never nil, so callers can defer it unconditionally.
func enableForwarding() func() {
	prev, ok := readForwarding()
	if ok && prev == forwardingOn {
		slog.Info("ip forwarding was already on; leaving it on at exit")
	}
	if err := writeForwarding(forwardingOn); err != nil {
		slog.Warn("could not enable ip forwarding", "err", err)
	}
	return func() {
		restore := forwardingOff
		if ok {
			restore = prev
		}
		if err := writeForwarding(restore); err != nil {
			slog.Warn("could not restore ip forwarding", "value", restore, "err", err)
		}
	}
}
