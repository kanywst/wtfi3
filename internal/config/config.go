// Package config parses command-line flags into a Config value.
package config

import "flag"

// Config holds all runtime options. It is passed explicitly rather than read
// from globals.
type Config struct {
	Iface       string
	Listen      string
	Spoof       bool
	Snaplen     int
	ScanCIDR    string
	PcapOut     string
	ReadFile    string
	ShowVersion bool
}

// Parse builds a Config from the given argument list.
func Parse(args []string) (*Config, error) {
	fs := flag.NewFlagSet("wtfi3", flag.ContinueOnError)
	c := &Config{}
	fs.StringVar(&c.Iface, "i", "en0", "capture interface")
	fs.StringVar(&c.Listen, "listen", ":8080", "dashboard listen address")
	fs.BoolVar(&c.Spoof, "spoof", false, "ARP-spoof the LAN to capture other devices' flows (own network only)")
	fs.IntVar(&c.Snaplen, "snaplen", 262144, "capture snaplen")
	fs.StringVar(&c.ScanCIDR, "scan", "", "override LAN CIDR to scan for spoofing (auto if empty)")
	fs.StringVar(&c.PcapOut, "w", "", "also write captured packets to this .pcap file (open in Wireshark)")
	fs.StringVar(&c.ReadFile, "r", "", "read packets from a .pcap file instead of a live interface (no root needed)")
	fs.BoolVar(&c.ShowVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return c, nil
}

// Offline reports whether packets are replayed from a file.
func (c *Config) Offline() bool { return c.ReadFile != "" }
