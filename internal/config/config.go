// Package config parses command-line flags into a Config value.
package config

import (
	"errors"
	"flag"
)

// Config holds all runtime options. It is passed explicitly rather than read
// from globals.
type Config struct {
	Iface       string
	Listen      string
	Spoof       bool
	OwnNetwork  bool
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
	fs.BoolVar(&c.Spoof, "spoof", false, "ARP-spoof the LAN to capture other devices' flows (requires -i-own-this-network)")
	fs.BoolVar(&c.OwnNetwork, "i-own-this-network", false, "acknowledge you own or are authorized to test this network (required for -spoof)")
	fs.IntVar(&c.Snaplen, "snaplen", 262144, "capture snaplen")
	fs.StringVar(&c.ScanCIDR, "scan", "", "override LAN CIDR to scan for spoofing (auto if empty)")
	fs.StringVar(&c.PcapOut, "w", "", "also write captured packets to this .pcap file (open in Wireshark)")
	fs.StringVar(&c.ReadFile, "r", "", "read packets from a .pcap file instead of a live interface (no root needed)")
	fs.BoolVar(&c.ShowVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	// ARP spoofing is an active MITM attack. Refuse to arm it unless the operator
	// has explicitly acknowledged that the network is theirs to test, so it can
	// never be turned on by a stray flag alone.
	if c.Spoof && !c.OwnNetwork {
		return nil, ErrSpoofUnauthorized
	}
	return c, nil
}

// ErrSpoofUnauthorized is returned by Parse when -spoof is requested without the
// -i-own-this-network acknowledgement.
var ErrSpoofUnauthorized = errors.New(
	"-spoof is an active man-in-the-middle attack; re-run with -i-own-this-network " +
		"to confirm you own or are authorized to test this network")

// Offline reports whether packets are replayed from a file.
func (c *Config) Offline() bool { return c.ReadFile != "" }
