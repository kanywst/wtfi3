// Package capture opens a live interface or an offline pcap file and feeds
// decoded packets to a Consumer, optionally teeing them to a pcap file.
package capture

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
)

// Consumer receives each captured packet.
type Consumer interface {
	Consume(gopacket.Packet)
}

// Options configures a capture run.
type Options struct {
	Iface    string
	Snaplen  int
	ReadFile string // if set, replay this pcap instead of a live capture
	PcapOut  string // if set, also write captured packets here
}

// Offline reports whether these options describe an offline replay.
func (o Options) Offline() bool { return o.ReadFile != "" }

// Run captures until ctx is canceled (live) or the file is exhausted
// (offline), delivering every packet to c.
func Run(ctx context.Context, opts Options, c Consumer) error {
	var (
		handle *pcap.Handle
		err    error
	)
	if opts.Offline() {
		handle, err = pcap.OpenOffline(opts.ReadFile)
	} else {
		handle, err = pcap.OpenLive(opts.Iface, int32(opts.Snaplen), true, pcap.BlockForever)
	}
	if err != nil {
		return fmt.Errorf("pcap open: %w", err)
	}
	defer handle.Close()

	var pcapW *pcapgo.Writer
	if opts.PcapOut != "" {
		f, err := os.Create(opts.PcapOut)
		if err != nil {
			return fmt.Errorf("open pcap %s: %w", opts.PcapOut, err)
		}
		defer func() { _ = f.Close() }()
		pcapW = pcapgo.NewWriter(f)
		if err := pcapW.WriteFileHeader(uint32(opts.Snaplen), handle.LinkType()); err != nil {
			return fmt.Errorf("pcap header: %w", err)
		}
		slog.Info("writing packets", "file", opts.PcapOut)
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.Lazy = true
	source.NoCopy = true
	pkts := source.Packets()

	var pcapErrLogged bool
	for {
		select {
		case <-ctx.Done():
			return nil
		case p, ok := <-pkts:
			if !ok {
				return nil // offline EOF
			}
			if pcapW != nil {
				if err := pcapW.WritePacket(p.Metadata().CaptureInfo, p.Data()); err != nil && !pcapErrLogged {
					slog.Warn("pcap write error (further errors suppressed)", "err", err)
					pcapErrLogged = true
				}
			}
			c.Consume(p)
		}
	}
}
