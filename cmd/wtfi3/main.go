// Command wtfi3 visualizes the traffic on a WiFi network you administer.
//
// Usage:
//
//	sudo wtfi3 -i en0                      # passive
//	sudo wtfi3 -i en0 -spoof               # ARP-spoof MITM (own network only)
//	sudo wtfi3 -i en0 -spoof -w cap.pcap   # also dump packets for Wireshark
//	wtfi3 -r cap.pcap                       # offline replay (no root)
//
// TLS payloads are never decrypted; only metadata (endpoints, volume, DNS, SNI)
// is shown at http://localhost:8080.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wtfi3/internal/aggregator"
	"wtfi3/internal/capture"
	"wtfi3/internal/config"
	"wtfi3/internal/netinfo"
	"wtfi3/internal/spoof"
	"wtfi3/internal/web"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		return err
	}
	if cfg.ShowVersion {
		fmt.Printf("wtfi3 %s\n", version)
		return nil
	}
	if !cfg.Offline() && os.Geteuid() != 0 {
		return fmt.Errorf("live capture requires root: sudo wtfi3 ...  (or use -r file.pcap)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	self, err := netinfo.Lookup(cfg.Iface)
	if err != nil {
		if !cfg.Offline() {
			return fmt.Errorf("interface %s: %w", cfg.Iface, err)
		}
		self = &netinfo.Self{Name: cfg.Iface}
		slog.Warn("offline mode: interface unavailable, LAN attribution limited", "iface", cfg.Iface)
	}
	slog.Info("starting", "version", version, "iface", self.Name, "ip", ipStr(self.IP), "gateway", ipStr(self.Gateway))

	state := aggregator.New(self, cfg.Spoof, version)
	go state.EvictLoop(ctx)
	go state.SampleLoop(ctx)

	if cfg.Spoof && !cfg.Offline() {
		slog.Warn("ARP-spoof MITM armed: this actively rewrites ARP caches on " + self.Name +
			"; use only on a network you own or are authorized to test")
		sp, err := spoof.Start(ctx, self, cfg.ScanCIDR, state)
		if err != nil {
			return fmt.Errorf("spoof: %w", err)
		}
		defer sp.Stop()
	}

	srv := web.New(cfg.Listen, state)
	srvErr := srv.Start()
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	slog.Info("dashboard serving", "addr", cfg.Listen, "spoof", cfg.Spoof)

	capErr := make(chan error, 1)
	go func() {
		capErr <- capture.Run(ctx, capture.Options{
			Iface: cfg.Iface, Snaplen: cfg.Snaplen, ReadFile: cfg.ReadFile, PcapOut: cfg.PcapOut,
		}, state)
	}()

	select {
	case err := <-srvErr:
		return fmt.Errorf("dashboard: %w", err)
	case err := <-capErr:
		if err != nil {
			return err
		}
		if cfg.Offline() && ctx.Err() == nil {
			slog.Info("finished replay; dashboard still serving (Ctrl-C to quit)", "addr", cfg.Listen)
			<-ctx.Done()
		}
		return nil
	case <-ctx.Done():
		return nil
	}
}

func ipStr(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
