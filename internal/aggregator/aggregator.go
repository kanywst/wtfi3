// Package aggregator turns decoded packets into the device/flow/DNS/throughput
// state that the dashboard renders. It is the domain core and has no knowledge
// of capture or HTTP.
package aggregator

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"wtfi3/internal/netinfo"
	"wtfi3/internal/oui"
	"wtfi3/internal/tlsmeta"
)

// Device is a LAN host keyed by IP.
type Device struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	Vendor    string    `json:"vendor"`
	RxBytes   uint64    `json:"rx_bytes"`
	TxBytes   uint64    `json:"tx_bytes"`
	Packets   uint64    `json:"packets"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	New       bool      `json:"new,omitempty"` // arrived after the initial baseline, still recent
}

const (
	// newDeviceGrace treats every device discovered in the first moments after
	// startup as the baseline (not an alert): those were already on the network.
	newDeviceGrace = 20 * time.Second
	// newDeviceWindow is how long a genuinely-new arrival stays flagged.
	newDeviceWindow = 90 * time.Second
)

// Flow is a unidirectional conversation summary.
type Flow struct {
	Key      string    `json:"key"`
	Src      string    `json:"src"`
	Dst      string    `json:"dst"`
	Proto    string    `json:"proto"`
	DstPort  uint16    `json:"dst_port"`
	Bytes    uint64    `json:"bytes"`
	Packets  uint64    `json:"packets"`
	SNI      string    `json:"sni,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

// DNSEntry is one observed DNS response.
type DNSEntry struct {
	Client string    `json:"client"`
	Name   string    `json:"name"`
	Type   string    `json:"type"`
	Answer string    `json:"answer,omitempty"`
	Time   time.Time `json:"time"`
}

// WiFiInfo reports the wireless network the capture interface is on. SSID and
// BSSID are empty when the OS withholds them (macOS gates them behind Location
// Services); Redacted distinguishes "withheld" from "not connected".
type WiFiInfo struct {
	Connected bool   `json:"connected"`
	SSID      string `json:"ssid,omitempty"`
	BSSID     string `json:"bssid,omitempty"`
	Security  string `json:"security,omitempty"`
	Redacted  bool   `json:"redacted,omitempty"`
}

// Snapshot is an immutable view served to the dashboard.
type Snapshot struct {
	Iface     string     `json:"iface"`
	WiFi      *WiFiInfo  `json:"wifi,omitempty"`
	SelfIP    string     `json:"self_ip"`
	Gateway   string     `json:"gateway"`
	Version   string     `json:"version"`
	Spoof     bool       `json:"spoof"`
	Uptime    float64    `json:"uptime_sec"`
	TotalMB   float64    `json:"total_mb"`
	Devices   []*Device  `json:"devices"`
	Flows     []*Flow    `json:"flows"`
	DNS       []DNSEntry `json:"dns"`
	SpoofList []string   `json:"spoof_list"`
	Series    []float64  `json:"series"`
}

// State is the concurrency-safe aggregate. All exported methods are safe for
// concurrent use.
// lanNet is an on-link prefix plus its IPv4 broadcast address (nil for IPv6).
type lanNet struct {
	net   *net.IPNet
	bcast net.IP
}

type State struct {
	mu      sync.Mutex
	self    *netinfo.Self
	spoof   bool
	version string
	nets    []lanNet
	arp     map[string]net.HardwareAddr
	devices map[string]*Device
	flows   map[string]*Flow
	dns     []DNSEntry
	spoofed map[string]bool
	total   uint64
	lastTot uint64
	series  []float64
	start   time.Time
}

// New builds a State for the given host. spoof enables the MITM de-duplication
// filter; version is reported in snapshots.
func New(self *netinfo.Self, spoof bool, version string) *State {
	s := &State{
		self:    self,
		spoof:   spoof,
		version: version,
		arp:     map[string]net.HardwareAddr{},
		devices: map[string]*Device{},
		flows:   map[string]*Flow{},
		spoofed: map[string]bool{},
		start:   time.Now(),
	}
	for _, n := range self.Nets {
		ln := lanNet{net: &net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}}
		if n.IP.To4() != nil {
			ln.bcast = broadcastOf(ln.net)
		}
		s.nets = append(s.nets, ln)
	}
	return s
}

func broadcastOf(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil {
		return nil
	}
	b := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		b[i] = ip[i] | ^n.Mask[i]
	}
	return b
}

// isLANHost reports whether ip is a real routable host on one of our on-link
// prefixes (IPv4 or IPv6), excluding the network address, IPv4 broadcast,
// multicast, and link-local addresses. Link-local is excluded because every
// IPv6 host also auto-configures an fe80::/64 address, which would otherwise
// fragment a single device into several rows. (A dual-stack device can still
// appear as one IPv4 and one global-IPv6 row; correlating those needs NDP/DHCP
// state we do not track.)
func (s *State) isLANHost(ip net.IP) bool {
	if ip == nil || ip.IsMulticast() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, ln := range s.nets {
		if !ln.net.Contains(ip) {
			continue
		}
		if ip.Equal(ln.net.IP) || (ln.bcast != nil && ip.Equal(ln.bcast)) {
			return false
		}
		return true
	}
	return false
}

// SetARP records an ip->mac mapping learned by another goroutine (spoofer).
func (s *State) SetARP(ip net.IP, mac net.HardwareAddr) {
	if ip == nil || len(mac) != 6 {
		return
	}
	s.mu.Lock()
	s.arp[ip.String()] = append(net.HardwareAddr(nil), mac...)
	s.mu.Unlock()
}

// LookupARP returns a learned MAC for ip.
func (s *State) LookupARP(ip net.IP) (net.HardwareAddr, bool) {
	if ip == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	mac, ok := s.arp[ip.String()]
	return mac, ok
}

// MarkSpoofed records that an IP is currently being spoofed (for the dashboard).
func (s *State) MarkSpoofed(ip net.IP) {
	v4 := ip.To4()
	if v4 == nil {
		return
	}
	s.mu.Lock()
	s.spoofed[v4.String()] = true
	s.mu.Unlock()
}

// Consume folds one captured packet into the state. It satisfies the capture
// package's Consumer interface.
func (s *State) Consume(p gopacket.Packet) {
	eth, _ := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	// In spoof mode a relayed packet is captured twice (target->us and us->gw).
	// Count only the leg destined to us at L2 so bytes and flows are not doubled.
	if s.spoof && eth != nil && !bytes.Equal(eth.DstMAC, s.self.MAC) {
		return
	}

	var srcIP, dstIP net.IP
	if ip4, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		srcIP, dstIP = ip4.SrcIP, ip4.DstIP
	} else if ip6, ok := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		srcIP, dstIP = ip6.SrcIP, ip6.DstIP
	} else {
		return
	}
	size := uint64(len(p.Data()))

	s.mu.Lock()
	defer s.mu.Unlock()
	s.total += size

	if eth != nil && s.isLANHost(srcIP) {
		if k := srcIP.String(); s.arp[k] == nil {
			s.arp[k] = append(net.HardwareAddr(nil), eth.SrcMAC...)
		}
	}
	if s.isLANHost(srcIP) {
		s.touchDevice(srcIP, size, true)
	}
	if s.isLANHost(dstIP) {
		s.touchDevice(dstIP, size, false)
	}

	proto := "other"
	var dport uint16
	if tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		proto, dport = "tcp", uint16(tcp.DstPort)
	} else if udp, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		proto, dport = "udp", uint16(udp.DstPort)
	} else if _, ok := p.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
		proto = "icmp"
	}

	fk := fmt.Sprintf("%s|%s|%s|%d", srcIP, dstIP, proto, dport)
	f := s.flows[fk]
	if f == nil {
		f = &Flow{Key: fk, Src: srcIP.String(), Dst: dstIP.String(), Proto: proto, DstPort: dport}
		s.flows[fk] = f
	}
	f.Bytes += size
	f.Packets++
	f.LastSeen = time.Now()

	if dns, ok := p.Layer(layers.LayerTypeDNS).(*layers.DNS); ok && dns.QR {
		s.recordDNS(dstIP, dns)
	}
	if proto == "tcp" && (dport == 443 || dport == 8443) {
		if app := p.ApplicationLayer(); app != nil {
			if sni := tlsmeta.SNI(app.Payload()); sni != "" {
				f.SNI = sni
			}
		}
	}
}

// touchDevice updates a LAN device keyed by IP. Caller holds s.mu.
func (s *State) touchDevice(ip net.IP, size uint64, isSrc bool) {
	key := ip.String()
	d := s.devices[key]
	if d == nil {
		d = &Device{IP: key, FirstSeen: time.Now()}
		s.devices[key] = d
	}
	if d.MAC == "" {
		if mac, ok := s.arp[key]; ok {
			d.MAC = mac.String()
			d.Vendor = oui.Lookup(d.MAC)
		}
	}
	d.Packets++
	d.LastSeen = time.Now()
	if isSrc {
		d.TxBytes += size
	} else {
		d.RxBytes += size
	}
}

func (s *State) recordDNS(client net.IP, dns *layers.DNS) {
	for _, q := range dns.Questions {
		e := DNSEntry{Client: client.String(), Name: string(q.Name), Type: q.Type.String(), Time: time.Now()}
		for _, a := range dns.Answers {
			if a.IP != nil {
				e.Answer = a.IP.String()
				break
			}
			if len(a.CNAME) > 0 {
				e.Answer = string(a.CNAME)
			}
		}
		s.dns = append(s.dns, e)
		if len(s.dns) > 500 {
			s.dns = s.dns[len(s.dns)-500:]
		}
	}
}

// isNewArrival reports whether a device should be flagged as a new arrival: it
// was first seen after the initial baseline window (so the hosts already on the
// network at startup are not all flagged) and only recently. Caller holds s.mu.
func (s *State) isNewArrival(d *Device) bool {
	return d.FirstSeen.After(s.start.Add(newDeviceGrace)) &&
		time.Since(d.FirstSeen) < newDeviceWindow
}

// Snapshot returns a sorted, bounded, copy-safe view of the current state.
func (s *State) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := Snapshot{
		Iface: s.self.Name, SelfIP: s.self.IP.String(), Version: s.version, Spoof: s.spoof,
		Uptime: time.Since(s.start).Seconds(), TotalMB: float64(s.total) / 1e6,
	}
	if s.self.Gateway != nil {
		snap.Gateway = s.self.Gateway.String()
	}
	if w := s.self.WiFi; w != nil {
		snap.WiFi = &WiFiInfo{
			Connected: w.Connected, SSID: w.SSID, BSSID: w.BSSID,
			Security: w.Security, Redacted: w.Redacted,
		}
	}
	for _, d := range s.devices {
		d.New = s.isNewArrival(d)
		snap.Devices = append(snap.Devices, d)
	}
	sortByTotal(snap.Devices)
	for _, f := range s.flows {
		snap.Flows = append(snap.Flows, f)
	}
	sortByBytes(snap.Flows)
	if len(snap.Flows) > 200 {
		snap.Flows = snap.Flows[:200]
	}
	for i := len(s.dns) - 1; i >= 0 && len(snap.DNS) < 100; i-- {
		snap.DNS = append(snap.DNS, s.dns[i])
	}
	for ip := range s.spoofed {
		snap.SpoofList = append(snap.SpoofList, ip)
	}
	sortStrings(snap.SpoofList)
	snap.Series = append([]float64(nil), s.series...)
	return snap
}

func sortByTotal(d []*Device) {
	sort.Slice(d, func(i, j int) bool {
		return d[i].TxBytes+d[i].RxBytes > d[j].TxBytes+d[j].RxBytes
	})
}

func sortByBytes(f []*Flow) {
	sort.Slice(f, func(i, j int) bool { return f[i].Bytes > f[j].Bytes })
}

func sortStrings(s []string) { sort.Strings(s) }

// refreshWiFi re-reads the wireless association so the dashboard follows a roam
// to a different SSID. It is a no-op on wired interfaces and offline replay.
func (s *State) refreshWiFi() {
	s.mu.Lock()
	wireless, name := s.self.WiFi != nil, s.self.Name
	s.mu.Unlock()
	if !wireless {
		return
	}
	w := netinfo.LookupWiFi(name) // exec, so outside the lock
	if w == nil {
		return
	}
	s.mu.Lock()
	s.self.WiFi = w
	s.mu.Unlock()
}

// EvictLoop drops flows idle for more than two minutes until ctx is canceled.
func (s *State) EvictLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refreshWiFi()
			cut := time.Now().Add(-2 * time.Minute)
			s.mu.Lock()
			for k, f := range s.flows {
				if f.LastSeen.Before(cut) {
					delete(s.flows, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

// SampleLoop records bytes/sec once per second into a 120-slot ring until ctx
// is canceled.
func (s *State) SampleLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			delta := float64(s.total - s.lastTot)
			s.lastTot = s.total
			s.series = append(s.series, delta)
			if len(s.series) > 120 {
				s.series = s.series[len(s.series)-120:]
			}
			s.mu.Unlock()
		}
	}
}
