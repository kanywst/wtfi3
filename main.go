// wtfi3 - WiFi flow visualizer.
//
// Visualize the traffic on a WiFi network you administer. Two modes:
//   - passive: your own Mac's traffic plus broadcast/multicast only.
//   - spoof:   ARP-spoof the LAN so every device's flows transit this host.
//
// TLS payloads are never decrypted. What you see is metadata: who talks to
// whom, how much, over which protocol, and to which hostname (via DNS/SNI).
//
// Usage:
//
//	go build -o wtfi3 .
//	sudo ./wtfi3 -i en0                      # passive
//	sudo ./wtfi3 -i en0 -spoof               # ARP-spoof MITM (own network only)
//	sudo ./wtfi3 -i en0 -spoof -w cap.pcap   # also dump packets for Wireshark
//	→ http://localhost:8080
//
// Vendor names come from the embedded IEEE OUI database (web/oui.tsv, ~52k).
package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
)

// version is injected at build time via -ldflags "-X main.version=...".
var version = "dev"

//go:embed web/index.html
var webFS embed.FS

var (
	iface    = flag.String("i", "en0", "capture interface")
	listen   = flag.String("listen", ":8080", "dashboard listen address")
	doSpoof  = flag.Bool("spoof", false, "ARP-spoof the LAN to capture other devices' flows (own network only)")
	snaplen  = flag.Int("snaplen", 262144, "capture snaplen")
	scanCIDR = flag.String("scan", "", "override LAN CIDR to scan for spoofing (auto if empty)")
	pcapOut  = flag.String("w", "", "also write captured packets to this .pcap file (open in Wireshark)")
	readFile = flag.String("r", "", "read packets from a .pcap file instead of a live interface (no root needed)")
	showVer  = flag.Bool("version", false, "print version and exit")
)

func main() {
	flag.Parse()
	if *showVer {
		fmt.Printf("wtfi3 %s\n", version)
		return
	}
	offline := *readFile != ""
	if !offline && os.Geteuid() != 0 {
		log.Fatal("live packet capture requires root: sudo ./wtfi3 ...  (or use -r file.pcap)")
	}

	self, err := ifaceInfo(*iface)
	if err != nil {
		if !offline {
			log.Fatalf("interface %s: %v", *iface, err)
		}
		// Offline replay can proceed without a live interface; subnet context
		// (for LAN-device attribution) is simply unavailable.
		self = &SelfInfo{Name: *iface}
		log.Printf("offline mode: interface %s unavailable, LAN attribution limited", *iface)
	}
	log.Printf("wtfi3 %s on %s ip=%s mac=%s gateway=%s", version, self.Name, self.IP, self.MAC, self.Gateway)

	st := newState(self)

	var handle *pcap.Handle
	if offline {
		handle, err = pcap.OpenOffline(*readFile)
	} else {
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatalf("pcap open: %v", err)
	}
	defer handle.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	if *doSpoof && !offline {
		spoofer, err := startSpoof(self, *scanCIDR, st)
		if err != nil {
			log.Fatalf("spoof: %v", err)
		}
		defer spoofer.Stop()
	}

	// optional pcap dump for later analysis in Wireshark
	var pcapW *pcapgo.Writer
	if *pcapOut != "" {
		f, err := os.Create(*pcapOut)
		if err != nil {
			log.Fatalf("open pcap %s: %v", *pcapOut, err)
		}
		defer func() { _ = f.Close() }()
		pcapW = pcapgo.NewWriter(f)
		if err := pcapW.WriteFileHeader(uint32(*snaplen), handle.LinkType()); err != nil {
			log.Fatalf("pcap header: %v", err)
		}
		log.Printf("writing packets to %s", *pcapOut)
	}

	go serveDashboard(st)
	go st.evictLoop()
	go st.sampleLoop()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.Lazy = true
	source.NoCopy = true
	pkts := source.Packets()

	log.Printf("capturing... dashboard: http://localhost%s  (spoof=%v)", *listen, *doSpoof)
	var pcapErrLogged bool
	for {
		select {
		case <-sig:
			log.Println("shutting down...")
			return
		case p, ok := <-pkts:
			if !ok {
				if offline {
					log.Printf("finished replaying %s; dashboard still serving on %s (Ctrl-C to quit)", *readFile, *listen)
					<-sig
				}
				return
			}
			if pcapW != nil {
				if err := pcapW.WritePacket(p.Metadata().CaptureInfo, p.Data()); err != nil && !pcapErrLogged {
					log.Printf("pcap write error (further errors suppressed): %v", err)
					pcapErrLogged = true
				}
			}
			st.consume(p)
		}
	}
}

// ---------- interface / network info ----------

type SelfInfo struct {
	Name    string
	IP      net.IP
	MAC     net.HardwareAddr
	Mask    net.IPMask
	Gateway net.IP
	GwMAC   net.HardwareAddr
}

func ifaceInfo(name string) (*SelfInfo, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, _ := ifc.Addrs()
	var ip net.IP
	var mask net.IPMask
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			ip = ipn.IP.To4()
			mask = ipn.Mask
			break
		}
	}
	if ip == nil {
		return nil, fmt.Errorf("no IPv4 address")
	}
	return &SelfInfo{Name: name, IP: ip, MAC: ifc.HardwareAddr, Mask: mask, Gateway: defaultGateway()}, nil
}

func defaultGateway() net.IP {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "gateway:" {
			return net.ParseIP(fields[1]).To4()
		}
	}
	return nil
}

// ---------- aggregated state ----------

type Device struct {
	IP       string    `json:"ip"`
	MAC      string    `json:"mac"`
	Vendor   string    `json:"vendor"`
	RxBytes  uint64    `json:"rx_bytes"` // toward this device
	TxBytes  uint64    `json:"tx_bytes"` // from this device
	Packets  uint64    `json:"packets"`
	LastSeen time.Time `json:"last_seen"`
}

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

type DNSEntry struct {
	Client string    `json:"client"`
	Name   string    `json:"name"`
	Type   string    `json:"type"`
	Answer string    `json:"answer,omitempty"`
	Time   time.Time `json:"time"`
}

type State struct {
	mu      sync.Mutex
	self    *SelfInfo
	subnet  *net.IPNet
	bcast   net.IP                      // subnet broadcast address
	arp     map[string]net.HardwareAddr // ip -> mac (learned)
	devices map[string]*Device          // key: LAN IP
	flows   map[string]*Flow            // key: src|dst|proto|dport
	dns     []DNSEntry                  // ring buffer
	spoofed map[string]bool             // IPs currently being spoofed
	total   uint64
	lastTot uint64    // total at previous sample
	series  []float64 // bytes/sec, ring of 120 (last 2 min)
	start   time.Time
}

func newState(self *SelfInfo) *State {
	s := &State{
		self:    self,
		arp:     map[string]net.HardwareAddr{},
		devices: map[string]*Device{},
		flows:   map[string]*Flow{},
		spoofed: map[string]bool{},
		start:   time.Now(),
	}
	if self.Mask != nil {
		s.subnet = &net.IPNet{IP: self.IP.Mask(self.Mask), Mask: self.Mask}
		s.bcast = broadcastOf(s.subnet)
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

// isLANHost reports whether ip is a real host on our subnet (not the network
// address, broadcast, or a multicast group).
func (s *State) isLANHost(ip net.IP) bool {
	if ip == nil || s.subnet == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil || !s.subnet.Contains(v4) {
		return false
	}
	return !v4.Equal(s.bcast) && !v4.Equal(s.subnet.IP) && !v4.IsMulticast()
}

// setARP records an ip->mac mapping. Safe to call from other goroutines.
func (s *State) setARP(ip net.IP, mac net.HardwareAddr) {
	v4 := ip.To4()
	if v4 == nil || len(mac) != 6 {
		return
	}
	s.mu.Lock()
	s.arp[v4.String()] = append(net.HardwareAddr(nil), mac...)
	s.mu.Unlock()
}

func (s *State) consume(p gopacket.Packet) {
	eth, _ := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	// In spoof mode a relayed packet is captured twice (target->us and us->gw).
	// Count only the leg destined to us at L2, so bytes and flows are not doubled.
	if *doSpoof && eth != nil && !bytes.Equal(eth.DstMAC, s.self.MAC) {
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

	// Learn MAC of LAN hosts we see sourcing frames directly (passive discovery).
	if eth != nil && s.isLANHost(srcIP) {
		if _, ok := s.arp[srcIP.To4().String()]; !ok {
			s.arp[srcIP.To4().String()] = append(net.HardwareAddr(nil), eth.SrcMAC...)
		}
	}

	// Attribute bytes to LAN devices by IP (works even when MITM rewrites MACs).
	if s.isLANHost(srcIP) {
		s.touchDevice(srcIP, size, true)
	}
	if s.isLANHost(dstIP) {
		s.touchDevice(dstIP, size, false)
	}

	// transport / flow
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

	// DNS responses reveal what a client looked up.
	if dns, ok := p.Layer(layers.LayerTypeDNS).(*layers.DNS); ok && dns.QR {
		s.recordDNS(dstIP, dns)
	}
	// TLS SNI from ClientHello (tcp 443/8443) reveals the destination hostname.
	if proto == "tcp" && (dport == 443 || dport == 8443) {
		if app := p.ApplicationLayer(); app != nil {
			if sni := parseSNI(app.Payload()); sni != "" {
				f.SNI = sni
			}
		}
	}
}

// touchDevice updates a LAN device keyed by IP. Caller holds s.mu.
func (s *State) touchDevice(ip net.IP, size uint64, isSrc bool) {
	key := ip.To4().String()
	d := s.devices[key]
	if d == nil {
		d = &Device{IP: key}
		s.devices[key] = d
	}
	if d.MAC == "" {
		if mac, ok := s.arp[key]; ok {
			d.MAC = mac.String()
			d.Vendor = vendorLookup(d.MAC)
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

func (s *State) evictLoop() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for range t.C {
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

// sampleLoop records throughput (bytes/sec) once per second into a 120-slot
// ring so the dashboard can draw a live bandwidth graph.
func (s *State) sampleLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
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

// ---------- dashboard ----------

type snapshot struct {
	Iface     string     `json:"iface"`
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
	Series    []float64  `json:"series"` // bytes/sec, last 120s
}

func (s *State) snapshot() snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := snapshot{
		Iface: s.self.Name, SelfIP: s.self.IP.String(), Version: version, Spoof: *doSpoof,
		Uptime: time.Since(s.start).Seconds(), TotalMB: float64(s.total) / 1e6,
	}
	if s.self.Gateway != nil {
		snap.Gateway = s.self.Gateway.String()
	}
	for _, d := range s.devices {
		snap.Devices = append(snap.Devices, d)
	}
	sort.Slice(snap.Devices, func(i, j int) bool {
		return snap.Devices[i].TxBytes+snap.Devices[i].RxBytes > snap.Devices[j].TxBytes+snap.Devices[j].RxBytes
	})
	for _, f := range s.flows {
		snap.Flows = append(snap.Flows, f)
	}
	sort.Slice(snap.Flows, func(i, j int) bool { return snap.Flows[i].Bytes > snap.Flows[j].Bytes })
	if len(snap.Flows) > 200 {
		snap.Flows = snap.Flows[:200]
	}
	for i := len(s.dns) - 1; i >= 0 && len(snap.DNS) < 100; i-- { // newest first
		snap.DNS = append(snap.DNS, s.dns[i])
	}
	for ip := range s.spoofed {
		snap.SpoofList = append(snap.SpoofList, ip)
	}
	sort.Strings(snap.SpoofList)
	snap.Series = append([]float64(nil), s.series...)
	return snap
}

func serveDashboard(s *State) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := webFS.ReadFile("web/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/api/state", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.snapshot())
	})
	log.Fatal(http.ListenAndServe(*listen, mux))
}
