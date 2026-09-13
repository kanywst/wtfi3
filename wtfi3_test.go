package main

import (
	"bytes"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// clientHello builds a minimal but valid TLS ClientHello record carrying the
// given SNI host, so parseSNI can be exercised end to end.
func clientHello(host string) []byte {
	name := []byte(host)
	var list bytes.Buffer
	list.WriteByte(0x00) // name type: host_name
	list.Write([]byte{byte(len(name) >> 8), byte(len(name))})
	list.Write(name)

	var snList bytes.Buffer
	snList.Write([]byte{byte(list.Len() >> 8), byte(list.Len())})
	snList.Write(list.Bytes())

	var exts bytes.Buffer
	exts.Write([]byte{0x00, 0x00}) // extension type: server_name
	exts.Write([]byte{byte(snList.Len() >> 8), byte(snList.Len())})
	exts.Write(snList.Bytes())

	var hb bytes.Buffer
	hb.Write([]byte{0x03, 0x03}) // client version
	hb.Write(make([]byte, 32))   // random
	hb.WriteByte(0x00)           // session id len
	hb.Write([]byte{0x00, 0x02, 0x00, 0x2f})
	hb.Write([]byte{0x01, 0x00}) // compression methods
	hb.Write([]byte{byte(exts.Len() >> 8), byte(exts.Len())})
	hb.Write(exts.Bytes())

	var hs bytes.Buffer
	hs.WriteByte(0x01) // handshake type: ClientHello
	hs.Write([]byte{byte(hb.Len() >> 16), byte(hb.Len() >> 8), byte(hb.Len())})
	hs.Write(hb.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(0x16)           // content type: handshake
	rec.Write([]byte{0x03, 0x01}) // record version
	rec.Write([]byte{byte(hs.Len() >> 8), byte(hs.Len())})
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func TestParseSNI(t *testing.T) {
	if got := parseSNI(clientHello("example.com")); got != "example.com" {
		t.Fatalf("parseSNI = %q, want example.com", got)
	}
	if got := parseSNI([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 1, 0}); got != "" {
		t.Fatalf("parseSNI(junk) = %q, want empty", got)
	}
	if got := parseSNI(nil); got != "" {
		t.Fatalf("parseSNI(nil) = %q, want empty", got)
	}
}

func TestVendorLookup(t *testing.T) {
	if got := vendorLookup("b8:27:eb:11:22:33"); got == "" || got[:9] != "Raspberry" {
		t.Fatalf("vendorLookup(rpi) = %q", got)
	}
	if got := vendorLookup("00:00:00:00:00:01"); got != "Xerox" {
		t.Fatalf("vendorLookup(xerox) = %q", got)
	}
	if got := vendorLookup("06:11:22:33:44:55"); got != "randomized?" {
		t.Fatalf("vendorLookup(local) = %q, want randomized?", got)
	}
}

func TestBroadcastAndLANHost(t *testing.T) {
	_, n, _ := net.ParseCIDR("192.168.0.0/24")
	if got := broadcastOf(n).String(); got != "192.168.0.255" {
		t.Fatalf("broadcast = %s, want 192.168.0.255", got)
	}
	self := &SelfInfo{Name: "en0", IP: net.IPv4(192, 168, 0, 15).To4(), Mask: n.Mask}
	st := newState(self)
	cases := map[string]bool{
		"192.168.0.20":  true,
		"192.168.0.15":  true,
		"192.168.0.0":   false, // network
		"192.168.0.255": false, // broadcast
		"8.8.8.8":       false, // internet
		"224.0.0.251":   false, // multicast
	}
	for ip, want := range cases {
		if got := st.isLANHost(net.ParseIP(ip)); got != want {
			t.Errorf("isLANHost(%s) = %v, want %v", ip, got, want)
		}
	}
}

// synthPkt assembles and decodes an Ethernet/IPv4/TCP packet with the given
// application payload, mirroring what the live capture would hand consume().
func synthPkt(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, dport layers.TCPPort, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: dport, SYN: false}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestConsumeAttribution(t *testing.T) {
	_, n, _ := net.ParseCIDR("192.168.0.0/24")
	me := net.HardwareAddr{0xde, 0xf9, 0xc5, 0x00, 0x00, 0x01}
	phone := net.HardwareAddr{0x3c, 0x22, 0xfb, 0xaa, 0xbb, 0xcc} // Apple OUI
	self := &SelfInfo{Name: "en0", IP: net.IPv4(192, 168, 0, 15).To4(), MAC: me, Mask: n.Mask}
	st := newState(self)

	phoneIP := net.IPv4(192, 168, 0, 20).To4()
	dstIP := net.IPv4(93, 184, 216, 34).To4()
	pkt := synthPkt(t, phone, me, phoneIP, dstIP, 443, clientHello("example.com"))
	st.consume(pkt)

	snap := st.snapshot()
	if len(snap.Devices) != 1 {
		t.Fatalf("devices = %d, want 1 (LAN host only)", len(snap.Devices))
	}
	d := snap.Devices[0]
	if d.IP != "192.168.0.20" || d.MAC != phone.String() {
		t.Fatalf("device = %+v", d)
	}
	if d.Vendor != "Apple, Inc." && d.Vendor[:5] != "Apple" {
		t.Fatalf("vendor = %q, want Apple*", d.Vendor)
	}
	if d.TxBytes == 0 {
		t.Fatalf("tx not attributed to phone")
	}
	var found bool
	for _, f := range snap.Flows {
		if f.SNI == "example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("SNI example.com not captured in flows")
	}
}

func TestSpoofDedupFilter(t *testing.T) {
	*doSpoof = true
	defer func() { *doSpoof = false }()
	_, n, _ := net.ParseCIDR("192.168.0.0/24")
	me := net.HardwareAddr{0xde, 0xf9, 0xc5, 0x00, 0x00, 0x01}
	other := net.HardwareAddr{0x3c, 0x22, 0xfb, 0xaa, 0xbb, 0xcc}
	self := &SelfInfo{Name: "en0", IP: net.IPv4(192, 168, 0, 15).To4(), MAC: me, Mask: n.Mask}
	st := newState(self)

	phoneIP := net.IPv4(192, 168, 0, 20).To4()
	dstIP := net.IPv4(93, 184, 216, 34).To4()
	// Ingress leg (dst MAC == us): must be counted.
	st.consume(synthPkt(t, other, me, phoneIP, dstIP, 443, []byte("x")))
	// Forwarded leg (src MAC == us, dst MAC == gateway): must be skipped.
	gw := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	st.consume(synthPkt(t, me, gw, phoneIP, dstIP, 443, []byte("x")))

	snap := st.snapshot()
	if len(snap.Flows) != 1 {
		t.Fatalf("flows = %d, want 1 (forwarded leg deduped)", len(snap.Flows))
	}
	if snap.Flows[0].Packets != 1 {
		t.Fatalf("packets = %d, want 1 (not double counted)", snap.Flows[0].Packets)
	}
}
