package aggregator

import (
	"bytes"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"wtfi3/internal/netinfo"
)

func clientHello(host string) []byte {
	name := []byte(host)
	var list bytes.Buffer
	list.WriteByte(0x00)
	list.Write([]byte{byte(len(name) >> 8), byte(len(name))})
	list.Write(name)
	var snList bytes.Buffer
	snList.Write([]byte{byte(list.Len() >> 8), byte(list.Len())})
	snList.Write(list.Bytes())
	var exts bytes.Buffer
	exts.Write([]byte{0x00, 0x00})
	exts.Write([]byte{byte(snList.Len() >> 8), byte(snList.Len())})
	exts.Write(snList.Bytes())
	var hb bytes.Buffer
	hb.Write([]byte{0x03, 0x03})
	hb.Write(make([]byte, 32))
	hb.WriteByte(0x00)
	hb.Write([]byte{0x00, 0x02, 0x00, 0x2f})
	hb.Write([]byte{0x01, 0x00})
	hb.Write([]byte{byte(exts.Len() >> 8), byte(exts.Len())})
	hb.Write(exts.Bytes())
	var hs bytes.Buffer
	hs.WriteByte(0x01)
	hs.Write([]byte{byte(hb.Len() >> 16), byte(hb.Len() >> 8), byte(hb.Len())})
	hs.Write(hb.Bytes())
	var rec bytes.Buffer
	rec.WriteByte(0x16)
	rec.Write([]byte{0x03, 0x01})
	rec.Write([]byte{byte(hs.Len() >> 8), byte(hs.Len())})
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func synthPkt(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, dport layers.TCPPort, payload []byte) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: dport}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func testSelf() *netinfo.Self {
	_, n, _ := net.ParseCIDR("192.168.0.0/24")
	return &netinfo.Self{
		Name: "en0", IP: net.IPv4(192, 168, 0, 15).To4(),
		MAC: net.HardwareAddr{0xde, 0xf9, 0xc5, 0x00, 0x00, 0x01}, Mask: n.Mask,
	}
}

func TestBroadcastAndLANHost(t *testing.T) {
	_, n, _ := net.ParseCIDR("192.168.0.0/24")
	if got := broadcastOf(n).String(); got != "192.168.0.255" {
		t.Fatalf("broadcast = %s, want 192.168.0.255", got)
	}
	st := New(testSelf(), false, "test")
	cases := map[string]bool{
		"192.168.0.20": true, "192.168.0.15": true,
		"192.168.0.0": false, "192.168.0.255": false, "8.8.8.8": false, "224.0.0.251": false,
	}
	for ip, want := range cases {
		if got := st.isLANHost(net.ParseIP(ip)); got != want {
			t.Errorf("isLANHost(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestConsumeAttribution(t *testing.T) {
	self := testSelf()
	phone := net.HardwareAddr{0x3c, 0x22, 0xfb, 0xaa, 0xbb, 0xcc} // Apple OUI
	st := New(self, false, "test")

	phoneIP := net.IPv4(192, 168, 0, 20).To4()
	dstIP := net.IPv4(93, 184, 216, 34).To4()
	st.Consume(synthPkt(t, phone, self.MAC, phoneIP, dstIP, 443, clientHello("example.com")))

	snap := st.Snapshot()
	if len(snap.Devices) != 1 {
		t.Fatalf("devices = %d, want 1", len(snap.Devices))
	}
	d := snap.Devices[0]
	if d.IP != "192.168.0.20" || d.MAC != phone.String() {
		t.Fatalf("device = %+v", d)
	}
	if len(d.Vendor) < 5 || d.Vendor[:5] != "Apple" {
		t.Fatalf("vendor = %q, want Apple*", d.Vendor)
	}
	if d.TxBytes == 0 {
		t.Fatalf("tx not attributed")
	}
	var found bool
	for _, f := range snap.Flows {
		if f.SNI == "example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("SNI example.com not captured")
	}
}

func TestSpoofDedupFilter(t *testing.T) {
	self := testSelf()
	st := New(self, true, "test") // spoof mode
	other := net.HardwareAddr{0x3c, 0x22, 0xfb, 0xaa, 0xbb, 0xcc}
	gw := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	phoneIP := net.IPv4(192, 168, 0, 20).To4()
	dstIP := net.IPv4(93, 184, 216, 34).To4()

	// Ingress leg (dst MAC == us): counted.
	st.Consume(synthPkt(t, other, self.MAC, phoneIP, dstIP, 443, []byte("x")))
	// Forwarded leg (src MAC == us): skipped.
	st.Consume(synthPkt(t, self.MAC, gw, phoneIP, dstIP, 443, []byte("x")))

	snap := st.Snapshot()
	if len(snap.Flows) != 1 {
		t.Fatalf("flows = %d, want 1 (forwarded leg deduped)", len(snap.Flows))
	}
	if snap.Flows[0].Packets != 1 {
		t.Fatalf("packets = %d, want 1", snap.Flows[0].Packets)
	}
}
