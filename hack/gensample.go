//go:build ignore

// gensample writes a small synthetic capture to the path given as the first
// argument (default sample.pcap). It is a developer aid for exercising the
// offline replay path (`wtfi3 -r`) without needing root or a live network.
//
//	go run hack/gensample.go /tmp/sample.pcap
package main

import (
	"bytes"
	"log"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
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

func tcpPkt(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, dport layers.TCPPort, payload []byte) []byte {
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: srcIP, DstIP: dstIP}
	tcp := &layers.TCP{SrcPort: 40000, DstPort: dport}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, tcp, gopacket.Payload(payload))
	return buf.Bytes()
}

func dnsResp(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, name, answer string) []byte {
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: srcIP, DstIP: dstIP}
	udp := &layers.UDP{SrcPort: 53, DstPort: 51000}
	udp.SetNetworkLayerForChecksum(ip)
	dns := &layers.DNS{
		QR: true, ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
		Answers:   []layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, IP: net.ParseIP(answer)}},
	}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		eth, ip, udp, dns)
	return buf.Bytes()
}

func main() {
	out := "sample.pcap"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	f, err := os.Create(out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	me := net.HardwareAddr{0xde, 0xf9, 0xc5, 0x00, 0x00, 0x01}
	phone := net.HardwareAddr{0x3c, 0x22, 0xfb, 0xaa, 0xbb, 0xcc} // Apple
	tv := net.HardwareAddr{0xb8, 0x27, 0xeb, 0x11, 0x22, 0x33}    // Raspberry Pi
	gw := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	phoneIP := net.IPv4(192, 168, 0, 20)
	tvIP := net.IPv4(192, 168, 0, 31)
	router := net.IPv4(192, 168, 0, 1)

	pkts := [][]byte{
		tcpPkt(phone, me, phoneIP, net.IPv4(93, 184, 216, 34), 443, clientHello("www.youtube.com")),
		tcpPkt(phone, me, phoneIP, net.IPv4(93, 184, 216, 34), 443, bytes.Repeat([]byte{0}, 1400)),
		tcpPkt(tv, me, tvIP, net.IPv4(140, 82, 121, 4), 443, clientHello("api.netflix.com")),
		tcpPkt(tv, me, tvIP, net.IPv4(140, 82, 121, 4), 443, bytes.Repeat([]byte{0}, 800)),
		dnsResp(gw, me, router, phoneIP, "www.youtube.com", "142.250.196.142"),
		dnsResp(gw, me, router, tvIP, "api.netflix.com", "44.242.61.10"),
	}
	ts := time.Now()
	for i, b := range pkts {
		ci := gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * time.Millisecond), CaptureLength: len(b), Length: len(b)}
		if err := w.WritePacket(ci, b); err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("wrote %d packets to %s", len(pkts), out)
}
