package tlsmeta

import (
	"bytes"
	"testing"
)

// clientHello builds a minimal valid TLS ClientHello carrying the given SNI.
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

func TestSNI(t *testing.T) {
	if got := SNI(clientHello("example.com")); got != "example.com" {
		t.Fatalf("SNI = %q, want example.com", got)
	}
	if got := SNI([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0, 0, 1, 0}); got != "" {
		t.Fatalf("SNI(junk) = %q, want empty", got)
	}
	if got := SNI(nil); got != "" {
		t.Fatalf("SNI(nil) = %q, want empty", got)
	}
}
