// Package tlsmeta extracts clear-text metadata from TLS handshakes.
package tlsmeta

import (
	"encoding/binary"
	"strings"
)

// SNI extracts the Server Name Indication host from a TLS ClientHello payload.
// It returns "" if the payload is not a ClientHello or carries no SNI.
func SNI(b []byte) string {
	// TLS record: type(1)=0x16 handshake, version(2), length(2)
	if len(b) < 5 || b[0] != 0x16 {
		return ""
	}
	rec := int(binary.BigEndian.Uint16(b[3:5]))
	if 5+rec > len(b) {
		rec = len(b) - 5 // tolerate truncated capture
	}
	p := b[5 : 5+rec]
	// Handshake: type(1)=0x01 ClientHello, length(3)
	if len(p) < 4 || p[0] != 0x01 {
		return ""
	}
	p = p[4:]
	if len(p) < 34 { // version(2) + random(32)
		return ""
	}
	p = p[34:]
	if len(p) < 1 { // session id
		return ""
	}
	sl := int(p[0])
	p = p[1:]
	if len(p) < sl {
		return ""
	}
	p = p[sl:]
	if len(p) < 2 { // cipher suites
		return ""
	}
	cs := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < cs {
		return ""
	}
	p = p[cs:]
	if len(p) < 1 { // compression methods
		return ""
	}
	cm := int(p[0])
	p = p[1:]
	if len(p) < cm {
		return ""
	}
	p = p[cm:]
	if len(p) < 2 { // extensions
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) > extLen {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		etype := binary.BigEndian.Uint16(p)
		elen := int(binary.BigEndian.Uint16(p[2:]))
		p = p[4:]
		if len(p) < elen {
			return ""
		}
		body := p[:elen]
		p = p[elen:]
		if etype != 0x00 { // server_name
			continue
		}
		if len(body) < 5 {
			return ""
		}
		nlen := int(binary.BigEndian.Uint16(body[3:5]))
		if 5+nlen > len(body) {
			return ""
		}
		host := string(body[5 : 5+nlen])
		if isHostish(host) {
			return host
		}
	}
	return ""
}

func isHostish(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return strings.Contains(s, ".")
}
