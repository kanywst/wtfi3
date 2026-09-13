package main

import (
	_ "embed"
	"encoding/binary"
	"strings"
	"sync"
)

//go:embed web/oui.tsv
var ouiRaw string

var (
	ouiOnce sync.Once
	ouiMap  map[string]string
)

func loadOUI() {
	ouiMap = make(map[string]string, 52000)
	for _, line := range strings.Split(ouiRaw, "\n") {
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		ouiMap[line[:tab]] = strings.TrimSpace(line[tab+1:])
	}
}

// parseSNI extracts the SNI host from a TLS ClientHello payload.
// Returns "" if the payload is not a ClientHello or has no SNI.
func parseSNI(b []byte) string {
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
	// version(2) + random(32)
	if len(p) < 34 {
		return ""
	}
	p = p[34:]
	// session id
	if len(p) < 1 {
		return ""
	}
	sl := int(p[0])
	p = p[1:]
	if len(p) < sl {
		return ""
	}
	p = p[sl:]
	// cipher suites
	if len(p) < 2 {
		return ""
	}
	cs := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if len(p) < cs {
		return ""
	}
	p = p[cs:]
	// compression methods
	if len(p) < 1 {
		return ""
	}
	cm := int(p[0])
	p = p[1:]
	if len(p) < cm {
		return ""
	}
	p = p[cm:]
	// extensions
	if len(p) < 2 {
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
		// server_name_list: list len(2), name type(1), name len(2), name
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

// vendorLookup maps an OUI prefix to a vendor label using the embedded IEEE
// OUI database (~52k entries). Unknown prefixes return the raw OUI; a
// locally-administered/randomized MAC is flagged.
func vendorLookup(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	ouiOnce.Do(loadOUI)
	oui := strings.ToLower(mac[:8])
	if v, ok := ouiMap[oui]; ok {
		return v
	}
	// Locally-administered / randomized MAC (2nd hex nibble is 2,6,a,e)
	if len(mac) >= 2 {
		switch mac[1] {
		case '2', '6', 'a', 'A', 'e', 'E':
			return "randomized?"
		}
	}
	return oui
}
