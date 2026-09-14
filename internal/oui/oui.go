// Package oui resolves MAC address prefixes to vendor names using an embedded
// snapshot of the IEEE OUI registry (regenerate with hack/update-oui.sh).
package oui

import (
	_ "embed"
	"strings"
	"sync"
)

//go:embed oui.tsv
var raw string

var (
	once  sync.Once
	table map[string]string
)

func load() {
	table = make(map[string]string, 52000)
	for _, line := range strings.Split(raw, "\n") {
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		table[line[:tab]] = strings.TrimSpace(line[tab+1:])
	}
}

// Lookup returns the vendor for a MAC address. Unknown prefixes return the raw
// OUI; locally administered or randomized MACs are flagged as "randomized?".
func Lookup(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	once.Do(load)
	prefix := strings.ToLower(mac[:8])
	if v, ok := table[prefix]; ok {
		return v
	}
	// Second hex nibble 2/6/a/e => locally administered address.
	switch mac[1] {
	case '2', '6', 'a', 'A', 'e', 'E':
		return "randomized?"
	}
	return prefix
}
