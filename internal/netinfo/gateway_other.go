//go:build !darwin && !linux

package netinfo

import "net"

// defaultGateway is unsupported on this platform; spoofing refuses to run
// without a gateway, so returning nil keeps passive capture working.
func defaultGateway() net.IP { return nil }
