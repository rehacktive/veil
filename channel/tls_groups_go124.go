//go:build !go1.26

package channel

import "crypto/tls"

// Intersection of C Tor's modern groups and the groups implemented by Go 1.24.
// Keep classical fallbacks for TLS 1.2 and older Tor/OpenSSL peers.
func torTLSGroups() []tls.CurveID {
	return []tls.CurveID{tls.X25519MLKEM768, tls.CurveP256, tls.X25519}
}
