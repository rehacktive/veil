//go:build go1.26

package channel

import "crypto/tls"

// Go 1.26 also implements Tor's P-256/ML-KEM hybrid. Go chooses wire ordering;
// this list enables only implemented groups, not an arbitrary ClientHello copy.
func torTLSGroups() []tls.CurveID {
	return []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.CurveP256, tls.X25519}
}
