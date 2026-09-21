package channel

import (
	"crypto/rand"
	"encoding/base32"
	"math/big"
	"strings"
)

// C Tor uses www.<4..25 random base32 characters>.com for TLS camouflage.
// This is regenerated per connection and never derived from identity, address,
// destination or isolation scope. It is not used for DNS or authentication.
func randomServerName() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(22))
	if err != nil {
		return "", err
	}
	var random [16]byte // 128 bits provide at least 25 base32 characters.
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	label := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(random[:]))
	return "www." + label[:4+int(n.Int64())] + ".com", nil
}
