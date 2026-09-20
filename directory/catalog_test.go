package directory

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Mainnet's family lists made the complete catalog exceed the former 32 MiB
// limit. Keep full-snapshot acceptance separate from per-download bounds.
func TestLargeMicrodescriptorCatalog(t *testing.T) {
	family := strings.Repeat(" $"+strings.Repeat("A", 40), 1400)
	c := &consensus{}
	var raw bytes.Buffer
	for i := 0; i < 600; i++ {
		key := sha256.Sum256([]byte(fmt.Sprint(i)))
		part := []byte("onion-key\nntor-onion-key " + base64.RawStdEncoding.EncodeToString(key[:]) + "\nfamily" + family + "\np accept 443\n")
		c.relays = append(c.relays, relayStatus{digest: sha256.Sum256(part)})
		raw.Write(part)
	}
	if raw.Len() <= 32<<20 || raw.Len() > MaxMicrodescriptorsSize {
		t.Fatal("fixture no longer exercises a mainnet-sized catalog", raw.Len())
	}
	s, err := complete(c, raw.Bytes())
	if err != nil || s.Info().Relays != 600 {
		t.Fatal("rejected complete large catalog", err)
	}
	if _, err := splitMicrodescriptors(raw.Bytes(), MaxMicrodescriptorBatch); !errors.Is(err, ErrDocument) {
		t.Fatal("per-request limit lost", err)
	}
	oversized := make([]byte, MaxMicrodescriptorsSize+1)
	copy(oversized, "onion-key\n")
	if _, err := complete(c, oversized); !errors.Is(err, ErrDocument) {
		t.Fatal("complete catalog limit lost", err)
	}
}
