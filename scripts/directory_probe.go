//go:build ignore

// A local interoperability helper; no production CLI or Tor runtime dependency.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"veil/directory"
)

func main() {
	var source directory.TorSource
	if err := json.NewDecoder(os.Stdin).Decode(&source); err != nil {
		panic(err)
	}
	source.Timeout = 5 * time.Second
	session := source.Open(context.Background())
	defer session.Close()
	b, err := session.Fetch(context.Background(), "/tor/server/authority", 1<<20)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !bytes.HasPrefix(b, []byte("router ")) || !bytes.Contains(b, []byte("ntor-onion-key ")) {
		panic("missing Tor descriptor")
	}
	second, err := session.Fetch(context.Background(), "/tor/server/authority", 1<<20)
	if err != nil || !bytes.HasPrefix(second, []byte("router ")) {
		fmt.Fprintln(os.Stderr, "sequential directory request:", err)
		os.Exit(1)
	}
	session.Close()
	// A separate request with a wrong ntor key must not obtain directory data.
	source.OnionKey[0] ^= 1
	if _, err := source.Fetch(context.Background(), "/tor/server/authority", 1<<20); err == nil {
		panic("accepted incorrect ntor key")
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"native_begin_dir": true, "sequential_requests": 2, "descriptor_bytes": len(b), "relay_rsa": hex.EncodeToString(source.Target.Identity.RSA[:]), "wrong_ntor_rejected": true})
}
