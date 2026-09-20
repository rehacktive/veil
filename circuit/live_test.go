package circuit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"

	"veil/cell"
	"veil/channel"
	"veil/directory"
	"veil/ntor"
)

// Opt-in interoperability check, fed fresh public pins by the private-network
// script. It exercises the same builder with test-only explicit hops because
// localhost relays intentionally cannot pass production subnet/exit selection.
func localTestHops(t *testing.T) [3]hop {
	t.Helper()
	raw := os.Getenv("VEIL_TEST_CIRCUIT_PEERS")
	if raw == "" {
		t.Skip("requires scripts/check_local_directory.py --circuit-test")
	}
	var peers []struct{ Address, RSA, Ed25519, NTor string }
	if err := json.Unmarshal([]byte(raw), &peers); err != nil || len(peers) != 3 {
		t.Fatal("invalid local test peers", err)
	}
	var hops [3]hop
	for i, p := range peers {
		address, err := netip.ParseAddrPort(p.Address)
		if err != nil || !address.Addr().IsLoopback() {
			t.Fatal("test peers must be localhost", err)
		}
		hops[i].target.Address = address
		for _, k := range []struct {
			s   string
			dst []byte
		}{{p.RSA, hops[i].target.Identity.RSA[:]}, {p.Ed25519, hops[i].target.Identity.Ed25519[:]}, {p.NTor, hops[i].ntor.OnionKey[:]}} {
			b, err := hex.DecodeString(k.s)
			if err != nil || len(b) != len(k.dst) {
				t.Fatal("invalid public key", err)
			}
			copy(k.dst, b)
		}
		hops[i].ntor.Identity = hops[i].target.Identity.RSA
	}
	return hops
}

func TestLocalTorThreeHop(t *testing.T) {
	hops := localTestHops(t)
	dial := func(ctx context.Context, target channel.Target, options channel.Options) (transport, error) {
		return channel.Dial(ctx, target, options)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	a := &testAttempt{usable: directory.GuardUsable}
	c, err := build(ctx, hops, a, 15*time.Second, dial, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// This raw API test keeps its exchange below flow-control thresholds.
	// TestLocalTorStreams separately exercises the managed application API.
	if _, err = c.Send(ctx, 2, cell.RelayMessage{Command: cell.RelayBeginDir, StreamID: 1}); err != nil {
		t.Fatal(err)
	}
	m, err := c.Receive(ctx)
	if err != nil || m.Command != cell.RelayConnected || m.Hop != 2 || m.StreamID != 1 {
		t.Fatal(m, err)
	}
	request := []byte("GET /tor/server/authority HTTP/1.0\r\nHost: localhost\r\nAccept-Encoding: identity\r\n\r\n")
	if _, err = c.Send(ctx, 2, cell.RelayMessage{Command: cell.RelayData, StreamID: 1, Data: request}); err != nil {
		t.Fatal(err)
	}
	var response []byte
	ended := false
	for cells := 0; cells < 40; cells++ {
		m, err = c.Receive(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if m.Hop != 2 || m.StreamID != 1 {
			t.Fatal("unexpected reply", m)
		}
		if m.Command == cell.RelayEnd {
			if len(m.Data) != 1 || m.Data[0] != 6 {
				t.Fatal("abnormal END", m)
			}
			ended = true
			break
		}
		if m.Command != cell.RelayData {
			t.Fatal("unexpected relay command", m.Command)
		}
		response = append(response, m.Data...)
	}
	if !ended || !bytes.HasPrefix(response, []byte("HTTP/1.0 200")) || !bytes.Contains(response, []byte("ntor-onion-key ")) {
		t.Fatal("missing bounded descriptor response")
	}
	c.Close()
	for _, wrong := range []string{"middle Ed25519", "last ntor"} {
		bad := hops
		if wrong == "middle Ed25519" {
			bad[1].target.Identity.Ed25519[0] ^= 1
		} else {
			bad[2].ntor.OnionKey[0] ^= 1
		}
		a := &testAttempt{usable: directory.GuardUsable}
		c, err := build(ctx, bad, a, 10*time.Second, dial, func() bool { return true })
		if c != nil {
			c.Close()
			t.Fatal("accepted wrong", wrong)
		}
		var remote *RemoteError
		rejected := errors.As(err, &remote) || (wrong == "last ntor" && errors.Is(err, ntor.ErrAuthentication))
		if !rejected || a.failure != 0 || a.success != 0 {
			t.Fatal("expected extension rejection without guard penalty", wrong, err, a)
		}
	}
	fmt.Printf("native three-hop CREATE2/EXTEND2: descriptor_bytes=%d; wrong middle identity and last ntor rejected\n", len(response))
}
