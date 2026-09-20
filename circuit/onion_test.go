package circuit

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha3"
	"errors"
	"io"
	"testing"
	"time"

	"veil/cell"
	"veil/onion"
)

const serviceName = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"

// Independent peer encryption exercises the fourth hop, including the 20-byte
// SENDME tags taken from its 32-byte running digest, beyond both credit windows.
func TestOnionRendezvousLargeTransfer(t *testing.T) {
	c, n, peer := streamCircuit(t, nil)
	c.mu.Lock()
	c.hs = &onionCircuit{purpose: OnionRendezvous}
	c.mu.Unlock()
	var keys [128]byte
	for i := range keys {
		keys[i] = byte(i + 1)
	}
	n.mu.Lock()
	stream := n.stream
	n.stream = func(m cell.RelayMessage, hop int) error {
		if m.Command == cell.RelayEstablishRendezvous {
			if hop != 2 || m.StreamID != 0 || len(m.Data) != 20 {
				return ErrProtocol
			}
			return n.emit(2, cell.RelayMessage{Command: cell.RelayRendezvousEstablished})
		}
		return stream(m, hop)
	}
	n.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.PrepareRendezvous(ctx, [20]byte{1}, serviceName, 80, func(reply []byte) ([128]byte, error) {
		if len(reply) != 64 {
			return [128]byte{}, ErrProtocol
		}
		return keys, nil
	}); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	// C Tor forwards padding up to the legacy 148-byte rendezvous reply.
	err := n.emit(2, cell.RelayMessage{Command: cell.RelayRendezvous2, Data: make([]byte, 148)})
	f, _ := aes.NewCipher(keys[64:96])
	b, _ := aes.NewCipher(keys[96:])
	l := testLayer{forward: cipher.NewCTR(f, make([]byte, 16)), backward: cipher.NewCTR(b, make([]byte, 16)), fd: sha3.New256(), bd: sha3.New256()}
	l.fd.Write(keys[:32])
	l.bd.Write(keys[32:64])
	n.layers = append(n.layers, l)
	n.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.FinishRendezvous(ctx); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"other.onion:80", serviceName + ":443", "example.com:80"} {
		if _, err := c.DialContext(ctx, "tcp", address); err == nil {
			t.Fatal("accepted unbound destination", address)
		}
	}
	s, err := c.DialContext(ctx, "tcp", serviceName+":80")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(10 * time.Second))
	payload := bytes.Repeat([]byte("onion-hop"), 256*1024)
	done := make(chan error, 1)
	go func() { _, err := s.Write(payload); done <- err }()
	got := make([]byte, len(payload))
	_, err = io.ReadFull(s, got)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("service round trip", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(peer.begins) != 1 || string(peer.begins[0]) != ":80\x00" || peer.circuitACKs < 40 || peer.streamACKs < 80 {
		t.Fatalf("service flow control: %+v", peer)
	}
}

func TestOnionControlRejectsUnsolicitedAndUnauthenticated(t *testing.T) {
	for _, scenario := range []string{"unsolicited", "wrong purpose", "wrong hop", "wrong stream", "short reply", "forged reply"} {
		t.Run(scenario, func(t *testing.T) {
			c, n := built(t)
			c.mu.Lock()
			c.hs = &onionCircuit{purpose: OnionRendezvous, stage: 2, finish: func([]byte) ([128]byte, error) { return [128]byte{}, onion.ErrAuthentication }}
			hop := 2
			m := cell.RelayMessage{Command: cell.RelayRendezvous2, Data: make([]byte, 148)}
			switch scenario {
			case "unsolicited":
				c.hs = nil
			case "wrong purpose":
				c.hs.purpose = OnionDirectory
			case "wrong hop":
				hop = 1
			case "wrong stream":
				m.StreamID = 1
			case "short reply":
				m.Data = make([]byte, 63)
			}
			c.mu.Unlock()
			n.mu.Lock()
			err := n.emit(hop, m)
			n.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-c.Done():
			case <-time.After(time.Second):
				t.Fatal("invalid rendezvous kept alive")
			}
			if c.endHop.Load() != 2 {
				t.Fatal("installed unauthenticated keys")
			}
			if scenario == "forged reply" && !errors.Is(c.Err(), onion.ErrAuthentication) {
				t.Fatal(c.Err())
			}
		})
	}
}
