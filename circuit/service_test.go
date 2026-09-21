package circuit

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha3"
	"io"
	"strconv"
	"testing"
	"time"
	"veil/cell"
)

func TestServiceIncomingStreamsAndFlowControl(t *testing.T) {
	for _, count := range []int{3, 4} {
		t.Run(strconv.Itoa(count), func(t *testing.T) { testServiceIncomingStreams(t, count) })
	}
}

func testServiceIncomingStreams(t *testing.T, count int) {
	c, n, peer := streamCircuitHops(t, nil, count)
	c.mu.Lock()
	c.hs = &onionCircuit{purpose: OnionServiceRendezvous}
	c.mu.Unlock()
	var keys [128]byte
	for j := range keys {
		keys[j] = byte(j + 1)
	}
	n.mu.Lock()
	original := n.stream
	n.stream = func(m cell.RelayMessage, hop int) error {
		if m.Command == cell.RelayRendezvous1 {
			if hop != count-1 || len(m.Data) != 84 {
				return ErrProtocol
			}
			f, _ := aes.NewCipher(keys[96:])
			b, _ := aes.NewCipher(keys[64:96])
			l := testLayer{forward: cipher.NewCTR(f, make([]byte, 16)), backward: cipher.NewCTR(b, make([]byte, 16)), fd: sha3.New256(), bd: sha3.New256()}
			l.fd.Write(keys[32:64])
			l.bd.Write(keys[:32])
			n.layers = append(n.layers, l)
			// Arrive immediately, before JoinService has returned to the application.
			return n.emit(count, cell.RelayMessage{Command: cell.RelayBegin, StreamID: 7, Data: []byte(":80\x00")})
		}
		if m.Command == cell.RelayConnected {
			return nil
		}
		return original(m, hop)
	}
	n.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.JoinService(ctx, [20]byte{1}, [64]byte{2}, keys, 80); err != nil {
		t.Fatal(err)
	}
	request, err := c.AcceptService(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s, err := request.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	payload := bytes.Repeat([]byte("hosted-onion"), 200000)
	done := make(chan error, 1)
	go func() { _, err := s.Write(payload); done <- err }()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("corrupt service traffic")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	acks := peer.circuitACKs
	n.mu.Unlock()
	if acks < 40 {
		t.Fatal("SENDME windows not crossed")
	}
	if _, err := request.Accept(ctx); err == nil {
		t.Fatal("pending stream accepted twice")
	}
}
func TestServiceBeginPortAndReplayPolicy(t *testing.T) {
	c := newCircuit(nil)
	c.port = 80
	m := newStreamMux(c)
	m.service = true
	m.accepted = make(chan *IncomingStream, maxStreams)
	for j, b := range [][]byte{[]byte("example.com:80\x00"), []byte(":443\x00"), []byte(":80"), []byte(":80\x00garbage")} {
		id := uint16(j + 1)
		if err := m.incomingBegin(Message{Hop: 3, RelayMessage: cell.RelayMessage{Command: cell.RelayBegin, StreamID: id, Data: b}}); err != nil {
			t.Fatal(err)
		}
		if len(m.accepted) != 0 {
			t.Fatal("unmapped BEGIN accepted")
		}
		if msg := <-m.controls; msg.Command != cell.RelayEnd || msg.StreamID != id {
			t.Fatal(msg)
		}
	}
	msg := Message{Hop: 3, RelayMessage: cell.RelayMessage{Command: cell.RelayBegin, StreamID: 8, Data: []byte(":80\x00")}}
	if err := m.incomingBegin(msg); err != nil {
		t.Fatal(err)
	}
	if err := m.incomingBegin(msg); err == nil {
		t.Fatal("reused stream ID accepted")
	}
	msg.StreamID = 9
	msg.Hop = 2
	if err := m.incomingBegin(msg); err == nil {
		t.Fatal("wrong hop accepted")
	}
}
