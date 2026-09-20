package directory

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"veil/cell"
	"veil/ntor"
	"veil/relaycrypto"
)

type fixtureSource struct {
	d        Documents
	requests []string
}

func (f *fixtureSource) Fetch(ctx context.Context, path string, limit int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.requests = append(f.requests, path)
	switch {
	case path == "/tor/keys/all":
		return f.d.Certificates, nil
	case strings.HasPrefix(path, "/tor/status-vote/current/consensus-microdesc/"):
		return f.d.Consensus, nil
	case strings.HasPrefix(path, "/tor/micro/d/"):
		return f.d.Microdescriptors, nil
	}
	return nil, errors.New("unexpected path")
}
func TestBootstrapVerificationOrder(t *testing.T) {
	d, roots, now := fixture(t)
	source := &fixtureSource{d: d}
	s, docs, err := Bootstrap(context.Background(), source, roots, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.Info().Relays != 7 || len(source.requests) != 3 || len(docs.Microdescriptors) != len(d.Microdescriptors) {
		t.Fatal("incomplete bootstrap")
	}
	if _, err := Verify(docs, roots, now); err != nil {
		t.Fatal(err)
	}
	source = &fixtureSource{d: d}
	source.d.Consensus = bytes.Replace(d.Consensus, []byte("Bandwidth=208"), []byte("Bandwidth=209"), 1)
	if _, _, err := Bootstrap(context.Background(), source, roots, now); !errors.Is(err, ErrTrust) {
		t.Fatal(err)
	}
	if len(source.requests) != 2 {
		t.Fatal("downloaded descriptors before verifying consensus")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Bootstrap(ctx, source, roots, now); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, _, err := Bootstrap(ctx, nil, roots, now); err == nil {
		t.Fatal("accepted nil source")
	}
}
func TestHTTPResponseBounds(t *testing.T) {
	for _, test := range []struct {
		name, wire string
		limit      int
		want       string
		bad        bool
	}{
		{"length", "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc", 3, "abc", false},
		{"EOF", "HTTP/1.0 200 OK\r\n\r\nabc", 3, "abc", false},
		{"chunked", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", 3, "abc", false},
		{"redirect", "HTTP/1.0 302 Redirect\r\nLocation: http://example.com\r\n\r\n", 3, "", true},
		{"compression", "HTTP/1.0 200 OK\r\nContent-Encoding: gzip\r\n\r\nabc", 3, "", true},
		{"oversized length", "HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nabcd", 3, "", true},
		{"oversized EOF", "HTTP/1.0 200 OK\r\n\r\nabcd", 3, "", true},
		{"truncated", "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nab", 3, "", true},
		{"oversized header line", "HTTP/1.0 200 OK\r\nX: " + strings.Repeat("a", 40000) + "\r\n\r\n", 3, "", true},
		{"malformed", "not http\r\n\r\n", 3, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, err := readResponse(strings.NewReader(test.wire), test.limit)
			if (err != nil) != test.bad || (!test.bad && string(b) != test.want) {
				t.Fatalf("%q %v", b, err)
			}
		})
	}
	for _, path := range []string{"http://example.com", "/tor/x\r\nInjected: yes", "/tor/x?q=y", "/tor/%20", "/tor/x y"} {
		if _, err := (TorSource{}).Fetch(context.Background(), path, 100); err == nil {
			t.Fatal(path)
		}
	}
}

type fakeCircuit struct {
	frames  []cell.Cell
	sent    []cell.RelayMessage
	peer    *relaycrypto.Client
	failure error
}

func (f *fakeCircuit) Receive(context.Context) (cell.Cell, error) {
	if f.failure != nil {
		return cell.Cell{}, f.failure
	}
	if len(f.frames) == 0 {
		return cell.Cell{}, io.EOF
	}
	frame := f.frames[0]
	f.frames = f.frames[1:]
	return frame, nil
}
func (f *fakeCircuit) Send(_ context.Context, c cell.Cell) error {
	if f.failure != nil {
		return f.failure
	}
	var body cell.RelayBody
	copy(body[:], c.Payload)
	body, _, _, err := f.peer.Decrypt(body)
	if err != nil {
		return err
	}
	m, err := cell.DecodeRelay(body)
	f.sent = append(f.sent, m)
	return err
}
func newFakeStream(t *testing.T) (*directoryStream, *fakeCircuit, func(cell.RelayMessage) relaycrypto.Tag) {
	t.Helper()
	var keys ntor.KeyMaterial
	for i := range keys.ForwardDigest {
		keys.ForwardDigest[i] = byte(i + 1)
		keys.BackwardDigest[i] = byte(i + 2)
	}
	for i := range keys.ForwardKey {
		keys.ForwardKey[i] = byte(i + 3)
		keys.BackwardKey[i] = byte(i + 4)
	}
	client, err := relaycrypto.NewClient(keys)
	if err != nil {
		t.Fatal(err)
	}
	keys.ForwardKey, keys.BackwardKey = keys.BackwardKey, keys.ForwardKey
	keys.ForwardDigest, keys.BackwardDigest = keys.BackwardDigest, keys.ForwardDigest
	peer, err := relaycrypto.NewClient(keys)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); peer.Close() })
	f := &fakeCircuit{peer: peer}
	s := &directoryStream{ctx: context.Background(), ch: f, id: 0x80000001, crypt: client, maxCells: 2000}
	enqueue := func(m cell.RelayMessage) relaycrypto.Tag {
		b, err := cell.EncodeRelay(m)
		if err != nil {
			t.Fatal(err)
		}
		b, tag, err := peer.Encrypt(0, b)
		if err != nil {
			t.Fatal(err)
		}
		f.frames = append(f.frames, cell.Cell{CircuitID: s.id, Command: cell.Relay, Payload: b[:]})
		return tag
	}
	return s, f, enqueue
}
func TestDirectoryStreamFlowControl(t *testing.T) {
	s, f, enqueue := newFakeStream(t)
	var tags []relaycrypto.Tag
	data := bytes.Repeat([]byte{'x'}, cell.RelayDataSize)
	for i := 1; i <= 1200; i++ {
		tag := enqueue(cell.RelayMessage{Command: cell.RelayData, StreamID: 1, Data: data})
		if i%100 == 0 {
			tags = append(tags, tag)
		}
	}
	enqueue(cell.RelayMessage{Command: cell.RelayEnd, StreamID: 1, Data: []byte{6}})
	b, err := io.ReadAll(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 1200*len(data) {
		t.Fatal(len(b))
	}
	circuitAcks, streamAcks := 0, 0
	for _, m := range f.sent {
		if m.Command != cell.RelaySendme {
			t.Fatal(m)
		}
		if m.StreamID == 0 {
			if !bytes.Equal(m.Data, append([]byte{1, 0, 20}, tags[circuitAcks][:]...)) {
				t.Fatal("wrong authenticated SENDME digest")
			}
			circuitAcks++
		} else {
			if m.StreamID != 1 || len(m.Data) != 0 {
				t.Fatal(m)
			}
			streamAcks++
		}
	}
	if circuitAcks != 12 || streamAcks != 24 {
		t.Fatalf("acks %d %d", circuitAcks, streamAcks)
	}
}
func TestDirectoryStreamRejects(t *testing.T) {
	for _, test := range []struct {
		name    string
		message cell.RelayMessage
	}{
		{"wrong stream", cell.RelayMessage{Command: cell.RelayData, StreamID: 2}},
		{"unsolicited ack", cell.RelayMessage{Command: cell.RelaySendme, StreamID: 0}},
		{"repeated connect", cell.RelayMessage{Command: cell.RelayConnected, StreamID: 1}},
		{"bad end", cell.RelayMessage{Command: cell.RelayEnd, StreamID: 1, Data: []byte{1}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, _, enqueue := newFakeStream(t)
			enqueue(test.message)
			if _, err := io.ReadAll(s); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("modified encrypted cell", func(t *testing.T) {
		s, f, enqueue := newFakeStream(t)
		enqueue(cell.RelayMessage{Command: cell.RelayData, StreamID: 1, Data: []byte("abc")})
		f.frames[0].Payload[20] ^= 1
		if _, err := io.ReadAll(s); err == nil {
			t.Fatal("accepted modified ciphertext")
		}
	})
	t.Run("empty flood", func(t *testing.T) {
		s, _, enqueue := newFakeStream(t)
		for i := 0; i < 128; i++ {
			enqueue(cell.RelayMessage{Command: cell.RelayData, StreamID: 1})
		}
		if _, err := io.ReadAll(s); err == nil {
			t.Fatal("accepted flood")
		}
	})
	t.Run("cell budget", func(t *testing.T) {
		s, _, enqueue := newFakeStream(t)
		s.maxCells = 1
		enqueue(cell.RelayMessage{Command: cell.RelayData, StreamID: 1, Data: []byte("a")})
		enqueue(cell.RelayMessage{Command: cell.RelayData, StreamID: 1, Data: []byte("b")})
		if _, err := io.ReadAll(s); err == nil {
			t.Fatal("accepted flood")
		}
	})
	t.Run("drop flood", func(t *testing.T) {
		s, _, enqueue := newFakeStream(t)
		for i := 0; i < 128; i++ {
			enqueue(cell.RelayMessage{Command: cell.RelayDrop})
		}
		if _, err := io.ReadAll(s); err == nil {
			t.Fatal("accepted flood")
		}
	})
	t.Run("circuit mismatch", func(t *testing.T) {
		s, f, enqueue := newFakeStream(t)
		enqueue(cell.RelayMessage{Command: cell.RelayData, StreamID: 1})
		f.frames[0].CircuitID++
		if _, err := io.ReadAll(s); err == nil {
			t.Fatal("accepted wrong circuit")
		}
	})
}
