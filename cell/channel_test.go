package cell

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"testing"
	"testing/iotest"
)

func codec(t *testing.T) *Codec {
	t.Helper()
	c, err := NewCodec(4)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVersionsWire(t *testing.T) {
	var b bytes.Buffer
	if err := WriteVersions(&b, []uint16{3, 4, 5}); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(b.Bytes()); got != "0000070006000300040005" {
		t.Fatal(got)
	}
	vs, err := ReadVersions(iotest.OneByteReader(&b))
	if err != nil || !reflect.DeepEqual(vs, []uint16{3, 4, 5}) {
		t.Fatalf("%v %v", vs, err)
	}
	if v, err := NegotiateVersion(vs, []uint16{5, 4}); err != nil || v != 5 {
		t.Fatalf("%v %v", v, err)
	}
	if _, err := NegotiateVersion(vs, []uint16{6}); err == nil {
		t.Fatal("negotiated unsupported protocol")
	}
	if _, err := NegotiateVersion([]uint16{0}, []uint16{0}); err == nil {
		t.Fatal("negotiated protocol zero")
	}
}

func TestChannelWire(t *testing.T) {
	for _, version := range []uint16{4, 5} {
		c, _ := NewCodec(version)
		var wire bytes.Buffer
		frames := []Cell{
			{CircuitID: 0x80000001, Command: Create2, Payload: []byte{0, 2, 0, 1, 42}},
			{Command: Certs, Payload: []byte{0}},
			{Command: VPadding},
			{Command: Versions, Payload: []byte{0, 4}},
			{CircuitID: 123, Command: 254, Payload: []byte{1, 2, 3}},
			{CircuitID: 321, Command: 100, Payload: []byte{4, 5}},
		}
		for _, f := range frames {
			if err := c.Write(&wire, f); err != nil {
				t.Fatal(err)
			}
		}
		if got := hex.EncodeToString(wire.Bytes()[:10]); got != "800000010a000200012a" {
			t.Fatal(got)
		}
		r := iotest.OneByteReader(&wire)
		for _, want := range frames {
			got, err := c.Read(r)
			if err != nil {
				t.Fatal(err)
			}
			if got.CircuitID != want.CircuitID || got.Command != want.Command || !bytes.Equal(got.Payload[:len(want.Payload)], want.Payload) {
				t.Fatalf("mismatch: %+v", got)
			}
			if !got.Command.Variable() && len(got.Payload) != PayloadSize {
				t.Fatal("wrong fixed size")
			}
			if !bytes.Equal(got.Payload[len(want.Payload):], make([]byte, len(got.Payload)-len(want.Payload))) {
				t.Fatal("padding is not zero")
			}
		}
		if _, err := c.Read(r); err != io.EOF {
			t.Fatalf("want clean EOF, got %v", err)
		}
	}
}

func TestEveryTruncatedFrame(t *testing.T) {
	c := codec(t)
	for _, f := range []Cell{{CircuitID: 1, Command: Relay}, {Command: Certs, Payload: []byte{1, 2, 3}}} {
		var b bytes.Buffer
		if err := c.Write(&b, f); err != nil {
			t.Fatal(err)
		}
		for n := 1; n < b.Len(); n++ {
			if _, err := c.Read(bytes.NewReader(b.Bytes()[:n])); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("cmd %d length %d: %v", f.Command, n, err)
			}
		}
	}
	var b bytes.Buffer
	_ = WriteVersions(&b, []uint16{4, 5})
	for n := 1; n < b.Len(); n++ {
		if _, err := ReadVersions(bytes.NewReader(b.Bytes()[:n])); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("versions length %d: %v", n, err)
		}
	}
}

func TestInvalidCells(t *testing.T) {
	c := codec(t)
	for _, f := range []Cell{
		{Command: Relay}, {Command: Create2}, {Command: Destroy},
		{CircuitID: 1, Command: Certs}, {CircuitID: 1, Command: Padding},
		{Command: Padding, Payload: make([]byte, 510)},
		{Command: VPadding, Payload: make([]byte, 65536)},
	} {
		var b bytes.Buffer
		if err := c.Write(&b, f); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %+v", f)
		}
		if b.Len() != 0 {
			t.Fatal("wrote invalid frame")
		}
	}
	for _, raw := range [][]byte{{0, 0, 0, 0, 3}, {0, 0, 0, 1, 129}, {0, 0, 0, 1, 7}} {
		if _, err := c.Read(bytes.NewReader(raw)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid header accepted: %x %v", raw, err)
		}
	}
	for _, v := range []uint16{0, 1, 2, 3, 6} {
		if _, err := NewCodec(v); err == nil {
			t.Fatalf("accepted %d", v)
		}
	}
	if err := new(Codec).Write(io.Discard, Cell{}); err == nil {
		t.Fatal("zero codec accepted")
	}
	if _, err := new(Codec).Read(bytes.NewReader(nil)); err == nil {
		t.Fatal("zero codec accepted")
	}
	for _, raw := range [][]byte{{0, 0, 7, 0, 0}, {0, 0, 7, 0, 1, 0}, {0, 1, 7, 0, 2, 0, 4}, {0, 0, 8, 0, 2, 0, 4}} {
		if _, err := ReadVersions(bytes.NewReader(raw)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("bad versions accepted: %x", raw)
		}
	}
	if err := WriteVersions(io.Discard, nil); err == nil {
		t.Fatal("empty versions accepted")
	}
	if err := WriteVersions(io.Discard, make([]uint16, 32768)); err == nil {
		t.Fatal("oversized versions accepted")
	}
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) {
	if len(b) > 3 {
		b = b[:3]
	}
	return w.Buffer.Write(b)
}

type stuckWriter struct{}

func (stuckWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriterBoundaries(t *testing.T) {
	c := codec(t)
	w := &shortWriter{}
	if err := c.Write(w, Cell{Command: Padding}); err != nil {
		t.Fatal(err)
	}
	if w.Len() != 514 {
		t.Fatal(w.Len())
	}
	if err := c.Write(stuckWriter{}, Cell{Command: Padding}); err != io.ErrShortWrite {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := c.Write(&b, Cell{Command: VPadding, Payload: make([]byte, 65535)}); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Read(&b); err != nil || len(got.Payload) != 65535 {
		t.Fatal(err)
	}
}

func FuzzChannel(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 128, 0, 0})
	f.Add([]byte{128, 0, 0, 1, 10})
	f.Add([]byte{})
	c, _ := NewCodec(4)
	f.Fuzz(func(t *testing.T, raw []byte) {
		r := bytes.NewReader(raw)
		got, err := c.Read(r)
		if err != nil {
			return
		}
		var encoded bytes.Buffer
		if err := c.Write(&encoded, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded.Bytes(), raw[:len(raw)-r.Len()]) {
			t.Fatal("wire round trip changed")
		}
	})
}

func FuzzVersions(f *testing.F) {
	f.Add([]byte{0, 0, 7, 0, 4, 0, 4, 0, 5})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		vs, err := ReadVersions(r)
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err := WriteVersions(&out, vs); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out.Bytes(), b[:len(b)-r.Len()]) {
			t.Fatal("versions round trip changed")
		}
	})
}
