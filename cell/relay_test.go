package cell

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestRelayLayoutAndPadding(t *testing.T) {
	m := RelayMessage{Command: RelayData, StreamID: 0x1234, Data: []byte("hello")}
	b, err := encodeRelay(m, bytes.NewReader(bytes.Repeat([]byte{0xab}, PayloadSize)))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(b[:16]) != "020000123400000000000568656c6c6f" {
		t.Fatalf("%x", b[:16])
	}
	if !bytes.Equal(b[16:20], make([]byte, 4)) || !bytes.Equal(b[20:], bytes.Repeat([]byte{0xab}, 489)) {
		t.Fatal("wrong padding")
	}
	got, err := DecodeRelay(b)
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Fatalf("%+v %v", got, err)
	}
	got.Data[0] = 0
	if b[11] != 'h' {
		t.Fatal("decode aliases input")
	}
	b[9], b[10] = 1, 243
	if _, err := DecodeRelay(b); err == nil {
		t.Fatal("oversize accepted")
	}
	b[9], b[10], b[1] = 0, 0, 1
	if _, err := DecodeRelay(b); err == nil {
		t.Fatal("unrecognized accepted")
	}
	if _, err := EncodeRelay(RelayMessage{Data: make([]byte, 499)}); err == nil {
		t.Fatal("oversize encoded")
	}
	if _, err := encodeRelay(m, bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("missing randomness: %v", err)
	}
}

func TestHandshakeBodies(t *testing.T) {
	create, err := EncodeCreate2(HandshakeNtor, []byte{1, 2, 3})
	if err != nil || hex.EncodeToString(create) != "00020003010203" {
		t.Fatalf("%x %v", create, err)
	}
	create = append(create, make([]byte, PayloadSize-len(create))...)
	k, h, err := DecodeCreate2(create)
	if err != nil || k != 2 || !bytes.Equal(h, []byte{1, 2, 3}) {
		t.Fatal(k, h, err)
	}
	created, err := EncodeCreated2([]byte{4, 5, 6})
	if err != nil || hex.EncodeToString(created) != "0003040506" {
		t.Fatal(err)
	}
	h, err = DecodeCreated2(created)
	if err != nil || !bytes.Equal(h, []byte{4, 5, 6}) {
		t.Fatal(h, err)
	}
	for _, b := range [][]byte{nil, {0}, {0, 2, 0, 10}, make([]byte, 510)} {
		if _, _, err := DecodeCreate2(b); err == nil {
			t.Fatalf("accepted %x", b)
		}
	}
	for _, b := range [][]byte{nil, {0}, {0, 10, 1}, make([]byte, 510)} {
		if _, err := DecodeCreated2(b); err == nil {
			t.Fatalf("accepted %x", b)
		}
	}
	if _, err := EncodeCreate2(2, make([]byte, 506)); err == nil {
		t.Fatal("oversize CREATE2")
	}
	if _, err := EncodeCreated2(make([]byte, 508)); err == nil {
		t.Fatal("oversize CREATED2")
	}
}

func TestExtend2(t *testing.T) {
	m := Extend2Message{Links: []LinkSpec{{LinkIPv4, []byte{127, 0, 0, 1, 0x23, 0x29}}, {LinkRSAIdentity, bytes.Repeat([]byte{7}, 20)}, {42, []byte{1, 2}}}, HandshakeType: 2, Handshake: []byte{3, 4, 5}}
	b, err := EncodeExtend2(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeExtend2(b)
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Fatalf("%+v %v", got, err)
	}
	for n := 0; n < len(b); n++ {
		if _, err := DecodeExtend2(b[:n]); err == nil {
			t.Fatalf("accepted prefix %d", n)
		}
	}
	if _, err := DecodeExtend2(append(b, 0)); err == nil {
		t.Fatal("accepted trailing bytes")
	}
	for _, m := range []Extend2Message{
		{Links: make([]LinkSpec, 256)}, {Links: []LinkSpec{{LinkIPv4, []byte{1}}}},
		{Links: []LinkSpec{{42, make([]byte, 256)}}}, {Handshake: make([]byte, 494)},
	} {
		if _, err := EncodeExtend2(m); err == nil {
			t.Fatal("accepted invalid EXTEND2")
		}
	}
}

func FuzzBodies(f *testing.F) {
	f.Add([]byte{0, 0, 2, 0, 0})
	f.Add(make([]byte, 509))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = DecodeCreate2(b)
		_, _ = DecodeCreated2(b)
		if m, err := DecodeExtend2(b); err == nil {
			out, err := EncodeExtend2(m)
			if err != nil || !bytes.Equal(out, b) {
				t.Fatal("EXTEND2 round trip changed")
			}
		}
		if len(b) == PayloadSize {
			var body RelayBody
			copy(body[:], b)
			_, _ = DecodeRelay(body)
		}
	})
}
