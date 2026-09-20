package cell

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
)

func TestCertsCodec(t *testing.T) {
	want := []Certificate{{Type: 2, Body: []byte{1, 2}}, {Type: 99, Body: []byte{3}}}
	b, err := EncodeCerts(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte{2, 2, 0, 2, 1, 2, 99, 0, 1, 3}) {
		t.Fatalf("%x", b)
	}
	got, err := DecodeCerts(append(b, 7, 8))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
	got[0].Body[0] = 0
	if b[4] != 1 {
		t.Fatal("aliased input")
	}
	for n := 0; n < len(b); n++ {
		if _, err := DecodeCerts(b[:n]); err == nil {
			t.Fatal("accepted truncated CERTS")
		}
	}
	duplicate := []byte{2, 2, 0, 0, 2, 0, 0}
	if _, err := DecodeCerts(duplicate); err == nil {
		t.Fatal("accepted duplicate type")
	}
	for _, certs := range [][]Certificate{make([]Certificate, 256), {{Type: 2}, {Type: 2}}, {{Type: 1, Body: make([]byte, 65535)}}} {
		if _, err := EncodeCerts(certs); err == nil {
			t.Fatal("accepted invalid CERTS")
		}
	}
}

func TestAuthChallengeCodec(t *testing.T) {
	want := AuthChallengeMessage{Challenge: [32]byte{1, 2, 3}, Methods: []uint16{1, 3, 65535}}
	b, err := EncodeAuthChallenge(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAuthChallenge(append(b, 0xff))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
	for n := 0; n < len(b); n++ {
		if _, err := DecodeAuthChallenge(b[:n]); err == nil {
			t.Fatal("accepted truncated challenge")
		}
	}
	if _, err := EncodeAuthChallenge(AuthChallengeMessage{Methods: make([]uint16, 32751)}); err == nil {
		t.Fatal("oversized challenge")
	}
}

func TestNetInfoCodec(t *testing.T) {
	want := NetInfoMessage{Timestamp: 1234, OtherAddress: netip.MustParseAddr("192.0.2.1"), MyAddresses: []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("198.51.100.2")}}
	b, err := EncodeNetInfo(want)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(b[:4]) != 1234 || !bytes.Equal(b[4:11], []byte{4, 4, 192, 0, 2, 1, 2}) {
		t.Fatalf("%x", b)
	}
	got, err := DecodeNetInfo(append(b, make([]byte, PayloadSize-len(b))...))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
	for n := 0; n < len(b); n++ {
		if _, err := DecodeNetInfo(b[:n]); err == nil {
			t.Fatalf("truncated NETINFO %d", n)
		}
	}
	b, err = EncodeNetInfo(NetInfoMessage{})
	if err != nil {
		t.Fatal(err)
	}
	got, err = DecodeNetInfo(b)
	if err != nil || got.OtherAddress.IsValid() || got.Timestamp != 0 || len(got.MyAddresses) != 0 {
		t.Fatal("client leaked metadata", got, err)
	}
	// An unknown address type must be skipped using its advertised length.
	got, err = DecodeNetInfo([]byte{0, 0, 0, 0, 99, 1, 42, 1, 4, 4, 127, 0, 0, 1})
	if err != nil || got.OtherAddress.IsValid() || len(got.MyAddresses) != 1 {
		t.Fatal(got, err)
	}
	for _, b := range [][]byte{{0, 0, 0, 0, 4, 1, 1, 0}, {0, 0, 0, 0, 6, 1, 1, 0}, make([]byte, 510)} {
		if _, err := DecodeNetInfo(b); err == nil {
			t.Fatal("bad address length")
		}
	}
	for _, m := range []NetInfoMessage{{MyAddresses: make([]netip.Addr, 256)}, {MyAddresses: []netip.Addr{{}}}, {OtherAddress: netip.MustParseAddr("fe80::1%en0")}} {
		if _, err := EncodeNetInfo(m); err == nil {
			t.Fatal("bad NETINFO accepted")
		}
	}
}

func FuzzChannelHandshakeBodies(f *testing.F) {
	f.Add([]byte{0})
	f.Add(make([]byte, 509))
	f.Add([]byte{1, 2, 0, 1, 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		if certs, err := DecodeCerts(b); err == nil {
			if _, err := EncodeCerts(certs); err != nil {
				t.Fatal(err)
			}
		}
		if challenge, err := DecodeAuthChallenge(b); err == nil {
			if _, err := EncodeAuthChallenge(challenge); err != nil {
				t.Fatal(err)
			}
		}
		if netinfo, err := DecodeNetInfo(b); err == nil {
			// Replacing an unknown short address with IPv4 unspecified can
			// enlarge a full cell, so not all parsed values fit when re-encoded.
			if wire, err := EncodeNetInfo(netinfo); err == nil {
				if _, err := DecodeNetInfo(wire); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}
