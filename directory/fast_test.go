package directory

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"testing"

	"veil/cell"
	"veil/ntor"
)

// Tor-generated vector from Arti crypto/handshake/fast.rs, checked independently
// of our derivation loop. Only the first 92 of Arti's 100 output bytes are used.
func TestFastTorVector(t *testing.T) {
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var x [20]byte
	copy(x[:], decode("080E247DF7C252FCD2DC10F459703480C223E3A6"))
	reply := decode("BA95C0D092335428BF80093BBED0B7A26C49E1E8696FBF9C8D6BE26504219C000D26AFE370FCEF04")
	material := decode("AFA89B4FC8CF882335A582C52478B5FCB1E08DAF707E2C2D23B8C27D30BD461F3DF98A3AF82221CB658AD0AA8680B99067E4F7DBC546970EA9A56B26433C71DA867BDD09C14A1308BC327D6A448D71D2382B3AB6AF0BB4E19649A8DFF607DB9C57A04AC3")
	expected, err := ntor.ParseKeyMaterial(material[:92])
	if err != nil {
		t.Fatal(err)
	}
	got, err := finishFast(x, reply)
	if err != nil || got != expected {
		t.Fatal("Tor KDF vector mismatch", err)
	}
	for _, n := range []int{0, 19, 39, 41} {
		if _, err := finishFast(x, make([]byte, n)); !errors.Is(err, ntor.ErrAuthentication) {
			t.Fatal(n, err)
		}
	}
	reply[35] ^= 1
	if _, err := finishFast(x, reply); !errors.Is(err, ntor.ErrAuthentication) {
		t.Fatal(err)
	}
}

type fastPeer struct {
	request cell.Cell
	wrong   bool
}

func (p *fastPeer) Send(_ context.Context, c cell.Cell) error {
	p.request = c
	c.Payload = append([]byte(nil), c.Payload...)
	p.request = c
	return nil
}
func (p *fastPeer) Receive(context.Context) (cell.Cell, error) {
	b := make([]byte, cell.PayloadSize)
	for i := 0; i < 20; i++ {
		b[i] = byte(i + 1)
	}
	in := append(append([]byte{}, p.request.Payload...), b[:20]...)
	in = append(in, 0)
	proof := sha1.Sum(in)
	copy(b[20:40], proof[:])
	command := cell.CreatedFast
	if p.wrong {
		command = cell.Created2
	}
	return cell.Cell{CircuitID: p.request.CircuitID, Command: command, Payload: b}, nil
}
func TestFastDirectoryWire(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		p := &fastPeer{wrong: wrong}
		_, err := fastDirectoryKeys(context.Background(), p, 42)
		if (err != nil) != wrong {
			t.Fatal(wrong, err)
		}
		if p.request.Command != cell.CreateFast || p.request.CircuitID != 42 || len(p.request.Payload) != 20 {
			t.Fatal("wrong framing")
		}
	}
}
func TestMainnetPins(t *testing.T) {
	roots, all, err := parseMainnet(mainnetPins)
	if err != nil || len(roots) != 9 || len(all) != 200 {
		t.Fatal(len(roots), len(all), err)
	}
	_, sample, err := Mainnet()
	if err != nil || len(sample) != 64 {
		t.Fatal(len(sample), err)
	}
	seen := map[[20]byte]bool{}
	for _, s := range sample {
		if seen[s.Target.Identity.RSA] || !s.DirectoryOnlyFast || s.OnionKey != ([32]byte{}) {
			t.Fatal("bad sample")
		}
		seen[s.Target.Identity.RSA] = true
	}
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{"authorities":[]}`)} {
		if _, _, err := parseMainnet(raw); err == nil {
			t.Fatal("accepted malformed pins")
		}
	}
}
