package relaycrypto

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"veil/cell"
	"veil/ntor"
)

// Keys and XOF seed from Tor's test_relaycrypt.c, via Arti's tor1.rs.
func vectorKeys(t *testing.T) []ntor.KeyMaterial {
	t.Helper()
	var keys []ntor.KeyMaterial
	for _, s := range []string{
		"    'My public key is in this signed x509 object', said Tom assertively.      (N-PREG-VIRYL)",
		"'Let's chart the pedal phlanges in the tomb', said Tom cryptographically.  (PELCG-GBR-TENCU)",
		"     'Segmentation fault bugs don't _just happen_', said Tom seethingly.        (P-GUVAT-YL)",
	} {
		k, err := ntor.ParseKeyMaterial([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
	}
	return keys
}

func TestTorEncryptionVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/tor_cell_crypt.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Cell int    `json:"cell"`
		Hex  string `json:"hex"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(vectorKeys(t)...)
	if err != nil {
		t.Fatal(err)
	}
	xof := sha3.NewSHAKE256()
	xof.Write([]byte("'You mean to tell me that there's a version of Sha-3 with no limit on the output length?', said Tom shakily."))
	checked := 0
	for n := 0; n <= 50; n++ {
		var b cell.RelayBody
		b[0], b[4], b[9], b[10] = 2, 1, 1, 242
		if _, err := xof.Read(b[11:]); err != nil {
			t.Fatal(err)
		}
		got, _, err := c.Encrypt(2, b)
		if err != nil {
			t.Fatal(err)
		}
		if checked < len(vectors) && vectors[checked].Cell == n {
			want, err := hex.DecodeString(vectors[checked].Hex)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got[:], want) {
				t.Fatalf("Tor ciphertext mismatch at cell %d", n)
			}
			checked++
		}
	}
	if checked != 8 || checked != len(vectors) {
		t.Fatalf("checked %d vectors", checked)
	}
}

func TestThreeHopDirectionsAndExtension(t *testing.T) {
	keys := vectorKeys(t)
	c, _ := NewClient(keys[0])
	var fwd, back []*layer
	for _, k := range keys {
		fwd = append(fwd, newLayer(k.ForwardKey, k.ForwardDigest))
		back = append(back, newLayer(k.BackwardKey, k.BackwardDigest))
	}
	for step, target := range []int{0, 1, 2, 0, 2, 1, 2, 0} {
		if step == 1 {
			if err := c.AddHop(keys[1]); err != nil {
				t.Fatal(err)
			}
		}
		if step == 2 {
			if err := c.AddHop(keys[2]); err != nil {
				t.Fatal(err)
			}
		}
		message := cell.RelayMessage{Command: cell.RelayData, StreamID: 7, Data: []byte{byte(step), 42}}
		plain, err := cell.EncodeRelay(message)
		if err != nil {
			t.Fatal(err)
		}
		wire, tag, err := c.Encrypt(target, plain)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i <= target; i++ {
			fwd[i].crypt(&wire)
			got, ok := fwd[i].recognize(&wire)
			if ok != (i == target) {
				t.Fatalf("recognition step %d hop %d", step, i)
			}
			if ok && got != tag {
				t.Fatal("outbound SENDME tag mismatch")
			}
		}
		decoded, err := cell.DecodeRelay(wire)
		if err != nil || !bytes.Equal(decoded.Data, message.Data) {
			t.Fatal(decoded, err)
		}
		// Simulate a reply originating at target, then relayed by earlier hops.
		wire = plain
		backTag := back[target].originate(&wire)
		for i := target; i >= 0; i-- {
			back[i].crypt(&wire)
		}
		got, hop, gotTag, err := c.Decrypt(wire)
		if err != nil || hop != target || gotTag != backTag {
			t.Fatalf("hop %d: %v", hop, err)
		}
		decoded, err = cell.DecodeRelay(got)
		if err != nil || !bytes.Equal(decoded.Data, message.Data) {
			t.Fatal(decoded, err)
		}
	}
}

func TestDigestRollback(t *testing.T) {
	k := vectorKeys(t)[0]
	sender := newLayer(k.ForwardKey, k.ForwardDigest)
	receiver := newLayer(k.ForwardKey, k.ForwardDigest)
	for i := 0; i < 5; i++ {
		body, err := cell.EncodeRelay(cell.RelayMessage{Command: cell.RelayData, Data: []byte{byte(i)}})
		if err != nil {
			t.Fatal(err)
		}
		tag := sender.originate(&body)
		bad := body
		bad[5] ^= 1
		before := receiver.digest.Sum(nil)
		if _, ok := receiver.recognize(&bad); ok {
			t.Fatal("accepted forged digest")
		}
		if !bytes.Equal(before, receiver.digest.Sum(nil)) {
			t.Fatal("failed probe advanced digest")
		}
		if bad[5] != (body[5] ^ 1) {
			t.Fatal("failed probe modified body")
		}
		if got, ok := receiver.recognize(&body); !ok || got != tag {
			t.Fatal("valid digest rejected after failed probe")
		}
	}
}

func TestFailuresCloseState(t *testing.T) {
	keys := vectorKeys(t)
	c, _ := NewClient(keys...)
	body, _ := cell.EncodeRelay(cell.RelayMessage{Command: cell.RelayData, Data: []byte("hello")})
	back := newLayer(keys[0].BackwardKey, keys[0].BackwardDigest)
	back.originate(&body)
	back.crypt(&body)
	body[11] ^= 1
	got, hop, tag, err := c.Decrypt(body)
	if err != ErrUnrecognized || got != (cell.RelayBody{}) || hop != -1 || tag != (Tag{}) {
		t.Fatal("returned untrusted plaintext", err)
	}
	if _, _, _, err := c.Decrypt(body); err != ErrClosed {
		t.Fatal(err)
	}
	if _, _, err := c.Encrypt(0, body); err != ErrClosed {
		t.Fatal(err)
	}
	if err := c.AddHop(keys[0]); err != ErrClosed {
		t.Fatal(err)
	}
	c.Close()
	c, _ = NewClient(keys[0])
	back = newLayer(keys[0].BackwardKey, keys[0].BackwardDigest)
	body = cell.RelayBody{}
	body[9], body[10] = 1, 243
	back.originate(&body)
	back.crypt(&body)
	if _, _, _, err := c.Decrypt(body); !errors.Is(err, cell.ErrInvalid) {
		t.Fatal("accepted authenticated invalid length", err)
	}
	if _, _, err := c.Encrypt(0, cell.RelayBody{}); err != ErrClosed {
		t.Fatal(err)
	}
}

func TestInvalidOutboundDoesNotAdvance(t *testing.T) {
	k := vectorKeys(t)[0]
	c, _ := NewClient(k)
	reference, _ := NewClient(k)
	for _, hop := range []int{-1, 1} {
		if _, _, err := c.Encrypt(hop, cell.RelayBody{}); err == nil {
			t.Fatal("invalid hop")
		}
	}
	bad := cell.RelayBody{}
	bad[9] = 255
	if _, _, err := c.Encrypt(0, bad); !errors.Is(err, cell.ErrInvalid) {
		t.Fatal(err)
	}
	a, tagA, _ := c.Encrypt(0, cell.RelayBody{})
	b, tagB, _ := reference.Encrypt(0, cell.RelayBody{})
	if a != b || tagA != tagB {
		t.Fatal("invalid call advanced state")
	}
	if _, err := NewClient(); err == nil {
		t.Fatal("empty path accepted")
	}
	if _, _, err := new(Client).Encrypt(0, cell.RelayBody{}); err != ErrClosed {
		t.Fatal(err)
	}
	c.Close()
	if _, _, err := c.Encrypt(0, cell.RelayBody{}); err != ErrClosed {
		t.Fatal(err)
	}
}
