package directory

import (
	"context"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- CREATE_FAST requires Tor's SHA-1 KDF, used only for one-hop directory bootstrap inside a pinned authenticated TLS channel.
	"crypto/subtle"
	"errors"

	"veil/cell"
	"veil/ntor"
)

// fastDirectoryKeys is deliberately private to the directory transport. It
// must run only after channel.Dial has authenticated BOTH relay identity pins.
// CREATE_FAST has no independent authentication or forward secrecy beyond TLS;
// application circuits always use ntor and cannot call this path.
func fastDirectoryKeys(ctx context.Context, ch cellChannel, id uint32) (ntor.KeyMaterial, error) {
	var x [20]byte
	if _, err := rand.Read(x[:]); err != nil {
		return ntor.KeyMaterial{}, err
	}
	defer clear(x[:])
	if err := ch.Send(ctx, cell.Cell{CircuitID: id, Command: cell.CreateFast, Payload: x[:]}); err != nil {
		return ntor.KeyMaterial{}, err
	}
	f, err := receiveCircuit(ctx, ch, id)
	if err != nil {
		return ntor.KeyMaterial{}, err
	}
	if f.Command != cell.CreatedFast || len(f.Payload) != cell.PayloadSize {
		return ntor.KeyMaterial{}, errors.New("directory circuit: expected CREATED_FAST")
	}
	return finishFast(x, f.Payload[:40])
}
func finishFast(x [20]byte, reply []byte) (ntor.KeyMaterial, error) {
	if len(reply) != 40 {
		return ntor.KeyMaterial{}, ntor.ErrAuthentication
	}
	var input [41]byte
	copy(input[:20], x[:])
	copy(input[20:40], reply[:20])
	defer clear(input[:])
	var expanded [120]byte
	defer clear(expanded[:])
	for counter := byte(0); counter < 6; counter++ {
		input[40] = counter
		digest := sha1.Sum(input[:]) // #nosec G401 -- Protocol-defined KDF-TOR: SHA1(X|Y|counter). The TLS-protected one-hop bootstrap never carries application traffic.
		copy(expanded[int(counter)*20:], digest[:])
	}
	if subtle.ConstantTimeCompare(expanded[:20], reply[20:]) != 1 {
		return ntor.KeyMaterial{}, ntor.ErrAuthentication
	}
	return ntor.ParseKeyMaterial(expanded[20:112])
}
