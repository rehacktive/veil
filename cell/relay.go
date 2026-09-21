package cell

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const RelayDataSize = PayloadSize - 11

type RelayCommand uint8

const (
	RelayBegin                 RelayCommand = 1
	RelayData                  RelayCommand = 2
	RelayEnd                   RelayCommand = 3
	RelayConnected             RelayCommand = 4
	RelaySendme                RelayCommand = 5
	RelayExtend                RelayCommand = 6
	RelayExtended              RelayCommand = 7
	RelayTruncate              RelayCommand = 8
	RelayTruncated             RelayCommand = 9
	RelayDrop                  RelayCommand = 10
	RelayResolve               RelayCommand = 11
	RelayResolved              RelayCommand = 12
	RelayBeginDir              RelayCommand = 13
	RelayExtend2               RelayCommand = 14
	RelayExtended2             RelayCommand = 15
	RelayEstablishIntro        RelayCommand = 32
	RelayIntroduce2            RelayCommand = 35
	RelayRendezvous1           RelayCommand = 36
	RelayIntroEstablished      RelayCommand = 38
	RelayEstablishRendezvous   RelayCommand = 33
	RelayIntroduce1            RelayCommand = 34
	RelayRendezvous2           RelayCommand = 37
	RelayRendezvousEstablished RelayCommand = 39
	RelayIntroduceAck          RelayCommand = 40
	RelayPaddingNegotiate      RelayCommand = 41
	RelayPaddingNegotiated     RelayCommand = 42
)

// RelayBody is one fixed-size body in Tor's original relay format (v0).
type RelayBody [PayloadSize]byte

// RelayMessage is an unencrypted message. StreamID zero denotes circuit control.
// Command-specific stream ID and message semantics belong to the circuit layer.
type RelayMessage struct {
	Command  RelayCommand
	StreamID uint16
	Data     []byte
}

// EncodeRelay leaves the recognized and digest fields zero for relaycrypto.
// The first four padding bytes are zero; remaining padding is random.
func EncodeRelay(m RelayMessage) (RelayBody, error) { return encodeRelay(m, rand.Reader) }

func encodeRelay(m RelayMessage, random io.Reader) (RelayBody, error) {
	var out RelayBody
	size := len(m.Data)
	if size > RelayDataSize {
		return out, fmt.Errorf("%w: relay payload too large", ErrInvalid)
	}
	out[0] = byte(m.Command)
	binary.BigEndian.PutUint16(out[3:5], m.StreamID)
	binary.BigEndian.PutUint16(out[9:11], uint16(size))
	copy(out[11:], m.Data)
	if start := 11 + len(m.Data) + 4; start < len(out) {
		if _, err := io.ReadFull(random, out[start:]); err != nil {
			return RelayBody{}, fmt.Errorf("relay padding: %w", err)
		}
	}
	return out, nil
}

// DecodeRelay must only be called AFTER relaycrypto authenticates the body.
// Checking recognized == 0 alone does not authenticate a relay message.
func DecodeRelay(b RelayBody) (RelayMessage, error) {
	if b[1] != 0 || b[2] != 0 {
		return RelayMessage{}, fmt.Errorf("%w: unrecognized relay body", ErrInvalid)
	}
	n := int(binary.BigEndian.Uint16(b[9:11]))
	if n > RelayDataSize {
		return RelayMessage{}, fmt.Errorf("%w: relay length exceeds body", ErrInvalid)
	}
	return RelayMessage{Command: RelayCommand(b[0]), StreamID: binary.BigEndian.Uint16(b[3:5]), Data: append([]byte(nil), b[11:11+n]...)}, nil
}
