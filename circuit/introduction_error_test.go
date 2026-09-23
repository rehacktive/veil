package circuit

import (
	"context"
	"errors"
	"testing"
	"time"
	"veil/cell"
)

func TestIntroducePreservesAckRejectionStatus(t *testing.T) {
	for _, status := range []byte{1, 2, 3} {
		c, n, _ := paddingCircuit(t, OnionIntroduction)
		n.stream = func(m cell.RelayMessage, hop int) error {
			if m.Command == cell.RelayIntroduce1 {
				return n.emit(3, cell.RelayMessage{Command: cell.RelayIntroduceAck, Data: []byte{0, status, 0}})
			}
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := c.Introduce(ctx, make([]byte, 120))
		cancel()
		var refusal *IntroductionError
		if !errors.As(err, &refusal) || refusal.Status != uint16(status) {
			t.Fatalf("lost ACK status %d: %v", status, err)
		}
		c.Close()
	}
}
