package circuit

import (
	"context"
	"fmt"

	"veil/cell"
	"veil/channel"
)

// sendControls drains only controls already available. Taking the mux lock before
// draining lets one received DATA's circuit/stream ACKs travel together without
// a batching timer. One bounded batch holds the send gate, preserving cipher and
// transport order while leaving other writers a chance to run between batches.
func (m *streamMux) sendControls(ctx context.Context, first cell.RelayMessage) (err error) {
	c := m.c
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return c.Err()
	case c.sendGate <- struct{}{}:
	}
	started := false
	defer func() {
		<-c.sendGate
		if err != nil && started {
			c.shutdown(err)
		}
	}()
	if err := c.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	messages := []cell.RelayMessage{first}
	m.mu.Lock()
drain:
	for len(messages) < channel.MaxBatchCells {
		select {
		case msg := <-m.controls:
			messages = append(messages, msg)
		default:
			break drain
		}
	}
	kept := messages[:0]
	for _, msg := range messages {
		// Stream ACKs queued before retirement must not be sent afterwards.
		if msg.Command == cell.RelaySendme && msg.StreamID != 0 && m.streams[msg.StreamID] == nil {
			continue
		}
		kept = append(kept, msg)
	}
	m.mu.Unlock()
	for _, msg := range kept {
		if len(msg.Data) > cell.RelayDataSize || (msg.Command != cell.RelaySendme && msg.Command != cell.RelayEnd) || (msg.Command == cell.RelayEnd && msg.StreamID == 0) {
			return fmt.Errorf("%w: invalid queued stream control", ErrProtocol)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	frames := make([]cell.Cell, 0, len(kept))
	for _, msg := range kept {
		if msg.Command == cell.RelayEnd {
			if ch, ok := c.ch.(interface{ MarkUsed() }); ok {
				ch.MarkUsed()
			}
		}
		started = true
		frame, _, err := c.encryptRelay(int(c.endHop.Load()), msg)
		if err != nil {
			return err
		}
		frames = append(frames, frame)
	}
	if ch, ok := c.ch.(interface {
		SendBatch(context.Context, []cell.Cell) error
	}); ok {
		return ch.SendBatch(ctx, frames)
	}
	// Fixture/custom transports may only provide the original interface.
	for _, frame := range frames {
		if err := c.ch.Send(ctx, frame); err != nil {
			return err
		}
	}
	return nil
}
