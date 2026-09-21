package channel

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"time"

	"veil/cell"
)

// PaddingOptions configures guard-link padding from authenticated consensus
// parameters. Low=High=0 disables it. Bootstrap links leave Options.Padding nil.
// This schedules idle cells; it does not provide channel pooling or retention.
type PaddingOptions struct {
	Low, High   time.Duration
	BeforeUsage bool
}

// MarkUsed enables deferred padding once a circuit carries user traffic.
func (c *Channel) MarkUsed() {
	select {
	case c.used <- struct{}{}:
	default:
	}
}

func (p PaddingOptions) delay() (time.Duration, error) {
	if p.High == p.Low {
		return p.Low, nil
	}
	width := big.NewInt(int64(p.High - p.Low))
	x, err := rand.Int(rand.Reader, width)
	if err != nil {
		return 0, err
	}
	y, err := rand.Int(rand.Reader, width)
	if err != nil {
		return 0, err
	}
	return p.Low + time.Duration(max(x.Int64(), y.Int64())), nil
}

// The sole writer owns padding and negotiation, preserving cell order. Live
// updates coalesce via a generation notification; there is no update queue.
func (c *Channel) writeLoop() {
	defer c.wg.Done()
	padding := c.padding
	var changes <-chan struct{}
	var expiry *time.Timer
	var expired <-chan time.Time
	var timer *time.Timer
	var tick <-chan time.Time
	used := false
	writeCell := func(command cell.Command, payload []byte) error {
		var wire bytes.Buffer
		if err := c.codec.Write(&wire, cell.Cell{Command: command, Payload: payload}); err != nil {
			return err
		}
		return c.write(wire.Bytes())
	}
	negotiate := func() error {
		if padding == nil || c.info.LinkVersion < 5 {
			return nil
		}
		command := byte(2)
		if padding.High == 0 {
			command = 1
		}
		return writeCell(cell.PaddingNegotiate, []byte{0, command, 0, 0, 0, 0})
	}
	reset := func() error {
		if timer != nil {
			timer.Stop()
		}
		tick = nil
		if padding == nil || padding.High == 0 || (!used && !padding.BeforeUsage) {
			return nil
		}
		delay, err := padding.delay()
		if err != nil {
			return err
		}
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			timer.Reset(delay)
		}
		tick = timer.C
		return nil
	}
	applyPolicy := func(initial bool) error {
		enabled := padding != nil && padding.High > 0
		if c.policy != nil {
			p, until, _, changed := c.policy.current()
			padding = &p
			changes = changed
			if expiry != nil {
				expiry.Stop()
			}
			expired = nil
			if time.Now().Before(until) {
				expiry = time.NewTimer(time.Until(until))
				expired = expiry.C
			}
		}
		if initial || enabled != (padding != nil && padding.High > 0) {
			if err := negotiate(); err != nil {
				return err
			}
		}
		return reset()
	}
	defer func() {
		if timer != nil {
			timer.Stop()
		}
		if expiry != nil {
			expiry.Stop()
		}
	}()
	if err := applyPolicy(true); err != nil {
		c.shutdown(err)
		return
	}
	for {
		// Give known policy updates precedence over an already-ready padding timer.
		update := false
		select {
		case <-changes:
			update = true
		case <-expired:
			update = true
		default:
		}
		if update {
			if err := applyPolicy(false); err != nil {
				c.shutdown(err)
				return
			}
		}
		var req writeRequest
		select {
		case <-c.done:
			return
		case <-changes:
			if err := applyPolicy(false); err != nil {
				c.shutdown(err)
				return
			}
			continue
		case <-expired:
			if err := applyPolicy(false); err != nil {
				c.shutdown(err)
				return
			}
			continue
		case <-c.used:
			if !used {
				used = true
				if err := reset(); err != nil {
					c.shutdown(err)
					return
				}
			}
			continue
		case req = <-c.send:
		case <-tick:
			select {
			case <-c.done:
				return
			case req = <-c.send:
			default:
				// Do not send using a policy that expired while the writer was busy.
				if c.policy != nil {
					_, until, _, _ := c.policy.current()
					if !time.Now().Before(until) {
						if err := applyPolicy(false); err != nil {
							c.shutdown(err)
							return
						}
						continue
					}
				}
				if err := writeCell(cell.Padding, nil); err != nil {
					c.shutdown(err)
					return
				}
				if err := reset(); err != nil {
					c.shutdown(err)
					return
				}
				continue
			}
		}
		err := c.write(req.data)
		req.result <- err
		if err != nil {
			c.shutdown(err)
			return
		}
		if err := reset(); err != nil {
			c.shutdown(err)
			return
		}
	}
}
