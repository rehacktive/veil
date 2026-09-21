//go:build veiltraffic

package channel

// Measurement-only routing through a controlled local SOCKS tap. TLS and Tor
// authentication still use the original, verified target. Production builds
// cannot select this route, and this fixture rejects every non-loopback target.
import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"time"
)

func dialTCP(ctx context.Context, address string) (net.Conn, error) {
	proxy := os.Getenv("VEIL_TEST_LOCAL_TAP")
	if proxy == "" {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	target, err := netip.ParseAddrPort(address)
	if err != nil || !target.Addr().Is4() || !target.Addr().IsLoopback() {
		return nil, errors.New("measurement requires IPv4 loopback target")
	}
	tap, err := netip.ParseAddrPort(proxy)
	if err != nil || !tap.Addr().IsLoopback() {
		return nil, errors.New("measurement requires loopback tap")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	ok := false
	defer func() {
		stop()
		if !ok {
			_ = conn.Close()
		}
	}()
	if deadline, exists := ctx.Deadline(); exists {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if err := writeFull(conn, []byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return nil, err
	}
	if choice != [2]byte{5, 0} {
		return nil, errors.New("measurement SOCKS negotiation failed")
	}
	request := append([]byte{5, 1, 0, 1}, target.Addr().AsSlice()...)
	request = binary.BigEndian.AppendUint16(request, target.Port())
	if err := writeFull(conn, request); err != nil {
		return nil, err
	}
	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[1] != 0 || reply[3] != 1 {
		return nil, errors.New("measurement SOCKS CONNECT failed")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	if !stop() || ctx.Err() != nil {
		return nil, ctx.Err()
	}
	ok = true
	return conn, nil
}
