//go:build !veiltraffic

package channel

import (
	"context"
	"net"
)

func dialTCP(ctx context.Context, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", address)
}
