// Package isolation carries explicit circuit-sharing scopes. Tokens are
// isolation metadata, not access-control credentials; never log them.
package isolation

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
)

type contextKey struct{}

// WithToken permits requests with this token to share client resources within
// one Dialer. An empty token disables sharing. Use separate tokens for unrelated
// sessions. Destination, port and address family remain separate pool keys.
func WithToken(ctx context.Context, token string) context.Context {
	if token == "" {
		return context.WithValue(ctx, contextKey{}, [32]byte{})
	}
	return context.WithValue(ctx, contextKey{}, sha256.Sum256(append([]byte("veil-api-isolation\x00"), token...)))
}

// WithSOCKS scopes both credential fields, with unambiguous length framing and
// a namespace separate from library tokens. Raw credentials are not retained.
func WithSOCKS(ctx context.Context, user, password []byte) context.Context {
	b := binary.BigEndian.AppendUint64([]byte("veil-socks-isolation\x00"), uint64(len(user)))
	b = append(b, user...)
	b = append(b, password...)
	id := sha256.Sum256(b)
	clear(b)
	return context.WithValue(ctx, contextKey{}, id)
}

func Scope(ctx context.Context) ([32]byte, bool) {
	id, ok := ctx.Value(contextKey{}).([32]byte)
	return id, ok && id != ([32]byte{})
}

// WithProxyBoundary adds the application IP and listener address to a SOCKS
// scope. It intentionally excludes the application's ephemeral source port.
func WithProxyBoundary(ctx context.Context, applicationIP, listener string) context.Context {
	id, ok := Scope(ctx)
	if !ok {
		return ctx
	}
	b := append([]byte("veil-proxy-boundary\x00"), id[:]...)
	b = binary.BigEndian.AppendUint64(b, uint64(len(applicationIP)))
	b = append(b, applicationIP...)
	b = append(b, listener...)
	return context.WithValue(ctx, contextKey{}, sha256.Sum256(b))
}
