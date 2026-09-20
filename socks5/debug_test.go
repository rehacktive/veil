package socks5

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
	"veil/internal/diagnostics"
)

func TestDebugLoggingAndCredentialExclusion(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, blocked := range []bool{false, true} {
			var logs bytes.Buffer
			local, _, done := startHandler(t, func(context.Context, string, string) (net.Conn, error) {
				return nil, &ReplyError{Code: 4, Err: errors.New("fixture unreachable")}
			}, Options{OnionOnly: blocked, Logger: diagnostics.New(enabled, &logs)})
			exchange(t, local, []byte{5, 1, 2}, []byte{5, 2})
			const user, password = "private-user-token", "private-password-token"
			auth := append([]byte{1, byte(len(user))}, user...)
			auth = append(auth, byte(len(password)))
			auth = append(auth, password...)
			exchange(t, local, auth, []byte{1, 0})
			code := byte(4)
			if blocked {
				code = 2
			}
			exchange(t, local, destination("example.com", 443), []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("handler did not stop")
			}
			text := logs.String()
			if !enabled {
				if text != "" {
					t.Fatal("logs emitted without debug", text)
				}
				continue
			}
			for _, want := range []string{"socks_connect", "example.com:443", "socks_connection_closed"} {
				if !strings.Contains(text, want) {
					t.Fatal("missing event", want, text)
				}
			}
			if blocked {
				if !strings.Contains(text, "destination_blocked") {
					t.Fatal(text)
				}
			} else if !strings.Contains(text, "fixture unreachable") {
				t.Fatal("lost underlying error", text)
			}
			if strings.Contains(text, user) || strings.Contains(text, password) {
				t.Fatal("credentials logged")
			}
		}
	}
}
