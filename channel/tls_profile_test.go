package channel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"testing"
	"time"

	"veil/cell"
)

var torNamePattern = regexp.MustCompile(`^www\.[a-z2-7]{4,25}\.com$`)

func TestFreshCoverServerNames(t *testing.T) {
	names := map[string]bool{}
	lengths := map[int]bool{}
	for range 200 {
		name, err := randomServerName()
		if err != nil || !torNamePattern.MatchString(name) {
			t.Fatal("invalid cover name", err)
		}
		names[name] = true
		lengths[len(name)] = true
	}
	if len(names) < 190 || len(lengths) < 10 {
		t.Fatal("cover names not regenerated with variable lengths")
	}
}

func TestTLSProfileHybridAndClassicalPeers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint16
		group   tls.CurveID
	}{
		{"TLS12 P256", tls.VersionTLS12, tls.CurveP256},
		{"TLS13 X25519", tls.VersionTLS13, tls.X25519},
		{"TLS13 P256 retry", tls.VersionTLS13, tls.CurveP256},
		{"TLS13 hybrid", tls.VersionTLS13, tls.X25519MLKEM768},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fixture(t)
			release := make(chan struct{})
			defer close(release)
			observed := make(chan error, 1)
			ch, err := tlsProfileDial(t, f, tc.version,
				func(conn *tls.Conn, _ *cell.Codec) error {
					state := conn.ConnectionState()
					var err error
					if state.Version != tc.version || state.DidResume || !torNamePattern.MatchString(state.ServerName) {
						err = fmt.Errorf("unexpected TLS state: version=%x resumed=%v valid_cover_name=%v", state.Version, state.DidResume, torNamePattern.MatchString(state.ServerName))
					}
					observed <- err
					<-release
					return err
				}, func(config *tls.Config) {
					// A successful authenticated channel proves interoperability when the
					// peer supports only this mechanism, including HelloRetryRequest.
					config.CurvePreferences = []tls.CurveID{tc.group}
					config.MinVersion = tc.version
				})
			if err != nil {
				t.Fatal(err)
			}
			defer ch.Close()
			if err := <-observed; err != nil {
				t.Fatal(err)
			}
			if ch.Info().Identity != f.target.Identity {
				t.Fatal("cover SNI replaced relay identity authentication")
			}
		})
	}
}

// Use real TCP for HelloRetryRequest. A zero-buffer net.Pipe can deadlock when
// both TLS endpoints write their compatibility CCS before reading the peer.
func tlsProfileDial(t *testing.T, f relayFixture, version uint16, after func(*tls.Conn, *cell.Codec) error, configure func(*tls.Config)) (*Channel, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	f.target.Address = listener.Addr().(*net.TCPAddr).AddrPort()
	frames := f.frames(t)
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn, codec, err := serveHandshake(raw, f, frames, []uint16{5}, version, configure)
		if err == nil {
			err = after(conn, codec)
		}
		done <- err
	}()
	ch, err := Dial(context.Background(), f.target, Options{HandshakeTimeout: 3 * time.Second})
	t.Cleanup(func() {
		if ch != nil {
			ch.Close()
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("TLS fixture did not stop")
		}
	})
	return ch, err
}
