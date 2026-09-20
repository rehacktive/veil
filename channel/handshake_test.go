package channel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"veil/cell"
	"veil/torcert"
)

func TestTLSHandshakeAndCellTransport(t *testing.T) {
	for _, tc := range []struct{ link, maxTLS uint16 }{{4, tls.VersionTLS12}, {5, tls.VersionTLS13}} {
		t.Run(fmt.Sprintf("link%d-tls%x", tc.link, tc.maxTLS), func(t *testing.T) {
			f := fixture(t)
			release := make(chan struct{})
			defer close(release)
			observed := make(chan error, 1)
			frames := f.frames(t)
			// Repeated VERSIONS uses negotiated framing; padding may intervene.
			frames = append([]cell.Cell{{Command: cell.VPadding}, {Command: cell.Versions, Payload: []byte{0, 4}}}, frames...)
			ch, err, _ := pipeHandshake(t, context.Background(), f, frames, []uint16{tc.link}, tc.maxTLS, func(conn *tls.Conn, codec *cell.Codec) error {
				frame, err := codec.Read(conn)
				if err == nil && (frame.Command != cell.Create2 || frame.CircuitID&0x80000000 == 0) {
					err = fmt.Errorf("unexpected frame %+v", frame)
				}
				if err == nil {
					kind, body, e := cell.DecodeCreate2(frame.Payload)
					err = e
					if err == nil && (kind != 2 || !bytes.Equal(body, []byte{1, 2, 3})) {
						err = errors.New("wrong CREATE2 body")
					}
				}
				if err == nil {
					_ = codec.Write(conn, cell.Cell{Command: cell.VPadding})
					err = codec.Write(conn, cell.Cell{Command: cell.Created2, CircuitID: frame.CircuitID, Payload: []byte{0, 1, 42}})
				}
				observed <- err
				<-release
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			defer ch.Close()
			info := ch.Info()
			if info.Identity != f.target.Identity || info.LinkVersion != tc.link || info.TLSVersion != tc.maxTLS {
				t.Fatalf("bad metadata %+v", info)
			}
			info.PeerNetInfo.MyAddresses[0] = netip.Addr{}
			if !ch.Info().PeerNetInfo.MyAddresses[0].IsValid() {
				t.Fatal("Info aliases channel state")
			}
			id, err := ch.AllocateCircuitID()
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := cell.EncodeCreate2(2, []byte{1, 2, 3})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := ch.Send(ctx, cell.Cell{CircuitID: id, Command: cell.Create2, Payload: payload}); err != nil {
				t.Fatal(err)
			}
			reply, err := ch.Receive(ctx)
			if err != nil || reply.Command != cell.Created2 || reply.CircuitID != id {
				t.Fatal(reply, err)
			}
			if err := <-observed; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHandshakeRejectsInvalidPeers(t *testing.T) {
	f := fixture(t)
	valid := f.frames(t)
	for _, tc := range []struct {
		name     string
		frames   []cell.Cell
		versions []uint16
	}{
		{"out-of-order", []cell.Cell{valid[1], valid[0], valid[2]}, []uint16{4}},
		{"duplicate-certs", []cell.Cell{valid[0], valid[0], valid[1], valid[2]}, []uint16{4}},
		{"missing-challenge", []cell.Cell{valid[0], valid[2]}, []uint16{4}},
		{"duplicate-challenge", []cell.Cell{valid[0], valid[1], valid[1], valid[2]}, []uint16{4}},
		{"premature-data", []cell.Cell{{Command: cell.Relay, CircuitID: 0x80000001}}, []uint16{4}},
		{"fixed-padding-during-handshake", []cell.Cell{{Command: cell.Padding}}, []uint16{4}},
		{"bad-challenge", []cell.Cell{valid[0], {Command: cell.AuthChallenge, Payload: []byte{0}}}, []uint16{4}},
		{"bad-netinfo", []cell.Cell{valid[0], valid[1], {Command: cell.NetInfo, Payload: []byte{0, 0, 0, 0, 4, 255}}}, []uint16{4}},
		{"no-common-version", valid, []uint16{3}},
		{"empty-certificates", []cell.Cell{{Command: cell.Certs, Payload: []byte{0}}}, []uint16{4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch, err, _ := pipeHandshake(t, context.Background(), f, tc.frames, tc.versions, 0, nil)
			if err == nil || ch != nil {
				t.Fatal("accepted invalid handshake")
			}
		})
	}
	for _, name := range []string{"wrong-rsa", "wrong-ed", "wrong-tls"} {
		t.Run(name, func(t *testing.T) {
			bad := f
			switch name {
			case "wrong-rsa":
				bad.target.Identity.RSA[0] ^= 1
			case "wrong-ed":
				bad.target.Identity.Ed25519[0] ^= 1
			case "wrong-tls":
				other, err := makeFixture()
				if err != nil {
					t.Fatal(err)
				}
				bad.tlsCert = other.tlsCert
			}
			ch, err, _ := pipeHandshake(t, context.Background(), bad, valid, []uint16{5}, 0, nil)
			if !errors.Is(err, torcert.ErrCertificate) || ch != nil {
				t.Fatal("accepted mismatched peer", err)
			}
		})
	}
}

func TestHandshakeResourceLimits(t *testing.T) {
	f := fixture(t)
	for _, size := range []int{0, 65535} {
		frames := make([]cell.Cell, 129)
		for i := range frames {
			frames[i] = cell.Cell{Command: cell.VPadding, Payload: make([]byte, size)}
		}
		ch, err, _ := pipeHandshake(t, context.Background(), f, frames, []uint16{4}, 0, nil)
		if !errors.Is(err, ErrProtocol) || ch != nil {
			t.Fatal("handshake budget not enforced", err)
		}
	}
}

func TestHandshakeCancellation(t *testing.T) {
	for _, cancelNow := range []bool{false, true} {
		client, server := net.Pipe()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		if cancelNow {
			cancel()
		}
		_, _, _, err := negotiate(ctx, client, fixture(t).target)
		cancel()
		server.Close()
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if _, err := client.Write([]byte{1}); err == nil {
			t.Fatal("failed handshake did not close transport")
		}
	}
}

func TestDialLocalRelay(t *testing.T) {
	f := fixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	f.target.Address = listener.Addr().(*net.TCPAddr).AddrPort()
	done := make(chan error, 1)
	frames := f.frames(t)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn, _, err := serveHandshake(raw, f, frames, []uint16{4, 5}, 0)
		if err == nil {
			_, err = io.Copy(io.Discard, conn)
			if errors.Is(err, io.EOF) {
				err = nil
			}
		}
		done <- err
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := Dial(ctx, f.target, Options{HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	cancel()
	select {
	case <-ch.Done():
	case <-time.After(time.Second):
		t.Fatal("lifetime cancellation did not close channel")
	}
	if !errors.Is(ch.Err(), context.Canceled) {
		t.Fatal(ch.Err())
	}
	ch.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not close")
	}
}

func TestDialValidation(t *testing.T) {
	f := fixture(t)
	for _, opt := range []Options{{HandshakeTimeout: -1}, {QueueSize: -1}, {QueueSize: 1025}} {
		if _, err := Dial(context.Background(), f.target, opt); err == nil {
			t.Fatal("invalid options")
		}
	}
	for _, addr := range []netip.AddrPort{{}, netip.MustParseAddrPort("127.0.0.1:0"), netip.MustParseAddrPort("0.0.0.0:9001"), netip.MustParseAddrPort("[ff02::1]:9001")} {
		target := f.target
		target.Address = addr
		if _, err := Dial(context.Background(), target, Options{}); err == nil {
			t.Fatal("invalid target")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Dial(ctx, f.target, Options{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	target := f.target
	target.Identity = torcert.Identity{}
	if _, err := Dial(context.Background(), target, Options{}); !errors.Is(err, torcert.ErrCertificate) {
		t.Fatal(err)
	}
}
