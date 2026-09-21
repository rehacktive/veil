// Package channel establishes pinned, authenticated Tor client channels.
// It provides cell transport, not circuits, directory bootstrap, or anonymity.
package channel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"veil/cell"
	"veil/torcert"
)

var ErrProtocol = errors.New("Tor channel protocol violation")

// Target must come from a trusted descriptor or explicit out-of-band pins.
// A numeric address prevents implicit hostname resolution during channel setup.
type Target struct {
	Address  netip.AddrPort
	Identity torcert.Identity
}

type Options struct {
	HandshakeTimeout time.Duration   // Zero means 30 seconds, including TCP/TLS.
	QueueSize        int             // Per-direction queue; zero means 32. Maximum 1024.
	Padding          *PaddingOptions // Nil for directory-only bootstrap channels.
	PaddingPolicy    *PaddingPolicy  // Optional live consensus policy.
}

func (o Options) normalized() (Options, error) {
	if o.HandshakeTimeout == 0 {
		o.HandshakeTimeout = 30 * time.Second
	}
	if o.QueueSize == 0 {
		o.QueueSize = 32
	}
	if o.HandshakeTimeout < 0 || o.QueueSize < 1 || o.QueueSize > 1024 {
		return Options{}, errors.New("channel: invalid timeout or queue size")
	}
	if o.Padding != nil {
		p := *o.Padding
		if p.Low < 0 || p.High < p.Low || p.High > time.Minute {
			return Options{}, errors.New("channel: invalid padding interval")
		}
		o.Padding = &p
	}
	return o, nil
}

// Info is the authenticated channel's metadata. PeerNetInfo contains statements
// made by the relay, not independently verified time or address information.
type Info struct {
	Identity           torcert.Identity
	LinkVersion        uint16
	TLSVersion         uint16
	CertificatesExpire time.Time
	PeerNetInfo        cell.NetInfoMessage
}

// Dial establishes TLS, verifies the Tor certificate chain against BOTH pins,
// and finishes the anonymous-client handshake before returning a Channel.
// Cancellation of ctx closes the channel, including after Dial returns. Callers
// should use a lifetime context here; HandshakeTimeout bounds setup separately.
func Dial(ctx context.Context, target Target, options Options) (*Channel, error) {
	options, err := options.normalized()
	if err != nil {
		return nil, err
	}
	if err := validateTarget(target); err != nil {
		return nil, err
	}
	hctx, cancel := context.WithTimeout(ctx, options.HandshakeTimeout)
	defer cancel()
	raw, err := dialTCP(hctx, target.Address.String())
	if err != nil {
		return nil, fmt.Errorf("channel TCP: %w", err)
	}
	return connect(ctx, hctx, raw, target, options)
}

func validateTarget(t Target) error {
	if !t.Address.IsValid() || t.Address.Port() == 0 || t.Address.Addr().Zone() != "" || t.Address.Addr().IsUnspecified() || t.Address.Addr().IsMulticast() {
		return errors.New("channel: target must be a numeric unicast IP and nonzero port")
	}
	return t.Identity.Validate()
}

// connect owns raw from entry onward. It is separate from TCP dialing so the
// complete production TLS/handshake path can also be exercised with net.Pipe.
func connect(lifetime, handshake context.Context, raw net.Conn, target Target, options Options) (*Channel, error) {
	conn, codec, info, err := negotiate(handshake, raw, target)
	if err != nil {
		return nil, err
	}
	if err := lifetime.Err(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return newPaddedChannel(lifetime, raw, conn, codec, info, options.QueueSize, options.Padding, options.PaddingPolicy), nil
}

func negotiate(ctx context.Context, raw net.Conn, target Target) (conn *tls.Conn, codec *cell.Codec, info Info, err error) {
	aborted := make(chan struct{})
	// Closing only interrupts pending I/O; the context/handshake error is authoritative.
	stop := context.AfterFunc(ctx, func() { _ = raw.Close(); close(aborted) })
	defer func() {
		// Synchronize with cancellation so no callback can close a successfully
		// handed-off socket after this function exits.
		if !stop() {
			<-aborted
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		} else if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			// Socket deadlines can fire just before the context timer is run.
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				err = context.DeadlineExceeded
			}
		}
		if err != nil {
			_ = raw.Close()
		}
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err = raw.SetDeadline(deadline); err != nil {
			return
		}
	}
	serverName, nameErr := randomServerName()
	if nameErr != nil {
		err = fmt.Errorf("channel TLS server name: %w", nameErr)
		return
	}
	conn = tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		// A fresh Tor-shaped cover name, unrelated to the relay/destination.
		// TCP is already connected to the numeric relay address: no DNS occurs.
		ServerName: serverName,
		// Tor authenticates the exact TLS leaf through CERTS after TLS finishes.
		// The connection is private to this function until torcert.Verify passes.
		InsecureSkipVerify:     true, // #nosec G402 -- Tor CERTS authenticates this exact TLS leaf against both pinned identities before returning a channel; Web PKI is not Tor's trust model.
		SessionTicketsDisabled: true,
		CurvePreferences:       torTLSGroups(),
	})
	if err = conn.HandshakeContext(ctx); err != nil {
		err = fmt.Errorf("channel TLS: %w", err)
		return
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		err = fmt.Errorf("%w: TLS peer has no certificate", ErrProtocol)
		return
	}
	if err = cell.WriteVersions(conn, []uint16{4, 5}); err != nil {
		return
	}
	var versions []uint16
	if versions, err = cell.ReadVersions(conn); err != nil {
		return
	}
	if info.LinkVersion, err = cell.NegotiateVersion(versions, []uint16{4, 5}); err != nil {
		return
	}
	codec, err = cell.NewCodec(info.LinkVersion)
	if err != nil {
		return
	}
	// Bound VPADDING/duplicate-VERSIONS work as well as handshake wall time.
	cells, bytes := 0, 0
	next := func(want cell.Command) (cell.Cell, error) {
		for {
			if cells >= 128 || bytes >= 1<<20 {
				return cell.Cell{}, fmt.Errorf("%w: handshake resource limit", ErrProtocol)
			}
			frame, e := codec.Read(conn)
			if e != nil {
				return cell.Cell{}, e
			}
			cells++
			bytes += len(frame.Payload) + 7
			if bytes > 1<<20 {
				return cell.Cell{}, fmt.Errorf("%w: handshake byte limit", ErrProtocol)
			}
			if frame.Command == cell.VPadding || frame.Command == cell.Versions {
				continue
			}
			if frame.Command != want {
				return cell.Cell{}, fmt.Errorf("%w: expected %s, received %s", ErrProtocol, want, frame.Command)
			}
			return frame, nil
		}
	}
	var frame cell.Cell
	if frame, err = next(cell.Certs); err != nil {
		return
	}
	var certs []cell.Certificate
	if certs, err = cell.DecodeCerts(frame.Payload); err != nil {
		return
	}
	var verified torcert.Verified
	if verified, err = torcert.Verify(certs, state.PeerCertificates[0].Raw, target.Identity, time.Now()); err != nil {
		return
	}
	if frame, err = next(cell.AuthChallenge); err != nil {
		return
	}
	if _, err = cell.DecodeAuthChallenge(frame.Payload); err != nil {
		return
	}
	if frame, err = next(cell.NetInfo); err != nil {
		return
	}
	if info.PeerNetInfo, err = cell.DecodeNetInfo(frame.Payload); err != nil {
		return
	}
	// Anonymous clients report neither their clock nor their local addresses.
	var payload []byte
	if payload, err = cell.EncodeNetInfo(cell.NetInfoMessage{OtherAddress: target.Address.Addr()}); err != nil {
		return
	}
	if err = codec.Write(conn, cell.Cell{Command: cell.NetInfo, Payload: payload}); err != nil {
		return
	}
	if err = raw.SetDeadline(time.Time{}); err != nil {
		return
	}
	info.Identity, info.CertificatesExpire, info.TLSVersion = verified.Identity, verified.Expires, state.Version
	return
}
