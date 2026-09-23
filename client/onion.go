package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"veil/cell"
	"veil/channel"
	"veil/circuit"
	"veil/directory"
	"veil/internal/diagnostics"
	"veil/isolation"
	"veil/onion"
)

var errOnionDescriptorMissing = errors.New("onion directory has no available descriptor")

func shuffle[T any](items []T) error {
	for i := len(items) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := int(n.Int64())
		items[i], items[j] = items[j], items[i]
	}
	return nil
}

func (d *Dialer) buildOnion(life, setup context.Context, guards *directory.GuardStore, host string, port uint16) (streamCircuit, error) {
	diagnostics.Log(setup, d.options.Logger, "onion_setup", "exit", "none (onion rendezvous)")
	id, err := onion.ParseAddress(host)
	if err != nil {
		return nil, err
	}
	snapshot, err := d.source.Snapshot()
	if err != nil {
		return nil, err
	}
	period, minutes, _, err := snapshot.OnionPeriod(time.Now())
	if err != nil {
		return nil, err
	}
	blinded, sub, err := onion.Blind(id, period, minutes)
	if err != nil {
		return nil, err
	}
	fetched := make(map[directory.Fingerprint]bool)
	exhausted := make(map[uint64]bool)
	scope, shared := isolation.Scope(setup)
	descriptorID := descriptorKey{scope: scope, blinded: blinded}
	fetch := func(requestContext context.Context) (*onion.Descriptor, [32]byte, error) {
		setup := requestContext
		dirs, err := snapshot.OnionDirectories(blinded, time.Now())
		if err != nil {
			return nil, [32]byte{}, err
		}
		if err := shuffle(dirs); err != nil {
			return nil, [32]byte{}, err
		}
		var last error
		// Bound attempts even if a future consensus expands the directory spread.
		for _, target := range dirs[:min(len(dirs), 8)] {
			if fetched[target.Identity()] {
				continue
			}
			if err := setup.Err(); err != nil {
				return nil, [32]byte{}, err
			}
			diagnostics.Log(setup, d.options.Logger, "onion_descriptor_fetch", "hsdir", target.Address().String())
			request, cancel := context.WithTimeout(setup, 30*time.Second)
			raw, e := fetchOnionDescriptor(request, snapshot, guards, target, blinded, d.options.BuildTimeout, d.channels)
			cancel()
			if e != nil {
				diagnostics.Log(setup, d.options.Logger, "onion_descriptor_fetch_failed", "error", e)
				last = e
				if !errors.Is(e, errOnionDescriptorMissing) && !errors.Is(e, directory.ErrPath) && !retryableBuild(e) {
					return nil, [32]byte{}, e
				}
				continue
			}
			descriptor, e := onion.ParseDescriptor(raw, blinded, sub, time.Now())
			digest := sha256.Sum256(raw)
			clear(raw)
			if e != nil {
				return nil, [32]byte{}, fmt.Errorf("onion descriptor verification: %w", e)
			} // Authentication/decryption failure is terminal.
			if shared {
				if e := d.descriptors.checkRevision(descriptorID, descriptor.Revision, digest); e != nil {
					last = e
					diagnostics.Log(setup, d.options.Logger, "onion_descriptor_stale", "error", e)
					continue
				}
			}
			if exhausted[descriptor.Revision] {
				last = errors.New("onion directory still advertises failed introduction points")
				continue
			}
			fetched[target.Identity()] = true
			return descriptor, digest, nil
		}
		return nil, [32]byte{}, fmt.Errorf("onion descriptor unavailable: %w", last)
	}
	var last error
	// Bound descriptor generations as well as the total OnionTimeout.
	for refresh := 0; refresh < 3; refresh++ {
		var descriptor *onion.Descriptor
		if shared {
			// Period boundaries are anchored at the Unix epoch plus 12 voting intervals.
			if minutes < 30 || minutes > 14400 {
				return nil, directory.ErrTime
			}
			info := snapshot.Info()
			length := time.Duration(minutes) * time.Minute
			offset := 12 * info.FreshUntil.Sub(info.ValidAfter)
			elapsed := time.Duration((info.ValidAfter.Unix()-int64(offset/time.Second))%int64(length/time.Second)) * time.Second
			periodEnd := info.ValidAfter.Add(length - elapsed)
			descriptor, err = d.descriptors.load(setup, descriptorID, periodEnd, fetch)
		} else {
			descriptor, _, err = fetch(setup)
		}
		if err != nil {
			return nil, err
		}
		diagnostics.Log(setup, d.options.Logger, "onion_descriptor_ready", "introduction_points", len(descriptor.Introductions))
		if err := shuffle(descriptor.Introductions); err != nil {
			return nil, err
		}
		for _, intro := range descriptor.Introductions[:min(len(descriptor.Introductions), 3)] {
			if err := setup.Err(); err != nil {
				return nil, err
			}
			if !time.Now().Before(descriptor.Expires) {
				return nil, onion.ErrDescriptor
			}
			current, err := d.source.Snapshot()
			if err != nil {
				return nil, err
			}
			// Never use stale descriptor keys to impersonate a relay. Intro points
			// absent from our verified consensus are not currently supported.
			target, e := introductionRelay(current, intro)
			if e != nil {
				last = e
				continue
			}
			diagnostics.Log(setup, d.options.Logger, "onion_introduction", "relay", target.Address().String())
			c, e := onionAttempt(life, setup, d.options.IntroductionTimeout, func(attemptLife, attemptSetup context.Context) (streamCircuit, error) {
				return d.connectOnion(attemptLife, attemptSetup, current, guards, target, intro, sub, host, port, d.options.BuildTimeout)
			})
			if e == nil {
				diagnostics.Log(setup, d.options.Logger, "onion_rendezvous_ready", "exit", "none")
				return c, nil
			}
			last = e
			diagnostics.Log(setup, d.options.Logger, "onion_introduction_failed", "error", e)
			if !retryableBuild(e) {
				return nil, e
			}
		}
		exhausted[descriptor.Revision] = true
		if shared {
			d.descriptors.invalidate(descriptorID, descriptor.Revision)
		}
		if setup.Err() != nil {
			return nil, setup.Err()
		}
		if refresh < 2 {
			diagnostics.Log(setup, d.options.Logger, "onion_descriptor_refresh")
		}
	}
	return nil, fmt.Errorf("onion introduction unavailable: %w", last)
}

func introductionRelay(s *directory.Snapshot, intro onion.Introduction) (directory.Relay, error) {
	var rsa directory.Fingerprint
	var ed [32]byte
	for _, l := range intro.Links {
		if l.Type == cell.LinkRSAIdentity {
			copy(rsa[:], l.Data)
		}
		if l.Type == cell.LinkEd25519Identity {
			copy(ed[:], l.Data)
		}
	}
	r, err := s.RelayByIdentity(rsa, ed)
	if err != nil {
		return r, err
	}
	if r.NTor().OnionKey != intro.OnionKey {
		return directory.Relay{}, directory.ErrPath
	}
	return r, nil
}

func fetchOnionDescriptor(ctx context.Context, s *directory.Snapshot, g *directory.GuardStore, target directory.Relay, blinded [32]byte, timeout time.Duration, pools ...*channel.Pool) ([]byte, error) {
	c, err := circuit.BuildInternal(ctx, s, g, &target, circuit.OnionDirectory, timeout, pools...)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	conn, err := c.DialDirectory(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	request := "GET /tor/hs/3/" + base64.RawStdEncoding.EncodeToString(blinded[:]) + " HTTP/1.0\r\nHost: www.example.com\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(conn, onion.MaxDescriptorSize+16385))
	if err != nil {
		return nil, err
	}
	if len(raw) > onion.MaxDescriptorSize+16384 {
		return nil, onion.ErrDescriptor
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		if response.StatusCode == 404 || response.StatusCode == 503 {
			return nil, errOnionDescriptorMissing
		}
		return nil, fmt.Errorf("onion directory response: %d", response.StatusCode)
	}
	if response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, onion.ErrDescriptor
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, onion.MaxDescriptorSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > onion.MaxDescriptorSize {
		return nil, onion.ErrDescriptor
	}
	return b, nil
}

func (d *Dialer) connectOnion(life, setup context.Context, s *directory.Snapshot, g *directory.GuardStore, target directory.Relay, intro onion.Introduction, sub [32]byte, host string, port uint16, timeout time.Duration) (_ streamCircuit, result error) {
	release, err := d.intros.reserve(setup, d.lifetime)
	if err != nil {
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			release()
		}
	}()
	ctx, cancel := context.WithCancel(life)
	keep := false
	defer func() {
		if !keep {
			cancel()
		}
	}()
	rend, err := circuit.BuildInternal(ctx, s, g, nil, circuit.OnionRendezvous, timeout, d.channels)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !keep {
			result = errors.Join(result, rend.Close())
		}
	}()
	handshake, err := onion.NewHandshake(intro, sub)
	if err != nil {
		return nil, err
	}
	var cookie [20]byte
	if _, err := rand.Read(cookie[:]); err != nil {
		return nil, err
	}
	if err := rend.PrepareRendezvous(setup, cookie, host, port, handshake.Finish); err != nil {
		return nil, fmt.Errorf("rendezvous establishment: %w", err)
	}
	r := rend.Path().Exit
	// Inner INTRODUCE1: cookie, no extensions, ntor onion key, link specifiers.
	body := append(cookie[:], 0, 1, 0, 32)
	key := r.NTor().OnionKey
	body = append(body, key[:]...)
	identity := r.Target().Identity
	address := binary.BigEndian.AppendUint16(r.Address().Addr().AsSlice(), r.Address().Port())
	addrType := cell.LinkIPv4
	if r.Address().Addr().Is6() {
		addrType = cell.LinkIPv6
	}
	links := []cell.LinkSpec{{Type: addrType, Data: address}, {Type: cell.LinkRSAIdentity, Data: identity.RSA[:]}, {Type: cell.LinkEd25519Identity, Data: identity.Ed25519[:]}}
	body = append(body, 3)
	for _, l := range links {
		size := len(l.Data)
		if size > 255 {
			return nil, circuit.ErrProtocol
		}
		body = append(body, l.Type, byte(size))
		body = append(body, l.Data...)
	}
	payload, err := handshake.Intro(body)
	if err != nil {
		return nil, err
	}
	// The introduction belongs to the dialer after its exchange, independently
	// of the rendezvous stream/attempt. During setup, cancellation still applies.
	introLife, introCancel := context.WithCancel(d.lifetime)
	stopIntroSetup := context.AfterFunc(setup, introCancel)
	defer func() {
		stopIntroSetup()
		if !retained {
			introCancel()
		}
	}()
	ic, err := circuit.BuildInternal(introLife, s, g, &target, circuit.OnionIntroduction, timeout, d.channels)
	if err != nil {
		return nil, err
	}
	err = ic.Introduce(setup, payload)
	var closeErr error
	if stopIntroSetup() && ic.PaddingStats().Started && ic.Err() == nil {
		d.intros.hold(d.lifetime, ic, introCancel, release, introductionRetention)
		retained = true
	} else {
		closeErr = ic.Close()
	}
	if err != nil || closeErr != nil {
		return nil, fmt.Errorf("introduction exchange: %w", errors.Join(err, closeErr))
	}
	if err := rend.FinishRendezvous(setup); err != nil {
		return nil, fmt.Errorf("rendezvous handshake: %w", err)
	}
	keep = true
	return &attemptCircuit{streamCircuit: rend, cancel: cancel}, nil
}

// Bound an individual setup without tying an established stream to its deadline.
// Retained introduction circuits remain owned by d.lifetime in connectOnion.
func onionAttempt(life, setup context.Context, timeout time.Duration, connect func(context.Context, context.Context) (streamCircuit, error)) (streamCircuit, error) {
	attemptSetup, stopSetup := context.WithTimeout(setup, timeout)
	defer stopSetup()
	attemptLife, cancel := context.WithCancel(life)
	detach := context.AfterFunc(attemptSetup, cancel)
	c, err := connect(attemptLife, attemptSetup)
	// Circuit builds watch their lifetime and may report Canceled when our
	// local setup deadline fires. Preserve that deadline as a retryable timeout.
	if attemptSetup.Err() == context.DeadlineExceeded && canceledOnionAttempt(err) {
		err = fmt.Errorf("onion attempt timed out: %w", context.DeadlineExceeded)
	}
	detached := detach()
	if err == nil && (!detached || attemptSetup.Err() != nil || attemptLife.Err() != nil) {
		err = attemptSetup.Err()
		if err == nil {
			err = attemptLife.Err()
		}
		if err == nil {
			err = context.Canceled
		}
	}
	if err != nil {
		cancel()
		if c != nil {
			err = errors.Join(err, c.Close())
		}
		return nil, err
	}
	return &attemptCircuit{streamCircuit: c, cancel: cancel}, nil
}

func canceledOnionAttempt(err error) bool {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !canceledOnionAttempt(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return canceledOnionAttempt(wrapped.Unwrap())
	}
	return err == context.Canceled || retryableBuild(err)
}
